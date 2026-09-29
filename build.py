#!/usr/bin/env python3
"""Build the encrypted call-coverage board.

Pulls inbound calls from the phone system and the voice agent, works out for each
call whether a person took it, the voice agent took it, or the caller hung up, and
for every call not taken by a person records who was busy and who was idle.

Everything identifying lives in repository secrets; nothing is printed except counts.
Output: site/index.html (static loader) + site/payload.bin (AES-GCM encrypted page).

Env (all secrets):
  HCP_COOKIES   session cookies, JSON object
  RETELL_KEY    voice agent API key
  BOARD_KEY     passphrase for the encrypted payload
  BOARD_CONFIG  JSON: {"lines": {"+1...": "label"}, "agent_number": "+1...",
                       "group_uuid": "vrng_...", "first_day": "YYYY-MM-DD"}
  PAGE_HTML_B64 base64 of the page template; "/*__DATA__*/" is replaced with the data
"""
import base64
import json
import os
import shutil
import ssl
import urllib.request
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CFG = json.loads(os.environ["BOARD_CONFIG"])
LINES = CFG["lines"]
AGENT = CFG["agent_number"]
FIRST_DAY = CFG["first_day"]
CACHE = "cache"
UTC_OFFSET = timedelta(hours=-4)   # EDT; switch to -5 after the first Sunday of November
WRAP_UP = 60                       # seconds of after-call work credited as busy
SHIFT_PAD = 15                     # minutes before first / after last call
PBKDF2_ROUNDS = 250_000

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def get_json(url, headers, data=None):
    req = urllib.request.Request(url, headers=headers, data=data)
    with urllib.request.urlopen(req, context=CTX, timeout=90) as r:
        return json.loads(r.read())


def hcp(path):
    ck = json.loads(os.environ["HCP_COOKIES"])
    return get_json("https://pro.housecallpro.com/alpha/voice/" + path, {
        "accept": "application/json",
        "x-csrf-token": ck["csrf_token"],
        "cookie": "; ".join(f"{k}={v}" for k, v in ck.items()),
        "referer": "https://pro.housecallpro.com/app/settings/inbox/voice",
        "user-agent": "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/150 Safari/537.36",
    })


def load(name):
    try:
        return json.load(open(os.path.join(CACHE, name)))
    except Exception:
        return {}


def store(name, obj):
    os.makedirs(CACHE, exist_ok=True)
    json.dump(obj, open(os.path.join(CACHE, name), "w"))


def pull_calls(calls):
    """Newest first until we pass the cutoff. Recent calls are re-read because the
    disposition (and so who answered) is written some time after the call."""
    back = datetime.now(timezone.utc) - timedelta(hours=36)
    stop = FIRST_DAY + "T04:00:00Z" if not calls else back.strftime("%Y-%m-%dT%H:%M:%SZ")
    for page in range(1, 500):
        rows = hcp(f"call_logs?page={page}&page_size=200"
                   "&sort_direction=desc&sort_column=started_at").get("data") or []
        if not rows:
            break
        for r in rows:
            if (r.get("display_direction") or "").lower() != "inbound" or not r.get("started_at"):
                continue
            disp = (r.get("call_disposition") or {}).get("data") or {}
            by = ((disp.get("created_by") or {}).get("data") or {}).get("full_name")
            calls[r["uuid"]] = {"t": r["started_at"], "dur": r.get("duration") or 0,
                                "status": r.get("display_status") or "", "to": r.get("to"),
                                "from": r.get("from"), "by": by}
        if rows[-1].get("started_at", "") < stop:
            break


def pull_agent(agent):
    first = datetime.strptime(FIRST_DAY, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    since = first if not agent else datetime.now(timezone.utc) - timedelta(hours=36)
    key, page_key = os.environ["RETELL_KEY"], None
    while True:
        body = {"limit": 1000, "sort_order": "ascending",
                "filter_criteria": {"to_number": [AGENT],
                                    "start_timestamp": {"lower_threshold": int(since.timestamp() * 1000)}}}
        if page_key:
            body["pagination_key"] = page_key
        rows = get_json("https://api.retellai.com/v2/list-calls",
                        {"Authorization": "Bearer " + key, "Content-Type": "application/json"},
                        json.dumps(body).encode())
        for c in rows:
            if c.get("start_timestamp"):
                agent[c["call_id"]] = {"from": c.get("from_number"), "ms": int(c["start_timestamp"])}
        if len(rows) < 1000:
            return
        page_key = rows[-1]["call_id"]


def group_members():
    for g in hcp("ring_groups?page_size=50").get("data") or []:
        if g.get("uuid") == CFG["group_uuid"]:
            names = []
            for m in (g.get("members") or {}).get("data") or []:
                n = (((m.get("device") or {}).get("service_pro") or {}).get("data") or {}).get("full_name")
                if n and n not in names:
                    names.append(n)
            return names
    return []


def utc(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def build_days(calls, agent, people):
    by_from = {}
    for a in agent.values():
        by_from.setdefault(a["from"], []).append(a["ms"])

    # every call, all lines: a disposition marks the person as busy for its duration
    busy = {}
    lines_calls = {}
    for c in calls.values():
        t = utc(c["t"]) + UTC_OFFSET
        day = t.strftime("%Y-%m-%d")
        if day < FIRST_DAY:
            continue
        if c["by"] in people and c["status"] == "completed":
            busy.setdefault(day, {}).setdefault(c["by"], []).append(
                (t, t + timedelta(seconds=c["dur"] + WRAP_UP)))
        if c["to"] in LINES:
            lines_calls.setdefault(day, []).append(c)

    out = {}
    for day, rows in lines_calls.items():
        d0 = datetime.strptime(day, "%Y-%m-%d")
        rows.sort(key=lambda c: c["t"])
        segs, shift = {}, {}
        for n in people:
            iv = sorted(busy.get(day, {}).get(n, []))
            merged = []
            for a, b in iv:
                fa, fb = (a - d0).total_seconds() / 60, (b - d0).total_seconds() / 60
                if merged and fa <= merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], fb)
                else:
                    merged.append([fa, fb])
            segs[n] = [[round(a, 1), round(b, 1), "on_a_call"] for a, b in merged]
            if merged:
                shift[n] = (merged[0][0] - SHIFT_PAD, merged[-1][1] + SHIFT_PAD)

        items, per = [], {n: {"free_missed": 0, "busy_missed": 0, "answered": 0} for n in people}
        summ = {"total": 0, "human": 0, "emily": 0, "missed": 0, "missed_20": 0,
                "someone_free": 0, "all_busy": 0, "nobody_online": 0}
        for c in rows:
            t = utc(c["t"]) + UTC_OFFSET
            t_ms = utc(c["t"]).replace(tzinfo=timezone.utc).timestamp() * 1000
            a = (t - d0).total_seconds() / 60
            hit = [m for m in by_from.get(c["from"], []) if t_ms - 5000 <= m <= t_ms + c["dur"] * 1000 + 5000]
            if hit:
                kind, wait = "emily", max(0, round((min(hit) - t_ms) / 1000))
            elif c["status"] == "missed":
                kind, wait = "missed", c["dur"]
            else:
                kind, wait = "human", None
            it = {"min": round(a, 2), "time": t.strftime("%H:%M"), "kind": kind, "wait": wait,
                  "account": LINES[c["to"]], "by": c["by"]}
            summ["total"] += 1
            summ[kind] += 1
            if kind == "human" and c["by"] in per:
                per[c["by"]]["answered"] += 1
            if kind != "human":
                if kind == "missed" and c["dur"] > 20:
                    summ["missed_20"] += 1
                b = a + (wait or 0) / 60
                who = {"on_a_call": [], "available": [], "unavailable": [], "offline": []}
                for n in people:
                    if any(s[0] < max(b, a + 0.1) and a < s[1] for s in segs[n]):
                        who["on_a_call"].append(n)
                    elif n in shift and shift[n][0] <= a <= shift[n][1]:
                        who["available"].append(n)
                    else:
                        who["offline"].append(n)
                for n in who["available"]:
                    per[n]["free_missed"] += 1
                for n in who["on_a_call"]:
                    per[n]["busy_missed"] += 1
                if who["available"]:
                    summ["someone_free"] += 1
                elif who["on_a_call"]:
                    summ["all_busy"] += 1
                else:
                    summ["nobody_online"] += 1
                it["who"] = who
            items.append(it)

        hm = lambda m: f"{int(m) // 60:02d}:{int(m) % 60:02d}"
        out[day] = {
            "day": day, "summary": summ, "per_person": per, "calls": items,
            "people": [{"name": n, "segs": segs[n],
                        "shift": [max(0, shift[n][0]), min(1440, shift[n][1])] if n in shift else None,
                        "shift_txt": f"{hm(max(0, shift[n][0] + SHIFT_PAD))}–{hm(min(1439, shift[n][1] - SHIFT_PAD))}"
                        if n in shift else None} for n in people]}
    return out


def encrypt(plain: bytes):
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=PBKDF2_ROUNDS).derive(os.environ["BOARD_KEY"].encode())
    return salt + iv + AESGCM(key).encrypt(iv, plain, None)


def main():
    calls, agent = load("calls.json"), load("agent.json")
    pull_calls(calls)
    pull_agent(agent)
    store("calls.json", calls)
    store("agent.json", agent)
    people = group_members()

    now = datetime.now(timezone.utc)
    data = {"days": build_days(calls, agent, people), "first_day": FIRST_DAY,
            "today": (now + UTC_OFFSET).strftime("%Y-%m-%d"),
            "built": (now + UTC_OFFSET).strftime("%Y-%m-%d %H:%M")}
    page = base64.b64decode(os.environ["PAGE_HTML_B64"]).decode()
    page = page.replace("/*__DATA__*/", json.dumps(data, ensure_ascii=False).replace("</", "<\\/"))

    shutil.rmtree("site", ignore_errors=True)
    os.makedirs("site")
    shutil.copy("index.html", "site/index.html")
    open("site/payload.bin", "wb").write(encrypt(page.encode()))
    print(f"calls cached: {len(calls)}, agent calls: {len(agent)}, days: {len(data['days'])}, "
          f"group size: {len(people)}")
    match_report(calls, agent)


def match_report(calls, agent):
    """Counts only: how many agent calls per day line up with a phone-system call, and on which kind of line."""
    idx = {}
    for c in calls.values():
        idx.setdefault(c["from"], []).append(c)
    stats = {}
    for a in agent.values():
        day = (datetime.fromtimestamp(a["ms"] / 1000, timezone.utc) + UTC_OFFSET).strftime("%m-%d")
        s = stats.setdefault(day, [0, 0, 0, 0])
        s[0] += 1
        near = [c for c in idx.get(a["from"], [])
                if abs(utc(c["t"]).replace(tzinfo=timezone.utc).timestamp() * 1000 - a["ms"]) < 600_000]
        if not near:
            s[3] += 1
        elif any(c["to"] in LINES for c in near):
            s[1] += 1
        else:
            s[2] += 1
    for day in sorted(stats)[-10:]:
        t, lsa, other, none = stats[day]
        print(f"match {day}: agent={t} lsa_line={lsa} other_line={other} no_match={none}")


if __name__ == "__main__":
    main()
