#!/usr/bin/env python3
"""Kavach Guard skill helper: start a session, screen content, check an action.
Standard library only. Exit codes for `check`: 0 allow, 2 ask, 3 block, 1 error."""
import argparse, json, os, sys, urllib.request, urllib.error

URL = os.getenv("KAVACH_URL", "http://localhost:8000").rstrip("/")
KEY = os.getenv("KAVACH_API_KEY", "kavach-secret-key")


def call(path, body):
    req = urllib.request.Request(URL + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-API-Key": KEY})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        print(json.dumps({"error": e.code, "detail": e.read().decode()[:300]}))
        sys.exit(1)
    except Exception as e:  # network down -> fail closed
        print(json.dumps({"error": "kavach_unreachable", "detail": str(e), "decision": "ask"}))
        sys.exit(2)


def main():
    p = argparse.ArgumentParser(description="Kavach Guard")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("start"); s.add_argument("--goal", required=True)
    c = sub.add_parser("screen"); c.add_argument("--session"); c.add_argument("--source", required=True)
    g = c.add_mutually_exclusive_group(required=True)
    g.add_argument("--text"); g.add_argument("--text-file")
    k = sub.add_parser("check"); k.add_argument("--session"); k.add_argument("--tool", required=True)
    k.add_argument("--args", default="{}"); k.add_argument("--flagged", action="append", default=[])
    a = p.parse_args()

    if a.cmd == "start":
        print(json.dumps(call("/session/start", {"user_goal": a.goal}), indent=2))
    elif a.cmd == "screen":
        text = a.text if a.text is not None else open(a.text_file, encoding="utf-8").read()
        r = call("/screen", {"session_id": a.session, "source": a.source, "text": text})
        r.pop("sanitized_text", None)
        print(json.dumps(r, indent=2))
    else:
        r = call("/check", {"session_id": a.session, "tool": a.tool,
                            "args": json.loads(a.args), "flagged_sources": a.flagged})
        print(json.dumps(r, indent=2))
        sys.exit({"allow": 0, "ask": 2, "block": 3}.get(str(r.get("decision", "")).lower(), 1))


if __name__ == "__main__":
    main()
