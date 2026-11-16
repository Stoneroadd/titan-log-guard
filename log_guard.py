"""Small defensive log pattern analyzer for synthetic authentication logs."""
import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

PATTERN = re.compile(r"^(?P<ts>\S+)\s+level=(?P<level>\S+)\s+user=(?P<user>\S+)\s+ip=(?P<ip>\S+)\s+event=(?P<event>\S+)$")


def analyze(text: str, threshold: int) -> dict:
    if threshold < 2: raise ValueError("threshold must be at least 2")
    by_ip, by_user = defaultdict(list), defaultdict(list)
    valid = skipped = 0
    for line_no, line in enumerate(text.splitlines(), 1):
        match = PATTERN.match(line.strip())
        if not match: skipped += 1; continue
        fields = match.groupdict(); valid += 1
        if fields["event"] == "login_failed":
            item = {"line": line_no, "timestamp": fields["ts"], "user": fields["user"], "ip": fields["ip"]}
            by_ip[fields["ip"]].append(item); by_user[fields["user"]].append(item)
    findings = []
    for ip, rows in sorted(by_ip.items()):
        if len(rows) >= threshold:
            findings.append({"rule": "LG001", "title": "Repeated failed logins from one IP", "count": len(rows), "ip": ip, "evidence_lines": [r["line"] for r in rows]})
    for user, rows in sorted(by_user.items()):
        if len(rows) >= threshold:
            findings.append({"rule": "LG002", "title": "Repeated failed logins for one user", "count": len(rows), "user": user, "evidence_lines": [r["line"] for r in rows]})
    return {"data_kind": "synthetic_log_analysis", "threshold": threshold, "lines_parsed": valid, "lines_skipped": skipped, "findings": findings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--fail-threshold", type=int, default=5)
    parser.add_argument("--output", type=Path, default=Path("findings.json"))
    args = parser.parse_args()
    try: result = analyze(args.input.read_text(encoding="utf-8"), args.fail_threshold)
    except (OSError, ValueError) as exc: parser.error(str(exc))
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__": main()
