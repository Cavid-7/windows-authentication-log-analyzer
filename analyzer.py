import csv
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

INPUT_FILE = Path("data/auth_events.csv")
REPORT_DIR = Path("reports")
WINDOW = timedelta(minutes=10)
THRESHOLD = 5

def parse_time(value):
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)

def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"{INPUT_FILE} not found. Run export_events.ps1 first.")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    success_count = 0
    failure_count = 0
    failed_users = Counter()
    failed_ips = Counter()
    ip_events = defaultdict(list)

    with INPUT_FILE.open("r", encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            event_id = row.get("EventId", "").strip()
            if event_id not in {"4624", "4625"}:
                continue
            if event_id == "4624":
                success_count += 1
                continue

            failure_count += 1
            username = (row.get("TargetUserName") or "").strip() or "Unknown"
            ip = (row.get("IpAddress") or "").strip()
            timestamp = parse_time(row["TimeCreated"])

            failed_users[username] += 1
            if not ip or ip == "-":
                ip = "Unknown"
            failed_ips[ip] += 1
            ip_events[ip].append((timestamp, username))

    alerts = []
    for ip, events in ip_events.items():
        events.sort(key=lambda event: event[0])
        window_events = deque()
        for timestamp, username in events:
            while window_events and timestamp - window_events[0][0] >= WINDOW:
                window_events.popleft()
            window_events.append((timestamp, username))

            if len(window_events) == THRESHOLD:
                alerts.append({
                    "SourceIP": ip,
                    "WindowStartUTC": window_events[0][0].isoformat(),
                    "WindowEndUTC": timestamp.isoformat(),
                    "FailedAttempts": len(window_events),
                    "TargetUsers": ";".join(sorted({user for _, user in window_events})),
                    "Alert": "Potential brute-force activity"
                })

    print("\n=== Windows Authentication Log Analyzer ===")
    print(f"Successful logons (4624): {success_count}")
    print(f"Failed logons (4625): {failure_count}")
    print("\nTop failed usernames:")
    for username, count in failed_users.most_common(10):
        print(f"  {username}: {count}")
    print("\nTop source IPs by failed attempts:")
    for ip, count in failed_ips.most_common(10):
        print(f"  {ip}: {count}")

    report_file = REPORT_DIR / "suspicious_sources.csv"
    with report_file.open("w", encoding="utf-8-sig", newline="") as file:
        columns = ["SourceIP", "WindowStartUTC", "WindowEndUTC", "FailedAttempts", "TargetUsers", "Alert"]
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(alerts)

    print(f"\nPotential brute-force alerts: {len(alerts)}")
    print(f"Report saved to: {report_file}")

if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        raise SystemExit(f"Analysis failed: {error}")