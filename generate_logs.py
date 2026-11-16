"""Generate a reproducible and entirely synthetic authentication log dataset."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import csv
import random

FIELDS = ("timestamp", "username", "src_ip", "status")
OUTPUT = Path(__file__).resolve().parent / "data" / "sample_auth_logs.csv"


def generate_logs(output: Path = OUTPUT, seed: int = 42) -> Path:
    rng = random.Random(seed)
    start = datetime(2026, 11, 10, 8, 0, tzinfo=timezone.utc)
    users = ["alice", "bob", "charlie", "diana"]
    user_ips = {
        "alice": ["192.0.2.11", "192.0.2.12"],
        "bob": ["192.0.2.21", "192.0.2.22"],
        "charlie": ["198.51.100.31", "198.51.100.32"],
        "diana": ["198.51.100.41", "198.51.100.42"],
    }
    events = []

    # Routine synthetic weekday traffic with occasional failed logins.
    for _ in range(240):
        user = rng.choice(users)
        timestamp = start + timedelta(seconds=rng.randint(0, 10 * 3600))
        events.append(
            {
                "timestamp": timestamp,
                "username": user,
                "src_ip": rng.choice(user_ips[user]),
                "status": "failure" if rng.random() < 0.08 else "success",
            }
        )

    # Inject a plausible brute-force pattern from a documentation-only IP.
    attacker_ip = "203.0.113.77"
    attack_start = start + timedelta(hours=4)
    for i in range(12):
        events.append(
            {
                "timestamp": attack_start + timedelta(seconds=30 * i),
                "username": "alice",
                "src_ip": attacker_ip,
                "status": "failure",
            }
        )
    events.append(
        {
            "timestamp": attack_start + timedelta(minutes=7),
            "username": "alice",
            "src_ip": attacker_ip,
            "status": "success",
        }
    )

    # A low-severity example: a late-night success (not evidence of compromise).
    events.append(
        {
            "timestamp": start + timedelta(days=1, hours=-5, minutes=-30),
            "username": "diana",
            "src_ip": "198.51.100.42",
            "status": "success",
        }
    )

    events.sort(key=lambda event: event["timestamp"])
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        for event in events:
            writer.writerow({**event, "timestamp": event["timestamp"].isoformat()})
    return output


if __name__ == "__main__":
    path = generate_logs()
    print(f"Created synthetic logs: {path}")
