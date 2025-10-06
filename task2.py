import re
from datetime import datetime, timedelta
from collections import defaultdict

LOG_FILE = "sample_auth_small.log"
FAILED_REGEX = re.compile(r"^(?P<month>\w{3}) (?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) .*Failed password.*from (?P<ip>\d+\.\d+\.\d+\.\d+)")

per_ip_timestamps = defaultdict(list)

with open(LOG_FILE, "r") as f:
    for line in f:
        match = FAILED_REGEX.match(line)
        if match:
            month = match.group("month")
            day = match.group("day")
            time_str = match.group("time")
            ip = match.group("ip")
            timestamp_str = f"2025 {month} {day} {time_str}"
            try:
                dt = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
                per_ip_timestamps[ip].append(dt)
            except ValueError:
                print(f"Failed to parse timestamp: {timestamp_str} in line: {line.strip()}")

# Sliding window detection for brute-force bursts
incidents = []
window = timedelta(minutes=10)
for ip, times in per_ip_timestamps.items():
    times.sort()
    n = len(times)
    i = 0
    while i < n:
        j = i
        while j + 1 < n and (times[j+1] - times[i]) <= window:
            j += 1
        count = j - i + 1
        if count >= 5:
            incidents.append({
                "ip": ip,
                "count": count,
                "first": times[i].isoformat(),
                "last": times[j].isoformat()
            })
            i = j + 1
        else:
            i += 1

print(f"Detected {len(incidents)} brute-force incidents")
for incident in incidents[:5]:
    print(incident)
