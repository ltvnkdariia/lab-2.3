import re
from datetime import datetime
from collections import defaultdict

# Path to the log file
LOG_FILE = "sample_auth_small.log"

# Regex to match failed attempts and extract timestamp and IP
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

# Sort timestamps for each IP
for ip in per_ip_timestamps:
    per_ip_timestamps[ip].sort()

# Print output in expected format
import json
output = {}
for ip, times in per_ip_timestamps.items():
    output[ip] = [dt.strftime("%b %d %H:%M:%S") for dt in times]
print(json.dumps(output, indent=2))
