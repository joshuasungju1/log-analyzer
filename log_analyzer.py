"""
Automated Log Analysis & Threat Detection Tool

Purpose:
    This script parses Linux authentication logs (auth.log / secure)
    and identifies suspicious SSH-related activity patterns.

Core Capabilities:
    - Extract SSH failures, invalid user attempts, accepted logins
    - Track activity per source IP address
    - Detect potential brute-force behavior using a sliding time window
    - Generate structured JSON security reports

Typical Use Case:
    Entry-level SOC / blue team style log triage & incident detection.

Tested against:
    Standard Debian / Ubuntu auth.log formats.
"""

# Enables modern Python typing behavior (cleaner type hints)
from __future__ import annotations

# Standard library imports only (good practice for portability)
import argparse              # CLI argument parsing
import datetime as dt        # Timestamp handling & time window logic
import ipaddress             # Safe IP validation
import json                  # Report generation
import os                    # File system checks
import re                    # Log pattern matching

# Efficient data structures for streaming analysis
from collections import defaultdict, deque

# Dataclass for clean structured IP tracking
from dataclasses import dataclass, asdict

# Type hints improve maintainability & readability
from typing import Deque, Dict, List, Optional, Tuple


# Regular Expressions (Log Pattern Definitions)

# These patterns match common sshd log messages.
# Real logs vary slightly between distributions, but these
# cover the majority of default Linux installations.

# Ex.)
# "Failed password for root from 1.2.3.4 port 12345"
FAILED_PASSWORD_RE = re.compile(
    r"sshd\[\d+\]: Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
)

# Ex.)
# "Invalid user admin from 1.2.3.4"
INVALID_USER_RE = re.compile(
    r"sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Ex.)
# "Accepted password/publickey for user from 1.2.3.4"
ACCEPTED_RE = re.compile(
    r"sshd\[\d+\]: Accepted \S+ for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
)

# Ex.)
# "Disconnected from 1.2.3.4"
DISCONNECT_RE = re.compile(
    r"sshd\[\d+\]: Disconnected from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Timestamp Handling Helpers

# Syslog timestamps omit the year, so we reconstruct full
# datetime objects using a provided year value.
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1
)}

# Matches timestamps at the beginning of syslog lines
SYSLOG_TS_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+"
)

# Data Model (Per-IP Tracking)

# Each IPStats instance represents observed activity for one
# source IP address across the log file.
@dataclass
class IPStats:
    ip: str

    # Counters for security-relevant behaviors
    failed_attempts: int = 0
    accepted_logins: int = 0
    invalid_user_attempts: int = 0

    # Temporal context (useful for investigations)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    # Distinct usernames attempted from this IP
    usernames: List[str] = None

    def __post_init__(self):
        # Defensive initialization prevents None errors
        if self.usernames is None:
            self.usernames = []


# Utility Functions
def parse_syslog_timestamp(line: str, year: int) -> Optional[dt.datetime]:
    """
    Extract and reconstruct syslog timestamps.

    Why needed:
        Syslog format does not include year information.

    Returns:
        datetime object if parsing succeeds, otherwise None.
    """
    m = SYSLOG_TS_RE.match(line)
    if not m:
        return None

    mon = MONTHS.get(m.group("mon"))
    day = int(m.group("day"))
    h, mi, s = map(int, m.group("hms").split(":"))

    try:
        return dt.datetime(year, mon, day, h, mi, s)
    except Exception:
        # Invalid timestamps should not crash analysis
        return None


def safe_ip(ip: str) -> bool:
    """
    Validate IP address format safely.

    Prevents malformed log entries from breaking logic.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def iso(ts: Optional[dt.datetime]) -> Optional[str]:
    """
    Convert datetime → ISO 8601 string.

    SOC tools often standardize timestamps this way.
    """
    return ts.isoformat() if ts else None


# Core Analysis Engine
def analyze_auth_log(
    log_path: str,
    year: int,
    brute_force_threshold: int,
    window_minutes: int
) -> Dict:
    """
    Main log processing routine.

    Detection Logic:
        Tracks failed attempts within a sliding time window
        to approximate brute-force detection behavior.
    """

    # Fail fast if log file is missing (good UX)
    if not os.path.exists(log_path):
        raise FileNotFoundError(f"Log file not found: {log_path}")

    # Per-IP aggregation structure
    ip_stats: Dict[str, IPStats] = {}

    # Sliding window store of recent failures per IP
    ip_fail_windows: Dict[str, Deque[dt.datetime]] = defaultdict(deque)

    # Global counters for reporting / metrics
    total_lines = 0
    parsed_events = 0

    events = {
        "failed_password": 0,
        "invalid_user": 0,
        "accepted": 0,
        "disconnect": 0,
    }

    suspicious_ips = set()
    now = dt.datetime.now()

    with open(log_path, "r", errors="ignore") as f:
        for line in f:
            total_lines += 1

            # Attempt timestamp reconstruction
            ts = parse_syslog_timestamp(line, year)

            # Failed Password Detection
            m = FAILED_PASSWORD_RE.search(line)
            if m:
                parsed_events += 1
                events["failed_password"] += 1

                ip = m.group("ip")
                user = m.group("user")

                if safe_ip(ip):
                    st = ip_stats.setdefault(ip, IPStats(ip=ip))
                    st.failed_attempts += 1

                    if user and user not in st.usernames:
                        st.usernames.append(user)

                    if ts:
                        st.first_seen = st.first_seen or iso(ts)
                        st.last_seen = iso(ts)

                        # Sliding window logic:
                        # Remove old failures outside detection window
                        dq = ip_fail_windows[ip]
                        dq.append(ts)

                        cutoff = ts - dt.timedelta(minutes=window_minutes)
                        while dq and dq[0] < cutoff:
                            dq.popleft()

                        # Brute-force heuristic trigger
                        if len(dq) >= brute_force_threshold:
                            suspicious_ips.add(ip)

                continue

            # Invalid User Detection
            m = INVALID_USER_RE.search(line)
            if m:
                parsed_events += 1
                events["invalid_user"] += 1

                ip = m.group("ip")
                user = m.group("user")

                if safe_ip(ip):
                    st = ip_stats.setdefault(ip, IPStats(ip=ip))
                    st.invalid_user_attempts += 1

                    if user and user not in st.usernames:
                        st.usernames.append(user)

                    if ts:
                        st.first_seen = st.first_seen or iso(ts)
                        st.last_seen = iso(ts)

                continue

            # Successful Login Detection
            m = ACCEPTED_RE.search(line)
            if m:
                parsed_events += 1
                events["accepted"] += 1

                ip = m.group("ip")
                user = m.group("user")

                if safe_ip(ip):
                    st = ip_stats.setdefault(ip, IPStats(ip=ip))
                    st.accepted_logins += 1

                    if user and user not in st.usernames:
                        st.usernames.append(user)

                    if ts:
                        st.first_seen = st.first_seen or iso(ts)
                        st.last_seen = iso(ts)

                continue

            # Disconnect Events
            m = DISCONNECT_RE.search(line)
            if m:
                parsed_events += 1
                events["disconnect"] += 1
                continue

    # Rank noisy IPs for analyst visibility
    ranked = sorted(
        ip_stats.values(),
        key=lambda s: (s.failed_attempts, s.invalid_user_attempts),
        reverse=True
    )

    # Construct detection findings
    findings = []
    for ip in sorted(suspicious_ips):
        st = ip_stats.get(ip)

        findings.append({
            "type": "possible_bruteforce",
            "ip": ip,
            "total_failed_attempts": st.failed_attempts if st else 0,
            "observed_usernames": st.usernames if st else []
        })

    # Final structured report
    return {
        "metadata": {
            "generated_at": now.isoformat(),
            "log_path": os.path.abspath(log_path),
            "total_lines_read": total_lines,
            "parsed_security_events": parsed_events
        },
        "event_counts": events,
        "top_ips": [asdict(x) for x in ranked[:20]],
        "findings": findings
    }


# CLI Entry Point
def main():
    """
    Command-line interface for tool execution.

    Designed to resemble real-world security utilities.
    """

    ap = argparse.ArgumentParser(description="Analyze Linux auth.log for suspicious SSH patterns.")

    ap.add_argument("--log", default="/var/log/auth.log", help="Path to auth log")
    ap.add_argument("--year", type=int, default=dt.datetime.now().year)
    ap.add_argument("--threshold", type=int, default=10)
    ap.add_argument("--window", type=int, default=5)
    ap.add_argument("--out", default="security_report.json")

    args = ap.parse_args()

    report = analyze_auth_log(
        log_path=args.log,
        year=args.year,
        brute_force_threshold=args.threshold,
        window_minutes=args.window
    )

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[+] Report written to: {args.out}")


if __name__ == "__main__":
    main()