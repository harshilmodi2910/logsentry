"""
Parses SSH auth log lines and Apache/Nginx access log lines into plain
Python objects so the detector functions don't have to deal with regex
or raw strings directly.

I used dataclasses here instead of dicts mostly because I kept typing
event["timestamp"] wrong in an earlier throwaway script. event.timestamp
felt safer and autocomplete actually works with it.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


@dataclass
class SSHEvent:
    timestamp: datetime
    ip: str
    event_type: str  # "failed" or "accepted"
    username: Optional[str] = None


@dataclass
class WebEvent:
    timestamp: datetime
    ip: str
    method: str
    path: str
    status: int
    size: Optional[int] = None


# Matches a full syslog line, something like:
# Mar 15 03:41:02 web01 sshd[2001]: Failed password for invalid user admin from 203.0.113.55 port 51234 ssh2
_SSH_LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+(?P<message>.+)$"
)

_SSH_FAILED_RE = re.compile(
    r"^Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+ ssh2$"
)
_SSH_ACCEPTED_RE = re.compile(
    r"^Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+ ssh2$"
)
_SSH_INVALID_USER_RE = re.compile(
    r"^Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _guess_year(month: int) -> int:
    """
    Syslog timestamps don't include a year, which is a known annoyance
    with auth.log. The common workaround, and what I'm doing here, is
    to assume the current year unless the month in the log line is
    later than the current month, in which case it's probably from
    last year (a log file being processed in January that still has
    some December lines in it). This still breaks for anything that
    spans more than one year boundary, or for old archived logs being
    parsed long after the fact. I looked at trying to be smarter about
    this by checking whether timestamps ever go backwards partway
    through the file, but decided that was more complexity than this
    project needs right now. Worth revisiting if this ever gets pointed
    at a real multi-month archive.
    """
    now = datetime.now()
    if month > now.month:
        return now.year - 1
    return now.year


def parse_auth_log(path: str) -> List[SSHEvent]:
    events = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            match = _SSH_LINE_RE.match(line)
            if not match:
                continue

            month = _MONTHS.get(match.group("month"))
            if month is None:
                continue
            day = int(match.group("day"))
            year = _guess_year(month)
            time_str = match.group("time")

            try:
                timestamp = datetime.strptime(
                    f"{year}-{month:02d}-{day:02d} {time_str}", "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                continue

            message = match.group("message")

            failed = _SSH_FAILED_RE.match(message)
            if failed:
                events.append(SSHEvent(
                    timestamp=timestamp,
                    ip=failed.group("ip"),
                    event_type="failed",
                    username=failed.group("user"),
                ))
                continue

            accepted = _SSH_ACCEPTED_RE.match(message)
            if accepted:
                events.append(SSHEvent(
                    timestamp=timestamp,
                    ip=accepted.group("ip"),
                    event_type="accepted",
                    username=accepted.group("user"),
                ))
                continue

            # "Invalid user X from IP" lines usually show up right next to
            # a matching "Failed password for invalid user" line for the
            # same attempt, so counting both would double count the same
            # login attempt. I'm skipping these on their own for now.
            if _SSH_INVALID_USER_RE.match(message):
                continue

    return events


# Matches Apache/Nginx combined log format, e.g.:
# 203.0.113.77 - - [15/Mar/2026:14:22:01 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Mozilla/5.0"
_WEB_LINE_RE = re.compile(
    r'^(?P<ip>[\d.]+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)


def parse_access_log(path: str) -> List[WebEvent]:
    events = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            match = _WEB_LINE_RE.match(line)
            if not match:
                continue

            try:
                timestamp = datetime.strptime(match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                continue

            size_str = match.group("size")
            size = None if size_str == "-" else int(size_str)

            events.append(WebEvent(
                timestamp=timestamp,
                ip=match.group("ip"),
                method=match.group("method"),
                path=match.group("path"),
                status=int(match.group("status")),
                size=size,
            ))

    return events
