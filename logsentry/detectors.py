"""
Detection logic for LogSentry.

Note to future me: brute force and web scanning detection here use
fixed time buckets instead of a true sliding window. An attack that
straddles two buckets, like three failures right before a boundary and
three more right after, can slip past the threshold even though it's
really six failures in a short stretch of time. That's a real gap. The
plan is to replace this with a proper sliding window later, using a
per-IP list of timestamps that gets trimmed as it goes. For now this
simpler version still catches straightforward brute force attempts,
which covers most of what you'd actually see.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional

from .parser import SSHEvent, WebEvent

SSH_BRUTE_FORCE_THRESHOLD = 5
SSH_BRUTE_FORCE_WINDOW_MINUTES = 10
LOGIN_AFTER_FAILURES_THRESHOLD = 3
WEB_SCAN_THRESHOLD = 20
WEB_SCAN_WINDOW_MINUTES = 5
OFFHOURS_START_HOUR = 22
OFFHOURS_END_HOUR = 5


@dataclass
class BruteForceFinding:
    ip: str
    count: int
    window_start: datetime
    window_end: datetime


@dataclass
class LoginAfterFailuresFinding:
    ip: str
    username: str
    failure_count: int
    login_time: datetime


@dataclass
class WebScanFinding:
    ip: str
    count: int
    window_start: datetime
    window_end: datetime


@dataclass
class OffHoursFinding:
    ip: str
    username: str
    login_time: datetime


def _bucket_start(timestamp: datetime, window_minutes: int) -> datetime:
    """
    Rounds a timestamp down to the start of its fixed size bucket.
    This assumes window_minutes divides evenly into 60, which is true
    for the 10 and 5 minute defaults used here. Wasn't worth handling
    the general case since thresholds aren't configurable yet anyway.
    """
    minute_bucket = (timestamp.minute // window_minutes) * window_minutes
    return timestamp.replace(minute=minute_bucket, second=0, microsecond=0)


def detect_brute_force(
    events: List[SSHEvent],
    threshold: int = SSH_BRUTE_FORCE_THRESHOLD,
    window_minutes: int = SSH_BRUTE_FORCE_WINDOW_MINUTES,
) -> List[BruteForceFinding]:
    buckets = defaultdict(list)
    for event in events:
        if event.event_type != "failed":
            continue
        key = (event.ip, _bucket_start(event.timestamp, window_minutes))
        buckets[key].append(event.timestamp)

    findings = []
    for (ip, bucket_start), timestamps in buckets.items():
        if len(timestamps) >= threshold:
            findings.append(BruteForceFinding(
                ip=ip,
                count=len(timestamps),
                window_start=bucket_start,
                window_end=bucket_start + timedelta(minutes=window_minutes),
            ))
    return findings


def detect_login_after_failures(
    events: List[SSHEvent],
    min_consecutive_failures: int = LOGIN_AFTER_FAILURES_THRESHOLD,
) -> List[LoginAfterFailuresFinding]:
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    consecutive_failures = defaultdict(int)
    findings = []

    for event in sorted_events:
        if event.event_type == "failed":
            consecutive_failures[event.ip] += 1
        elif event.event_type == "accepted":
            count = consecutive_failures[event.ip]
            if count >= min_consecutive_failures:
                findings.append(LoginAfterFailuresFinding(
                    ip=event.ip,
                    username=event.username or "unknown",
                    failure_count=count,
                    login_time=event.timestamp,
                ))
            consecutive_failures[event.ip] = 0

    return findings


def detect_web_scanning(
    events: List[WebEvent],
    threshold: int = WEB_SCAN_THRESHOLD,
    window_minutes: int = WEB_SCAN_WINDOW_MINUTES,
) -> List[WebScanFinding]:
    buckets = defaultdict(list)
    for event in events:
        if event.status not in (403, 404):
            continue
        key = (event.ip, _bucket_start(event.timestamp, window_minutes))
        buckets[key].append(event.timestamp)

    findings = []
    for (ip, bucket_start), timestamps in buckets.items():
        if len(timestamps) >= threshold:
            findings.append(WebScanFinding(
                ip=ip,
                count=len(timestamps),
                window_start=bucket_start,
                window_end=bucket_start + timedelta(minutes=window_minutes),
            ))
    return findings


def detect_offhours_logins(
    events: List[SSHEvent],
    start_hour: int = OFFHOURS_START_HOUR,
    end_hour: int = OFFHOURS_END_HOUR,
) -> List[OffHoursFinding]:
    findings = []
    for event in events:
        if event.event_type != "accepted":
            continue
        hour = event.timestamp.hour
        is_offhours = hour >= start_hour or hour < end_hour
        if is_offhours:
            findings.append(OffHoursFinding(
                ip=event.ip,
                username=event.username or "unknown",
                login_time=event.timestamp,
            ))
    return findings
