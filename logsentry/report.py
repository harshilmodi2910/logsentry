"""
Formats detector findings into a plain text report. Nothing fancy,
just enough structure to read through quickly at the terminal.
JSON output is planned for a later version, this only builds text.
"""

from typing import List

from .detectors import (
    BruteForceFinding,
    LoginAfterFailuresFinding,
    WebScanFinding,
    OffHoursFinding,
)


def _format_brute_force(findings: List[BruteForceFinding]) -> str:
    if not findings:
        return "  none found\n"
    lines = []
    for f in findings:
        start = f.window_start.strftime("%Y-%m-%d %H:%M")
        end = f.window_end.strftime("%H:%M")
        lines.append(f"  {f.ip}: {f.count} failed logins between {start} and {end}")
    return "\n".join(lines) + "\n"


def _format_login_after_failures(findings: List[LoginAfterFailuresFinding]) -> str:
    if not findings:
        return "  none found\n"
    lines = []
    for f in findings:
        when = f.login_time.strftime("%Y-%m-%d %H:%M:%S")
        lines.append(
            f"  {f.ip}: logged in as {f.username} at {when}, "
            f"after {f.failure_count} failed attempts right before it"
        )
    return "\n".join(lines) + "\n"


def _format_web_scanning(findings: List[WebScanFinding]) -> str:
    if not findings:
        return "  none found\n"
    lines = []
    for f in findings:
        start = f.window_start.strftime("%Y-%m-%d %H:%M")
        end = f.window_end.strftime("%H:%M")
        lines.append(f"  {f.ip}: {f.count} responses with status 403 or 404 between {start} and {end}")
    return "\n".join(lines) + "\n"


def _format_offhours(findings: List[OffHoursFinding]) -> str:
    if not findings:
        return "  none found\n"
    lines = []
    for f in findings:
        when = f.login_time.strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"  {f.ip}: {f.username} logged in at {when}")
    return "\n".join(lines) + "\n"


def build_report(
    brute_force_findings,
    login_after_failures_findings,
    web_scan_findings,
    offhours_findings,
) -> str:
    sections = []

    sections.append("LogSentry Report")
    sections.append("=" * 40)
    sections.append("")

    sections.append("SSH Brute Force Attempts")
    sections.append("-" * 40)
    sections.append(_format_brute_force(brute_force_findings))

    sections.append("Successful Logins After Repeated Failures")
    sections.append("-" * 40)
    sections.append(_format_login_after_failures(login_after_failures_findings))

    sections.append("Web Scanning Activity")
    sections.append("-" * 40)
    sections.append(_format_web_scanning(web_scan_findings))

    sections.append("Off-Hours Logins (context only, not automatically treated as malicious)")
    sections.append("-" * 40)
    sections.append(_format_offhours(offhours_findings))

    return "\n".join(sections)
