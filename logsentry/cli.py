"""
Command line entry point for LogSentry.

Right now this takes an auth log and/or an access log, runs the
detectors with their default thresholds, and prints a plain text
report. Configurable thresholds and JSON output are planned for a
later version, not this one.
"""

import argparse
import sys

from .parser import parse_auth_log, parse_access_log
from .detectors import (
    detect_brute_force,
    detect_login_after_failures,
    detect_web_scanning,
    detect_offhours_logins,
)
from .report import build_report


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logsentry",
        description="Parses SSH auth logs and web access logs and flags suspicious activity.",
    )
    parser.add_argument("--auth-log", help="Path to an SSH auth.log style file")
    parser.add_argument("--access-log", help="Path to an Apache or Nginx combined format access log")
    return parser


def main(argv=None) -> int:
    arg_parser = build_arg_parser()
    args = arg_parser.parse_args(argv)

    if not args.auth_log and not args.access_log:
        arg_parser.error("provide at least one of --auth-log or --access-log")

    brute_force_findings = []
    login_after_failures_findings = []
    offhours_findings = []
    web_scan_findings = []

    if args.auth_log:
        ssh_events = parse_auth_log(args.auth_log)
        brute_force_findings = detect_brute_force(ssh_events)
        login_after_failures_findings = detect_login_after_failures(ssh_events)
        offhours_findings = detect_offhours_logins(ssh_events)

    if args.access_log:
        web_events = parse_access_log(args.access_log)
        web_scan_findings = detect_web_scanning(web_events)

    report = build_report(
        brute_force_findings,
        login_after_failures_findings,
        web_scan_findings,
        offhours_findings,
    )
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
