# LogSentry

Command line tool that parses SSH auth logs and Apache/Nginx access logs and flags brute force attempts, logins after repeated failures, web scanning behavior, and off-hours logins.

Version 0.1, early and rough. Read the limitations below before trusting it on anything real.

## Running it

Python 3.9+, no dependencies.

\`\`\`
python -m logsentry.cli --auth-log /var/log/auth.log --access-log /var/log/nginx/access.log
\`\`\`

Needs at least one of `--auth-log` or `--access-log`. Sample logs are in `tests/sample_logs`.

## What it flags

- 5+ failed SSH logins from one IP in 10 minutes
- A login right after 3+ failed attempts from the same IP
- 20+ 403/404 responses from one IP in 5 minutes
- SSH logins between 10pm and 5am, shown as context, not an alert

Thresholds are hardcoded for now.

## Known limitations

auth.log has no year in its timestamps, so the year is guessed from the current date, breaks across a December/January boundary. Off-hours detection has no timezone awareness. Brute force and scanning detection use fixed time buckets instead of a true sliding window, so an attack split across a boundary can slip through. Nothing persists between runs. No tests yet.