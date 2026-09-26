# LogSentry

Command line tool that reads SSH auth logs and Apache/Nginx access logs and flags some common signs of trouble, brute force attempts, logins after a bunch of failures, IPs scanning for admin panels and config files, and logins at odd hours.

Built alongside a Splunk lab I've been working through. Wanted something that does the analysis in code instead of clicking around a dashboard.

Version 0.1. Works, but not close to done, read the limitations below before trusting it on anything real.

## Running it

Just Python 3.9+, no dependencies.

\`\`\`
git clone https://github.com/harshilmodi2910/logsentry.git
cd logsentry
python -m logsentry.cli --auth-log /var/log/auth.log --access-log /var/log/nginx/access.log
\`\`\`

Need at least one of `--auth-log` or `--access-log`. Sample logs are in `tests/sample_logs` if you want to try it without real files.

## What it flags

- 5+ failed SSH logins from one IP in 10 minutes
- A login that succeeds right after 3+ failed attempts from the same IP
- 20+ 403/404 responses from one IP in 5 minutes, usually means scanning
- SSH logins between 10pm and 5am, shown as context, not a hard alert, plenty of people work odd hours

Thresholds are hardcoded for now, no CLI flags yet.

## What's broken or missing

auth.log has no year in its timestamps, so the year gets guessed off the current date. Breaks if your log crosses a December/January boundary.

Off-hours detection has no timezone awareness, just whatever local time the server clock had. Same reason it's flagged as context and not an alert.

Brute force and scanning detection use fixed time buckets, not a real sliding window, so an attack split across a bucket boundary can slip through. Known gap, fixing it next.

Nothing persists between runs either, same log lines can get flagged again the next day if they're still inside the window. No tests yet. Configurable thresholds, JSON output, and the sliding window fix are next.