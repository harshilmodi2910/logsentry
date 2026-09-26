# LogSentry

LogSentry is a small command line tool that reads SSH auth logs and Apache or Nginx style web access logs and looks for a few common patterns of suspicious activity. I built this alongside a Splunk home lab I have been working through, mostly because I wanted something that does log analysis in actual code instead of only clicking through a dashboard.

This is the first working version. It does what it says below, but it is not finished, and the Known Limitations section is not just boilerplate, please actually read it before trusting the output on anything real.

## What it looks for

- **SSH brute force attempts.** An IP address with several failed SSH logins in a short window.
- **Successful logins that follow a string of failures.** Same IP, a run of failed attempts, then a login that works. Might be someone finally guessing right, might be a legitimate user who fat fingered their password a few times, worth a look either way.
- **Web scanning behavior.** An IP generating a high volume of 403 or 404 responses in a short window, which usually means something is probing for admin panels, config files, or other paths that should not be reachable.
- **Off-hours logins.** Successful SSH logins between 10pm and 5am. This one shows up as context in the report, not as an alert on its own, since plenty of legitimate admins work night shifts or are just in a different timezone than the server.

## Installation

```
git clone https://github.com/harshilmodi2910/logsentry.git
cd logsentry
```

No external dependencies for this version, everything runs on the Python standard library. Python 3.9 or newer should work fine.

## Usage

```
python -m logsentry.cli --auth-log /var/log/auth.log
python -m logsentry.cli --access-log /var/log/nginx/access.log
python -m logsentry.cli --auth-log /var/log/auth.log --access-log /var/log/nginx/access.log
```

At least one of the two flags is required. To try it against the sample logs included in this repo:

```
python -m logsentry.cli --auth-log tests/sample_logs/auth.log --access-log tests/sample_logs/access.log
```

The tool prints a plain text report to the console. Thresholds are currently fixed at the values described above, there is no way to change them from the command line yet.

## Known limitations

I want to be upfront about what this version does not handle well.

- **Syslog timestamps do not include a year.** auth.log lines look like `Mar 15 03:41:02` with no year attached anywhere. This tool guesses the year based on the current date, which works fine for a log from the current year but gets it wrong for anything spanning a December to January boundary, since the whole file gets stamped with one guessed year even if part of it actually happened the year before.
- **No timezone handling on the SSH side.** auth.log timestamps are just whatever local time the server clock was set to, with no timezone info in the line itself. If the server is in a different timezone than you expect, or logs get shipped somewhere else before you look at them, the off-hours window ends up checked against the wrong clock. This is exactly why off-hours logins are flagged as context instead of as a hard alert.
- **Brute force and web scanning detection use fixed time windows, not a true sliding window.** Both currently chop time into fixed chunks and count events per IP per chunk, instead of checking a rolling window at every point in time. That means an attack spread across a chunk boundary, say three failed logins right before the cutoff and three more right after, can slip past the threshold even though it is really six failed logins in a short stretch. I know this is a real gap and plan on fixing it with an actual sliding window in the next version.
- **No state between runs.** Every run starts from scratch and reads the whole log file again. Nothing gets saved between runs, so if you run this daily against a log file that keeps growing, the same brute force attempt from yesterday can show up again today if those lines are still recent enough to be inside the detection window.

## Project status

Version 0.1. No automated tests yet. Planned next: a real sliding window for the brute force and web scanning detectors, configurable thresholds via command line flags, JSON output, one more detection rule, and an actual pytest suite with CI.
