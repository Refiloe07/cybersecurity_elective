# Changelog

## [1.0.0] - 2026-10-19

First release.

### Added
- `sentry analyze`: parse an SSH auth log and report suspicious activity.
- Three detection rules: `brute-force` (many failed logins from one IP in a short
  time), `invalid-user` (one IP guessing many usernames that do not exist) and
  `success-after-failures` (a login that succeeds right after many failures).
- Per-rule thresholds (`-T`), a shared time window (`-w`), and `--skip` to leave
  rules out. `sentry rules` lists the rules.
- A readable report: ranked findings, severity counts, a table of the most
  suspicious IPs and a chart of failed logins by hour, with optional colour.
- JSON and CSV export (`--format`, `--output`).
- `sentry watch`: follow a log live and alert when a rule fires, with one alert
  per incident and an alert when it escalates.
- `sentry generate`: make a fake, repeatable auth log containing realistic attacks.
- GitHub Actions CI (Linux and Windows, Java 17 and 21) and an automated release.

### Security
- Untrusted text from logs (usernames, IPs) is made safe before it is printed, so a
  hostile username cannot send escape codes to your terminal.
- CSV export neutralises cells that a spreadsheet would run as formulas.
- JSON output is pure ASCII, with every special character escaped.

### Known limits
- Only classic syslog timestamps are read (for example `Oct 10 17:20:48`).
- Only sshd password and key logins are analysed.