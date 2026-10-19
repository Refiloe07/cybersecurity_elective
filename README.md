# sentry

[![CI](https://github.com/Refiloe07/cybersecurity_elective/actions/workflows/ci.yml/badge.svg)](https://github.com/Refiloe07/cybersecurity_elective/actions/workflows/ci.yml)

**sentry** reads SSH login logs and tells you who is trying to break in.

A server writes a line to its log for every login attempt. When someone is guessing
passwords there can be thousands of lines, far too many to read. sentry reads them
for you and prints a short, ranked list of what looks suspicious. It is one small
Java program: it only reads logs, never changes anything, and sends nothing anywhere.

```text
Findings: 5 (1 CRITICAL, 1 HIGH, 3 MEDIUM) across 3 IPs
  [CRITICAL] 192.0.2.44      success-after-failures: login as 'deploy' succeeded after 7 failed attempts from the same IP (2026-10-05 22:30:00 to 2026-10-05 22:30:16)
  [HIGH    ] 203.0.113.5     brute-force: 12 failed logins; users tried: root (2026-10-05 02:14:00 to 2026-10-05 02:14:11)
  [MEDIUM  ] 203.0.113.9     brute-force: 8 failed logins; users tried: admin, ftp, guest, oracle, postgres +3 more (2026-10-05 03:40:00 to 2026-10-05 03:40:21)
  [MEDIUM  ] 203.0.113.9     invalid-user: 8 non-existent usernames tried: admin, ftp, guest, oracle, postgres +3 more (2026-10-05 03:40:00 to 2026-10-05 03:40:21)
  [MEDIUM  ] 192.0.2.44      brute-force: 7 failed logins; users tried: deploy (2026-10-05 22:30:00 to 2026-10-05 22:30:12)

Top offending IPs
  IP               Failed  Accepted  Findings  Worst
  192.0.2.44            7         1         2  CRITICAL
  203.0.113.5          12         0         1  HIGH
  203.0.113.9           8         0         2  MEDIUM

Failed logins by hour
  2026-10-05 02:00  ############################## 12
  2026-10-05 03:00  ####################            8
  2026-10-05 17:00  #####                           2
  2026-10-05 22:00  ##################              7
```

The most serious finding is the first one: someone failed seven times and then **got in**.

## Quick start

You need Java 17 or newer.

**Option 1: download.** Get `sentry.jar` from the [Releases](../../releases) page.

**Option 2: build it.** You also need Maven.

```bash
mvn package
```

Then try it on a fake log, so no real server is needed:

```bash
java -jar sentry.jar generate -o samples/auth.log --year 2026
java -jar sentry.jar analyze samples/auth.log --year 2026
java -jar sentry.jar watch samples/auth.log --from-start --for 2s --year 2026
```

On a real Linux server, point it at `/var/log/auth.log` (you may need `sudo` to read it).

## Commands

| Command | What it does |
|---|---|
| `sentry analyze LOGFILE` | Analyze a whole log and print a report (text, JSON or CSV). |
| `sentry watch LOGFILE` | Follow a log live and print an alert the moment a rule fires. |
| `sentry generate -o FILE` | Write a fake log containing realistic attacks, for practice and tests. |
| `sentry rules` | List the detection rules. |

Every command has `--help` with examples. The options you will use most:

| Option | Meaning |
|---|---|
| `-t N` | How many failures count as suspicious (default 5). |
| `-w 10m` | The time window for that count: `30s`, `10m`, `2h`, `1d`. |
| `-T brute-force=20` | Change the threshold of one rule only. |
| `-s invalid-user` | Leave a rule out. |
| `-f json` / `-f csv` | Machine-readable output. |
| `-o FILE` | Save the report to a file instead of the screen. |
| `--no-color` | Turn colors off. |

## The rules

| Rule | What it looks for | Severity |
|---|---|---|
| `brute-force` | At least N failed logins from one IP inside the time window. | MEDIUM, or HIGH at twice N |
| `invalid-user` | One IP trying N different usernames that do not exist on the server. | MEDIUM, or HIGH at twice N |
| `success-after-failures` | A successful login right after at least N failures from the same IP. | always CRITICAL |

A person who mistypes a password twice and then gets in is **not** flagged. A robot that
makes twelve guesses in eleven seconds is. These are heuristics, so sentry reports what
looks suspicious; it does not prove anyone is an attacker.

## Output formats

- **text** (default): the report above.
- **json**: settings, summary counts, every finding and every offending IP. Output is pure ASCII.
- **csv**: one row per finding. Cells that a spreadsheet would run as formulas are neutralised.

```bash
java -jar sentry.jar analyze auth.log -f json -o report.json
java -jar sentry.jar analyze auth.log -f csv  -o report.csv
```

On Windows PowerShell 5.1, use `-o` rather than `>`; that version of PowerShell saves
redirected output as UTF-16, which many tools cannot read.

## Live mode

`sentry watch` follows the log like `tail -f`. It prints one alert per incident, stays quiet
while an attack continues, and alerts again if it gets more serious (for example MEDIUM to
HIGH). Alerts go to standard output and status messages to standard error, so the alerts
can be piped. It copes with half-written lines, log rotation, and a log that briefly disappears.

## Design decisions

- **Rules are plug-ins.** Each rule implements a small `Rule` interface and is listed in one
  catalog, so adding a rule is one new class and one new line.
- **Sliding windows.** A rule looks at failures inside a moving time window, so ten failures
  spread over a week do not count but ten in ten seconds do. Overlapping windows are merged,
  so one long attack gives one finding, not hundreds.
- **Time comes from the log, not the clock.** Replaying an old log gives the same result as
  watching it live.
- **Untrusted input is cleaned.** Usernames in a log are typed by the attacker. Control and
  invisible characters are replaced by visible escapes like `\x1b` so a hostile username
  cannot clear your screen or disguise text. CSV and JSON are escaped for the same reason.
- **No JSON library.** The JSON writer is about 100 lines and covers only what sentry outputs.
  The trade-off is that it only writes JSON; swapping in Jackson later would be easy.
- **One input at a time.** Everything is a pure function of the log lines, which keeps it
  easy to test.

## Limitations

- Only classic syslog timestamps (`Oct 10 17:20:48`) are read; ISO-8601 timestamps are not yet supported.
- syslog carries no year or time zone. Use `--year` for old logs; times are shown as logged.
- Only sshd password and public-key logins are analyzed.
- Many users behind one shared address (an office or a campus) can look like one noisy IP.
- A slow attacker who stays under the threshold will not be flagged.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. Findings are reported, not treated as a failure. |
| 1 | A file could not be read or written, or an unexpected error occurred. |
| 2 | Wrong usage: a bad option, an unknown rule, a missing file. |

Set the `SENTRY_DEBUG` environment variable to see a full stack trace for unexpected errors.

## Development

```bash
mvn verify      # compile and run all the tests
```

GitHub Actions builds and tests every push on Linux and Windows with Java 17 and 21.

**Releasing:** set the version in `pom.xml` and `Version.java`, push, wait for CI to pass,
then tag it:

```bash
git tag -a v1.0.0 -m "sentry 1.0.0"
git push origin v1.0.0
```

The release workflow rebuilds, runs the tests, checks that the tag matches the program version,
and publishes `sentry.jar` with a SHA-256 checksum. To check a download on Windows:

```powershell
Get-FileHash sentry.jar -Algorithm SHA256
```

```text
src/main/java/dev/sentry/
  cli/       commands and option handling
  parser/    reads log lines into events, cleans untrusted text
  detect/    the rules and the rule engine
  report/    the readable report and colors
  export/    JSON and CSV
  live/      following a log and raising alerts
  tools/     the fake log generator
```

## License

MIT, see [LICENSE](LICENSE).

## Code

WTC-98J8JRLR