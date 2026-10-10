# sentry

A Java command-line tool that analyzes SSH/auth logs and flags suspicious activity such as brute-force attempts.

> Status: Day 1 of a 10-day build. Work in progress.

## Goals

- Parse `auth.log` entries into structured events
- Detect brute-force attempts, invalid usernames, and success-after-failures
- Print a readable terminal report; export JSON/CSV
- Live mode that follows a log file and alerts in real time

## Build and run

Requires Java 17+ and Maven.

```bash
mvn package
java -jar target/sentry.jar --help
java -jar target/sentry.jar analyze path/to/auth.log --threshold 5 --window 10m
```

## Planned usage

## Roadmap

- [x] Day 1: project setup, CLI skeleton
- [ ] Day 2: log parser
- [ ] Day 3: sample logs and parser tests
- [ ] Day 4: brute-force rule
- [ ] Day 5: invalid-user and success-after-failure rules
- [ ] Day 6: rule engine and configurable thresholds
- [ ] Day 7: terminal report
- [ ] Day 8: JSON/CSV export
- [ ] Day 9: live mode and CI
- [ ] Day 10: polish and v1.0 release

## License

TBD