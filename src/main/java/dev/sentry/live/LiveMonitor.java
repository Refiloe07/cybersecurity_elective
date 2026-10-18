package dev.sentry.live;

import dev.sentry.detect.Finding;
import dev.sentry.detect.RuleEngine;
import dev.sentry.detect.Severity;
import dev.sentry.model.LogEvent;
import dev.sentry.parser.LogParser;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Turns a stream of log lines into alerts. It keeps a rolling buffer of recent
 * events, runs the rules over it whenever new lines arrive, and raises an alert only
 * the first time something is found.
 *
 * <p>Time comes from the log itself, not the computer's clock, so replaying an old
 * log behaves the same as watching a live one.
 *
 * <p>An <em>incident</em> is one rule firing for one IP. Once it has been announced it
 * stays quiet while the attack continues, and alerts again only if it becomes more
 * serious (for example a brute-force burst growing from MEDIUM to HIGH) or after the
 * IP has been quiet for longer than the window.
 *
 * <p>This class does no file or screen work, so it is easy to test.
 */
public final class LiveMonitor {

    private record Incident(LocalDateTime lastSeen, Severity severity) {
    }

    private final RuleEngine engine;
    private final Duration window;
    private final Duration retention;
    private final Duration step;
    private final List<LogEvent> buffer = new ArrayList<>();
    private final Map<String, Incident> incidents = new HashMap<>();

    private int year;
    private LogParser parser;
    private LocalDateTime newest;
    private LocalDateTime evaluatedAt;
    private boolean unevaluated;

    public LiveMonitor(int year, RuleEngine engine, Duration window) {
        this.year = year;
        this.parser = new LogParser(year);
        this.engine = engine;
        this.window = window;
        this.retention = window.multipliedBy(2);
        this.step = window.dividedBy(2);
    }

    /** Feed newly read lines; returns the alerts they caused, oldest first. */
    public List<Alert> accept(List<String> lines) {
        List<Alert> alerts = new ArrayList<>();
        for (String line : lines) {
            Optional<LogEvent> parsed = parser.parseLine(line);
            if (parsed.isEmpty()) {
                continue;
            }
            LogEvent event = parsed.get();
            if (newest != null && event.timestamp().isBefore(newest.minusDays(180))) {
                // syslog has no year: a January line after December means the year rolled over
                year++;
                parser = new LogParser(year);
                parsed = parser.parseLine(line);
                if (parsed.isEmpty()) {
                    continue;
                }
                event = parsed.get();
            }

            // A big batch (such as an old log read from the start) covers a lot of log time.
            // Run the rules every half window of that time, before old events are forgotten,
            // so an attack from long ago is still noticed.
            if (unevaluated && event.timestamp().isAfter(evaluatedAt.plus(step))) {
                evaluate(alerts);
            }

            buffer.add(event);
            unevaluated = true;
            if (newest == null || event.timestamp().isAfter(newest)) {
                newest = event.timestamp();
            }
            if (evaluatedAt == null) {
                evaluatedAt = event.timestamp();
            }
        }
        if (unevaluated) {
            evaluate(alerts);
        }
        return alerts;
    }

    /** How many events are currently remembered (for tests). */
    public int bufferedEvents() {
        return buffer.size();
    }

    private void judge(Finding f, List<Alert> alerts) {
        String key = f.rule() + "|" + f.ip();
        Incident previous = incidents.get(key);

        if (previous == null || f.firstSeen().isAfter(previous.lastSeen().plus(window))) {
            incidents.put(key, new Incident(f.lastSeen(), f.severity()));
            alerts.add(new Alert(f, false));
            return;
        }

        boolean worse = f.severity().compareTo(previous.severity()) > 0;
        incidents.put(key, new Incident(
                f.lastSeen().isAfter(previous.lastSeen()) ? f.lastSeen() : previous.lastSeen(),
                worse ? f.severity() : previous.severity()));
        if (worse) {
            alerts.add(new Alert(f, true));
        }
    }

    private void evaluate(List<Alert> alerts) {
        List<Finding> findings = new ArrayList<>(engine.run(buffer));
        findings.sort(Comparator.comparing(Finding::firstSeen)); // judge incidents oldest first
        List<Alert> fresh = new ArrayList<>();
        for (Finding f : findings) {
            judge(f, fresh);
        }
        fresh.sort(Comparator.comparing((Alert a) -> a.finding().lastSeen())); // show in time order
        alerts.addAll(fresh);
        prune();
        evaluatedAt = newest;
        unevaluated = false;
    }

    private void prune() {
        LocalDateTime cutoff = newest.minus(retention);
        buffer.removeIf(e -> e.timestamp().isBefore(cutoff));
        incidents.values().removeIf(i -> i.lastSeen().plus(retention).isBefore(newest));
    }
}