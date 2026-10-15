package dev.sentry.detect;

import dev.sentry.model.EventType;
import dev.sentry.model.LogEvent;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Flags a successful login that comes right after many failures from the same IP.
 * That is the worrying case: the guessing may have worked.
 *
 * For every accepted login, it counts failed logins from the same IP (any username)
 * in the {@code window} before it. If that count reaches {@code threshold}, it
 * raises a CRITICAL finding. Failures that happen after the success, or from other
 * IPs, are not counted. Events at the same second are judged in file order.
 *
 * Each accepted login is judged on its own, so two successes after one burst give
 * two findings. A shared IP (an office behind one router, say) can cause false alarms.
 */
public class SuccessAfterFailuresDetector implements Rule {

    public static final String RULE = "success-after-failures";

    private final int threshold;
    private final Duration window;

    public SuccessAfterFailuresDetector(int threshold, Duration window) {
        if (threshold < 1) {
            throw new IllegalArgumentException("threshold must be at least 1");
        }
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("window must be greater than zero");
        }
        this.threshold = threshold;
        this.window = window;
    }

    @Override
    public String name() {
        return RULE;
    }

    @Override
    public String description() {
        return "A successful login right after many failures from the same IP.";
    }

    @Override
    public List<Finding> detect(List<LogEvent> events) {
        List<LogEvent> ordered = new ArrayList<>(events);
        ordered.sort(Comparator.comparing(LogEvent::timestamp)); // stable: ties keep file order

        Map<String, ArrayDeque<LocalDateTime>> recentFailures = new HashMap<>();
        List<Finding> findings = new ArrayList<>();

        for (LogEvent e : ordered) {
            ArrayDeque<LocalDateTime> failures =
                    recentFailures.computeIfAbsent(e.ip(), ip -> new ArrayDeque<>());

            if (e.type() == EventType.FAILED_LOGIN) {
                failures.addLast(e.timestamp());
            } else if (e.type() == EventType.ACCEPTED_LOGIN) {
                LocalDateTime cutoff = e.timestamp().minus(window);
                while (!failures.isEmpty() && failures.peekFirst().isBefore(cutoff)) {
                    failures.removeFirst();
                }
                if (failures.size() >= threshold) {
                    int count = failures.size();
                    findings.add(new Finding(
                            RULE,
                            Severity.CRITICAL,
                            e.ip(),
                            failures.peekFirst(),
                            e.timestamp(),
                            count + 1,
                            "login as '" + e.user() + "' succeeded after " + count
                                    + (count == 1 ? " failed attempt" : " failed attempts")
                                    + " from the same IP"));
                }
            }
        }
        return findings;
    }
}