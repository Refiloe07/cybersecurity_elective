package dev.sentry.detect;

import dev.sentry.model.EventType;
import dev.sentry.model.LogEvent;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Flags an IP that tries many different usernames that do not exist on the server
 * (a "username spray"). A real person knows their own username, so guessing
 * "admin", "test", "oracle"... is a strong sign of an automated scan.
 *
 * It fires when at least {@code threshold} DIFFERENT non-existent usernames are tried
 * from one IP inside {@code window}. Trying the same wrong name over and over does not
 * count here (the brute-force rule covers that). Overlapping windows are merged into
 * one finding. Severity is HIGH at twice the threshold, otherwise MEDIUM.
 */
public class InvalidUserDetector {

    public static final String RULE = "invalid-user";
    private static final int MAX_USERS_SHOWN = 5;

    private final int threshold;
    private final Duration window;

    public InvalidUserDetector(int threshold, Duration window) {
        if (threshold < 1) {
            throw new IllegalArgumentException("threshold must be at least 1");
        }
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("window must be greater than zero");
        }
        this.threshold = threshold;
        this.window = window;
    }

    public List<Finding> detect(List<LogEvent> events) {
        Map<String, List<LogEvent>> attemptsByIp = new LinkedHashMap<>();
        for (LogEvent e : events) {
            if (e.type() == EventType.FAILED_LOGIN && e.invalidUser()) {
                attemptsByIp.computeIfAbsent(e.ip(), ip -> new ArrayList<>()).add(e);
            }
        }

        List<Finding> findings = new ArrayList<>();
        for (Map.Entry<String, List<LogEvent>> entry : attemptsByIp.entrySet()) {
            List<LogEvent> attempts = new ArrayList<>(entry.getValue());
            attempts.sort(Comparator.comparing(LogEvent::timestamp));
            scan(entry.getKey(), attempts, findings);
        }

        findings.sort(Comparator.comparingInt(Finding::eventCount).reversed()
                .thenComparing(Finding::firstSeen));
        return findings;
    }

    private void scan(String ip, List<LogEvent> attempts, List<Finding> out) {
        Map<String, Integer> inWindow = new HashMap<>(); // username -> attempts inside the window
        int left = 0;
        int burstStart = -1;
        int burstEnd = -1;

        for (int right = 0; right < attempts.size(); right++) {
            inWindow.merge(attempts.get(right).user(), 1, Integer::sum);
            while (Duration.between(attempts.get(left).timestamp(),
                    attempts.get(right).timestamp()).compareTo(window) > 0) {
                String leaving = attempts.get(left).user();
                if (inWindow.merge(leaving, -1, Integer::sum) == 0) {
                    inWindow.remove(leaving);
                }
                left++;
            }

            if (inWindow.size() >= threshold) {
                if (burstStart < 0) {
                    burstStart = left;
                }
                burstEnd = right;
            } else if (burstStart >= 0) {
                out.add(toFinding(ip, attempts.subList(burstStart, burstEnd + 1)));
                burstStart = -1;
            }
        }
        if (burstStart >= 0) {
            out.add(toFinding(ip, attempts.subList(burstStart, burstEnd + 1)));
        }
    }

    private Finding toFinding(String ip, List<LogEvent> burst) {
        TreeSet<String> users = new TreeSet<>();
        for (LogEvent e : burst) {
            users.add(e.user());
        }
        Severity severity = users.size() >= 2 * threshold ? Severity.HIGH : Severity.MEDIUM;

        String userText = String.join(", ", users.stream().limit(MAX_USERS_SHOWN).toList());
        if (users.size() > MAX_USERS_SHOWN) {
            userText += " +" + (users.size() - MAX_USERS_SHOWN) + " more";
        }

        return new Finding(
                RULE,
                severity,
                ip,
                burst.get(0).timestamp(),
                burst.get(burst.size() - 1).timestamp(),
                burst.size(),
                users.size() + " non-existent usernames tried: " + userText);
    }
}