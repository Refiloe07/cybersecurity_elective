package dev.sentry.detect;

import dev.sentry.model.EventType;
import dev.sentry.model.LogEvent;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Flags any IP address with at least {@code threshold} failed logins inside a
 * sliding time window.
 *
 * Two failures exactly {@code window} apart still count as inside the same window.
 * Consecutive overlapping windows that all reach the threshold are merged into one
 * finding, so a single sustained attack is reported once, not once per login.
 * Severity is HIGH once the burst reaches twice the threshold, otherwise MEDIUM.
 */
public class BruteForceDetector {

    public static final String RULE = "brute-force";
    private static final int MAX_USERS_SHOWN = 5;

    private final int threshold;
    private final Duration window;

    public BruteForceDetector(int threshold, Duration window) {
        if (threshold < 1) {
            throw new IllegalArgumentException("threshold must be at least 1");
        }
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("window must be greater than zero");
        }
        this.threshold = threshold;
        this.window = window;
    }

    /** Returns findings, biggest bursts first. */
    public List<Finding> detect(List<LogEvent> events) {
        Map<String, List<LogEvent>> failuresByIp = new LinkedHashMap<>();
        for (LogEvent e : events) {
            if (e.type() == EventType.FAILED_LOGIN) {
                failuresByIp.computeIfAbsent(e.ip(), ip -> new ArrayList<>()).add(e);
            }
        }

        List<Finding> findings = new ArrayList<>();
        for (Map.Entry<String, List<LogEvent>> entry : failuresByIp.entrySet()) {
            List<LogEvent> failures = new ArrayList<>(entry.getValue());
            failures.sort(Comparator.comparing(LogEvent::timestamp));
            scan(entry.getKey(), failures, findings);
        }

        findings.sort(Comparator.comparingInt(Finding::eventCount).reversed()
                .thenComparing(Finding::firstSeen));
        return findings;
    }

    private void scan(String ip, List<LogEvent> failures, List<Finding> out) {
        int left = 0;
        int burstStart = -1;
        int burstEnd = -1;

        for (int right = 0; right < failures.size(); right++) {
            while (Duration.between(failures.get(left).timestamp(),
                    failures.get(right).timestamp()).compareTo(window) > 0) {
                left++;
            }
            int inWindow = right - left + 1;

            if (inWindow >= threshold) {
                if (burstStart < 0) {
                    burstStart = left;
                }
                burstEnd = right;
            } else if (burstStart >= 0) {
                out.add(toFinding(ip, failures.subList(burstStart, burstEnd + 1)));
                burstStart = -1;
            }
        }
        if (burstStart >= 0) {
            out.add(toFinding(ip, failures.subList(burstStart, burstEnd + 1)));
        }
    }

    private Finding toFinding(String ip, List<LogEvent> burst) {
        TreeSet<String> users = new TreeSet<>();
        for (LogEvent e : burst) {
            users.add(e.user());
        }
        Severity severity = burst.size() >= 2 * threshold ? Severity.HIGH : Severity.MEDIUM;

        List<String> shown = users.stream().limit(MAX_USERS_SHOWN).toList();
        String userText = String.join(", ", shown);
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
                burst.size() + " failed logins; users tried: " + userText);
    }
}