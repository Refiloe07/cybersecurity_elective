package dev.sentry.detect;

import java.time.LocalDateTime;

/**
 * Something suspicious found in the log.
 *
 * @param rule        which detection rule produced it, e.g. "brute-force"
 * @param severity    how serious it looks
 * @param ip          the source IP involved
 * @param firstSeen   first event in the pattern
 * @param lastSeen    last event in the pattern
 * @param eventCount  how many log events make up the pattern
 * @param description human-readable summary
 */
public record Finding(
        String rule,
        Severity severity,
        String ip,
        LocalDateTime firstSeen,
        LocalDateTime lastSeen,
        int eventCount,
        String description) {
}