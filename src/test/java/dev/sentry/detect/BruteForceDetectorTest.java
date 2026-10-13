package dev.sentry.detect;

import dev.sentry.model.EventType;
import dev.sentry.model.LogEvent;
import dev.sentry.parser.LogParser;
import dev.sentry.tools.SampleLogGenerator;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BruteForceDetectorTest {

    private static final String IP = "203.0.113.5";
    private static final LocalDateTime BASE = LocalDateTime.of(2026, 10, 5, 0, 0, 0);

    private static LogEvent event(EventType type, String ip, String user, int second) {
        return new LogEvent(BASE.plusSeconds(second), type, "password", user, false, ip, 22);
    }

    private static LogEvent fail(String ip, int second) {
        return event(EventType.FAILED_LOGIN, ip, "root", second);
    }

    private static List<LogEvent> burst(int count) {
        List<LogEvent> events = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            events.add(fail(IP, i));
        }
        return events;
    }

    private static List<Finding> detect(int threshold, int windowSeconds, LogEvent... events) {
        return new BruteForceDetector(threshold, Duration.ofSeconds(windowSeconds)).detect(List.of(events));
    }

    @Test
    void flagsBurstAtThreshold() {
        List<Finding> findings = detect(5, 10, fail(IP, 0), fail(IP, 1), fail(IP, 2), fail(IP, 3), fail(IP, 4));
        assertEquals(1, findings.size());
        assertEquals(5, findings.get(0).eventCount());
        assertEquals(IP, findings.get(0).ip());
        assertEquals(BruteForceDetector.RULE, findings.get(0).rule());
    }

    @Test
    void belowThresholdIsNotFlagged() {
        assertTrue(detect(5, 10, fail(IP, 0), fail(IP, 1), fail(IP, 2), fail(IP, 3)).isEmpty());
    }

    @Test
    void failuresExactlyWindowApartAreInside() {
        assertEquals(1, detect(5, 10, fail(IP, 0), fail(IP, 2), fail(IP, 4), fail(IP, 6), fail(IP, 10)).size());
    }

    @Test
    void failuresJustOutsideWindowAreNotCounted() {
        assertTrue(detect(5, 10, fail(IP, 0), fail(IP, 2), fail(IP, 4), fail(IP, 6), fail(IP, 11)).isEmpty());
    }

    @Test
    void slowAttackIsNotFlagged() {
        assertTrue(detect(5, 10, fail(IP, 0), fail(IP, 10), fail(IP, 20), fail(IP, 30), fail(IP, 40)).isEmpty());
    }

    @Test
    void separateIpsAreCountedSeparately() {
        assertTrue(detect(5, 10,
                fail("1.1.1.1", 0), fail("1.1.1.1", 1), fail("1.1.1.1", 2),
                fail("2.2.2.2", 0), fail("2.2.2.2", 1), fail("2.2.2.2", 2)).isEmpty());
    }

    @Test
    void acceptedLoginsDoNotCount() {
        assertTrue(detect(5, 10, fail(IP, 0), fail(IP, 1), fail(IP, 2), fail(IP, 3),
                event(EventType.ACCEPTED_LOGIN, IP, "root", 4)).isEmpty());
    }

    @Test
    void distantBurstsAreReportedSeparately() {
        assertEquals(2, detect(3, 10,
                fail(IP, 0), fail(IP, 1), fail(IP, 2),
                fail(IP, 3600), fail(IP, 3601), fail(IP, 3602)).size());
    }

    @Test
    void unsortedInputIsHandled() {
        assertEquals(1, detect(3, 10, fail(IP, 2), fail(IP, 0), fail(IP, 1)).size());
    }

    @Test
    void sustainedAttackIsReportedOnce() {
        List<LogEvent> events = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            events.add(fail(IP, i * 2));
        }
        List<Finding> findings = new BruteForceDetector(5, Duration.ofSeconds(10)).detect(events);
        assertEquals(1, findings.size());
        assertEquals(100, findings.get(0).eventCount());
    }

    @Test
    void severityScalesWithBurstSize() {
        BruteForceDetector detector = new BruteForceDetector(5, Duration.ofSeconds(10));
        assertEquals(Severity.MEDIUM, detector.detect(burst(6)).get(0).severity());
        assertEquals(Severity.HIGH, detector.detect(burst(10)).get(0).severity());
        assertEquals(Severity.HIGH, detector.detect(burst(12)).get(0).severity());
    }

    @Test
    void rejectsInvalidSettings() {
        assertThrows(IllegalArgumentException.class, () -> new BruteForceDetector(0, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> new BruteForceDetector(1, Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new BruteForceDetector(1, Duration.ofSeconds(-5)));
    }

    @Test
    void findsExpectedPatternsInSampleLog() {
        List<LogEvent> events = new LogParser(2026).parseLines(new SampleLogGenerator(2026, 42).generate()).events();
        List<Finding> findings = new BruteForceDetector(5, Duration.ofMinutes(10)).detect(events);

        assertEquals(List.of("203.0.113.5", "203.0.113.9", "192.0.2.44"),
                findings.stream().map(Finding::ip).toList());
        assertEquals(List.of(12, 8, 7), findings.stream().map(Finding::eventCount).toList());
        assertEquals(List.of(Severity.HIGH, Severity.MEDIUM, Severity.MEDIUM),
                findings.stream().map(Finding::severity).toList());
        // alice's two typos stay below the threshold
        assertTrue(findings.stream().noneMatch(f -> f.ip().equals("198.51.100.7")));
    }

    @Test
    void describesUsersTried() {
        List<LogEvent> events = new LogParser(2026).parseLines(new SampleLogGenerator(2026, 42).generate()).events();
        List<Finding> findings = new BruteForceDetector(5, Duration.ofMinutes(10)).detect(events);

        assertEquals("12 failed logins; users tried: root", findings.get(0).description());
        assertEquals("8 failed logins; users tried: admin, ftp, guest, oracle, postgres +3 more",
                findings.get(1).description());
    }
}