package dev.sentry.detect;

import dev.sentry.model.EventType;
import dev.sentry.model.LogEvent;
import dev.sentry.parser.LogParser;
import dev.sentry.tools.SampleLogGenerator;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SuccessAfterFailuresDetectorTest {

    private static final String IP = "9.9.9.9";
    private static final LocalDateTime BASE = LocalDateTime.of(2026, 10, 5, 0, 0, 0);

    private static LogEvent bad(String ip, String user, int second) {
        return new LogEvent(BASE.plusSeconds(second), EventType.FAILED_LOGIN, "password", user, false, ip, 22);
    }

    private static LogEvent ok(String ip, String user, int second) {
        return new LogEvent(BASE.plusSeconds(second), EventType.ACCEPTED_LOGIN, "password", user, false, ip, 22);
    }

    private static List<Finding> detect(int threshold, int windowSeconds, LogEvent... events) {
        return new SuccessAfterFailuresDetector(threshold, Duration.ofSeconds(windowSeconds)).detect(List.of(events));
    }

    @Test
    void flagsSuccessAfterManyFailures() {
        List<Finding> findings = detect(5, 600,
                bad(IP, "root", 0), bad(IP, "root", 1), bad(IP, "root", 2), bad(IP, "root", 3), bad(IP, "root", 4),
                ok(IP, "root", 10));
        assertEquals(1, findings.size());
        Finding f = findings.get(0);
        assertEquals(Severity.CRITICAL, f.severity());
        assertEquals(6, f.eventCount());
        assertEquals(BASE, f.firstSeen());
        assertEquals(BASE.plusSeconds(10), f.lastSeen());
        assertEquals("login as 'root' succeeded after 5 failed attempts from the same IP", f.description());
    }

    @Test
    void belowThresholdIsNotFlagged() {
        assertTrue(detect(5, 600,
                bad(IP, "r", 0), bad(IP, "r", 1), bad(IP, "r", 2), bad(IP, "r", 3), ok(IP, "r", 10)).isEmpty());
    }

    @Test
    void failuresAfterTheSuccessDoNotCount() {
        assertTrue(detect(3, 600,
                ok(IP, "r", 0), bad(IP, "r", 1), bad(IP, "r", 2), bad(IP, "r", 3)).isEmpty());
    }

    @Test
    void oldFailuresOutsideWindowAreIgnored() {
        assertTrue(detect(3, 60,
                bad(IP, "r", 0), bad(IP, "r", 1), bad(IP, "r", 2), ok(IP, "r", 1000)).isEmpty());
    }

    @Test
    void windowBoundaryIsInclusive() {
        assertEquals(1, detect(3, 60,
                bad(IP, "r", 0), bad(IP, "r", 1), bad(IP, "r", 2), ok(IP, "r", 60)).size());
        assertTrue(detect(3, 60,
                bad(IP, "r", 0), bad(IP, "r", 1), bad(IP, "r", 2), ok(IP, "r", 62)).isEmpty());
    }

    @Test
    void failuresFromOtherIpsDoNotCount() {
        assertTrue(detect(3, 600,
                bad("1.1.1.1", "r", 0), bad("1.1.1.1", "r", 1), bad("1.1.1.1", "r", 2),
                ok("2.2.2.2", "r", 5)).isEmpty());
    }

    @Test
    void countsFailuresAcrossDifferentUsers() {
        assertEquals(1, detect(3, 600,
                bad(IP, "root", 0), bad(IP, "admin", 1), bad(IP, "test", 2), ok(IP, "deploy", 5)).size());
    }

    @Test
    void eachSuccessAfterABurstIsReported() {
        assertEquals(2, detect(3, 600,
                bad(IP, "r", 0), bad(IP, "r", 1), bad(IP, "r", 2), ok(IP, "r", 5), ok(IP, "r", 8)).size());
    }

    @Test
    void sameSecondEventsAreJudgedInFileOrder() {
        // success listed before the failure at the same second: that failure came later
        assertTrue(detect(3, 600,
                bad(IP, "r", 0), bad(IP, "r", 1), ok(IP, "r", 5), bad(IP, "r", 5)).isEmpty());
        // failure listed first: it counts
        assertEquals(1, detect(3, 600,
                bad(IP, "r", 0), bad(IP, "r", 1), bad(IP, "r", 5), ok(IP, "r", 5)).size());
    }

    @Test
    void unsortedInputIsHandled() {
        assertEquals(1, detect(3, 600,
                ok(IP, "r", 5), bad(IP, "r", 2), bad(IP, "r", 0), bad(IP, "r", 1)).size());
    }

    @Test
    void usesSingularWordingForOneFailure() {
        assertEquals("login as 'r' succeeded after 1 failed attempt from the same IP",
                detect(1, 600, bad(IP, "r", 0), ok(IP, "r", 1)).get(0).description());
    }

    @Test
    void findsDeployCompromiseInSampleLog() {
        List<LogEvent> events = new LogParser(2026).parseLines(new SampleLogGenerator(2026, 42).generate()).events();
        List<Finding> findings = new SuccessAfterFailuresDetector(5, Duration.ofMinutes(10)).detect(events);

        assertEquals(1, findings.size());
        Finding f = findings.get(0);
        assertEquals("192.0.2.44", f.ip());
        assertEquals(8, f.eventCount());
        assertEquals(LocalDateTime.of(2026, 10, 5, 22, 30, 0), f.firstSeen());
        assertEquals(LocalDateTime.of(2026, 10, 5, 22, 30, 16), f.lastSeen());
        assertEquals("login as 'deploy' succeeded after 7 failed attempts from the same IP", f.description());
    }

    @Test
    void rejectsInvalidSettings() {
        assertThrows(IllegalArgumentException.class, () -> new SuccessAfterFailuresDetector(0, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> new SuccessAfterFailuresDetector(1, Duration.ZERO));
    }
}