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

class InvalidUserDetectorTest {

    private static final String IP = "9.9.9.9";
    private static final LocalDateTime BASE = LocalDateTime.of(2026, 10, 5, 0, 0, 0);

    private static LogEvent invalid(String ip, String user, int second) {
        return new LogEvent(BASE.plusSeconds(second), EventType.FAILED_LOGIN, "password", user, true, ip, 22);
    }

    private static LogEvent valid(String ip, String user, int second) {
        return new LogEvent(BASE.plusSeconds(second), EventType.FAILED_LOGIN, "password", user, false, ip, 22);
    }

    private static List<Finding> detect(int threshold, int windowSeconds, LogEvent... events) {
        return new InvalidUserDetector(threshold, Duration.ofSeconds(windowSeconds)).detect(List.of(events));
    }

    @Test
    void flagsManyDifferentInvalidUsers() {
        List<Finding> findings = detect(5, 10,
                invalid(IP, "a", 0), invalid(IP, "b", 1), invalid(IP, "c", 2), invalid(IP, "d", 3), invalid(IP, "e", 4));
        assertEquals(1, findings.size());
        assertEquals(InvalidUserDetector.RULE, findings.get(0).rule());
        assertEquals(5, findings.get(0).eventCount());
    }

    @Test
    void sameInvalidUserRepeatedIsNotASpray() {
        assertTrue(detect(3, 10,
                invalid(IP, "a", 0), invalid(IP, "a", 1), invalid(IP, "a", 2),
                invalid(IP, "a", 3), invalid(IP, "a", 4), invalid(IP, "a", 5)).isEmpty());
    }

    @Test
    void existingUsersAreIgnored() {
        assertTrue(detect(3, 10, valid(IP, "a", 0), valid(IP, "b", 1), valid(IP, "c", 2)).isEmpty());
    }

    @Test
    void belowThresholdIsNotFlagged() {
        assertTrue(detect(5, 10,
                invalid(IP, "a", 0), invalid(IP, "b", 1), invalid(IP, "c", 2), invalid(IP, "d", 3)).isEmpty());
    }

    @Test
    void windowIsRespected() {
        assertTrue(detect(3, 10, invalid(IP, "a", 0), invalid(IP, "b", 20), invalid(IP, "c", 40)).isEmpty());
        assertEquals(1, detect(3, 10, invalid(IP, "a", 0), invalid(IP, "b", 5), invalid(IP, "c", 10)).size());
        assertTrue(detect(3, 10, invalid(IP, "a", 0), invalid(IP, "b", 5), invalid(IP, "c", 11)).isEmpty());
    }

    @Test
    void separateIpsAreCountedSeparately() {
        assertTrue(detect(3, 10,
                invalid("1.1.1.1", "a", 0), invalid("1.1.1.1", "b", 1),
                invalid("2.2.2.2", "c", 2), invalid("2.2.2.2", "d", 3)).isEmpty());
    }

    @Test
    void severityIsHighAtDoubleThreshold() {
        LogEvent[] five = new LogEvent[5];
        for (int i = 0; i < 5; i++) {
            five[i] = invalid(IP, "u" + i, i);
        }
        LogEvent[] ten = new LogEvent[10];
        for (int i = 0; i < 10; i++) {
            ten[i] = invalid(IP, "u" + i, i);
        }
        assertEquals(Severity.MEDIUM, detect(5, 100, five).get(0).severity());
        assertEquals(Severity.HIGH, detect(5, 100, ten).get(0).severity());
    }

    @Test
    void sustainedSprayIsReportedOnce() {
        LogEvent[] events = new LogEvent[60];
        for (int i = 0; i < 60; i++) {
            events[i] = invalid(IP, "u" + i, i * 2);
        }
        List<Finding> findings = detect(5, 10, events);
        assertEquals(1, findings.size());
        assertEquals(60, findings.get(0).eventCount());
    }

    @Test
    void findsSprayInSampleLog() {
        List<LogEvent> events = new LogParser(2026).parseLines(new SampleLogGenerator(2026, 42).generate()).events();
        List<Finding> findings = new InvalidUserDetector(5, Duration.ofMinutes(10)).detect(events);

        assertEquals(1, findings.size());
        assertEquals("203.0.113.9", findings.get(0).ip());
        assertEquals(8, findings.get(0).eventCount());
        assertEquals(Severity.MEDIUM, findings.get(0).severity());
        assertEquals("8 non-existent usernames tried: admin, ftp, guest, oracle, postgres +3 more",
                findings.get(0).description());
    }

    @Test
    void rejectsInvalidSettings() {
        assertThrows(IllegalArgumentException.class, () -> new InvalidUserDetector(0, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> new InvalidUserDetector(1, Duration.ZERO));
    }
}