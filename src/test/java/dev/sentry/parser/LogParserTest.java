package dev.sentry.parser;

import dev.sentry.model.EventType;
import dev.sentry.model.LogEvent;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class LogParserTest {

    private final LogParser parser = new LogParser(2026);

    @Test
    void parsesFailedPassword() {
        Optional<LogEvent> e = parser.parseLine(
                "Oct 10 17:20:48 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 4242 ssh2");
        assertTrue(e.isPresent());
        assertEquals(EventType.FAILED_LOGIN, e.get().type());
        assertEquals("root", e.get().user());
        assertEquals("203.0.113.5", e.get().ip());
        assertEquals(4242, e.get().port());
        assertFalse(e.get().invalidUser());
        assertEquals(LocalDateTime.of(2026, 10, 10, 17, 20, 48), e.get().timestamp());
    }

    @Test
    void parsesInvalidUserAndSingleDigitDay() {
        LogEvent e = parser.parseLine(
                "Oct  5 03:01:09 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 4243 ssh2")
                .orElseThrow();
        assertTrue(e.invalidUser());
        assertEquals("admin", e.user());
        assertEquals(5, e.timestamp().getDayOfMonth());
    }

    @Test
    void parsesAcceptedPublickey() {
        LogEvent e = parser.parseLine(
                "Oct 10 17:21:05 web01 sshd[1241]: Accepted publickey for bob from 198.51.100.8 port 51001 ssh2: RSA SHA256:abc")
                .orElseThrow();
        assertEquals(EventType.ACCEPTED_LOGIN, e.type());
        assertEquals("publickey", e.method());
        assertEquals("bob", e.user());
    }

    @Test
    void ignoresUnrelatedAndMalformedLines() {
        assertTrue(parser.parseLine("Oct 10 17:22:01 web01 CRON[99]: session opened").isEmpty());
        assertTrue(parser.parseLine("").isEmpty());
        assertTrue(parser.parseLine("garbage").isEmpty());
        assertTrue(parser.parseLine(null).isEmpty());
    }

    @Test
    void rejectsImpossibleDate() {
        assertTrue(parser.parseLine(
                "Feb 29 10:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2").isEmpty());
    }

    @Test
    void countsSkippedLines() {
        ParseResult r = parser.parseLines(List.of(
                "Oct 10 17:20:48 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 4242 ssh2",
                "not a log line"));
        assertEquals(2, r.totalLines());
        assertEquals(1, r.events().size());
        assertEquals(1, r.skippedLines());
    }
}