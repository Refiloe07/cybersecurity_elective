package dev.sentry.parser;

import dev.sentry.model.LogEvent;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LogParserEdgeCaseTest {

    private final LogParser parser = new LogParser(2026);

    @Test
    void parsesIpv6Source() {
        LogEvent e = parser.parseLine(
                "Oct 10 17:20:48 web01 sshd[1234]: Failed password for root from 2001:db8::1 port 4242 ssh2")
                .orElseThrow();
        assertEquals("2001:db8::1", e.ip());
    }

    @Test
    void parsesSshdWithoutPid() {
        assertTrue(parser.parseLine(
                "Oct 10 17:20:48 web01 sshd: Failed password for root from 1.1.1.1 port 22 ssh2").isPresent());
    }

    @Test
    void parsesUsernameWithDotAndDash() {
        LogEvent e = parser.parseLine(
                "Oct 10 17:20:48 web01 sshd[1]: Failed password for john.doe-1 from 1.1.1.1 port 22 ssh2")
                .orElseThrow();
        assertEquals("john.doe-1", e.user());
    }

    @Test
    void rejectsAbsurdPort() {
        assertTrue(parser.parseLine(
                "Oct 10 17:20:48 web01 sshd[1]: Failed password for root from 1.1.1.1 port 99999999999 ssh2").isEmpty());
    }

    @Test
    void usesConfiguredYearIncludingLeapDay() {
        LogParser leap = new LogParser(2024);
        LogEvent e = leap.parseLine(
                "Feb 29 10:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2")
                .orElseThrow();
        assertEquals(2024, e.timestamp().getYear());
    }

    @Test
    void isoTimestampsAreNotSupportedYet() {
        // Newer systems using journald-style logs write ISO-8601 stamps. Known limitation.
        assertTrue(parser.parseLine(
                "2026-10-10T17:20:48.123456+02:00 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 4242 ssh2")
                .isEmpty());
    }
}