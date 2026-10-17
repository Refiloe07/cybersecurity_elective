package dev.sentry.parser;

import dev.sentry.model.LogEvent;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LogParserSecurityTest {

    private final LogParser parser = new LogParser(2026);

    @Test
    void controlCharactersInUsernameAreMadeVisible() {
        LogEvent e = parser.parseLine(
                "Oct 10 17:20:48 web01 sshd[1]: Failed password for invalid user \u001B[2Jevil from 1.1.1.1 port 22 ssh2")
                .orElseThrow();
        assertEquals("\\x1b[2Jevil", e.user());
        assertFalse(e.user().contains("\u001B"));
    }

    @Test
    void controlCharactersInIpAreMadeVisible() {
        LogEvent e = parser.parseLine(
                "Oct 10 17:20:48 web01 sshd[1]: Failed password for root from 1.1.1.\u00071 port 22 ssh2")
                .orElseThrow();
        assertEquals("1.1.1.\\x071", e.ip());
    }

    @Test
    void cleanLinesAreNotChanged() {
        LogEvent e = parser.parseLine(
                "Oct 10 17:20:48 web01 sshd[1]: Accepted publickey for alice from 198.51.100.7 port 22 ssh2")
                .orElseThrow();
        assertEquals("alice", e.user());
        assertEquals("198.51.100.7", e.ip());
        assertEquals("publickey", e.method());
    }
}