package dev.sentry.live;

import dev.sentry.detect.Finding;
import dev.sentry.detect.Severity;
import dev.sentry.report.Ansi;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

class AlertFormatterTest {

    private final Finding finding = new Finding("brute-force", Severity.MEDIUM, "203.0.113.5",
            LocalDateTime.of(2026, 10, 5, 2, 14, 0), LocalDateTime.of(2026, 10, 5, 2, 14, 4),
            5, "5 failed logins; users tried: root");

    @Test
    void formatsOneReadableLine() {
        assertEquals("2026-10-05 02:14:04  [MEDIUM  ] 203.0.113.5     brute-force: 5 failed logins; users tried: root",
                AlertFormatter.format(new Alert(finding, false), new Ansi(false)));
    }

    @Test
    void marksEscalations() {
        assertTrue(AlertFormatter.format(new Alert(finding, true), new Ansi(false)).endsWith("  (escalated)"));
    }

    @Test
    void colorOnlyAddsEscapeCodes() {
        String plain = AlertFormatter.format(new Alert(finding, true), new Ansi(false));
        String colored = AlertFormatter.format(new Alert(finding, true), new Ansi(true));

        assertTrue(colored.contains("\u001B[33m[MEDIUM  ]\u001B[0m"));
        assertEquals(plain, colored.replaceAll("\u001B\\[[0-9;]*m", ""));
    }
}