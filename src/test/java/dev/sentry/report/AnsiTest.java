package dev.sentry.report;

import dev.sentry.detect.Severity;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AnsiTest {

    @Test
    void colorOffReturnsTextUnchanged() {
        Ansi off = new Ansi(false);
        assertFalse(off.enabled());
        assertEquals("hi", off.bold("hi"));
        assertEquals("hi", off.dim("hi"));
        for (Severity s : Severity.values()) {
            assertEquals("hi", off.severity(s, "hi"));
        }
    }

    @Test
    void colorOnWrapsTextInCodes() {
        Ansi on = new Ansi(true);
        assertTrue(on.enabled());
        assertEquals("\u001B[1mhi\u001B[0m", on.bold("hi"));
        assertEquals("\u001B[2mhi\u001B[0m", on.dim("hi"));
        assertEquals("\u001B[1;97;41mhi\u001B[0m", on.severity(Severity.CRITICAL, "hi"));
        assertEquals("\u001B[1;31mhi\u001B[0m", on.severity(Severity.HIGH, "hi"));
        assertEquals("\u001B[33mhi\u001B[0m", on.severity(Severity.MEDIUM, "hi"));
        assertEquals("\u001B[36mhi\u001B[0m", on.severity(Severity.LOW, "hi"));
    }
}