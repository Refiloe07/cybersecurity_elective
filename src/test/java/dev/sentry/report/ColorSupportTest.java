package dev.sentry.report;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ColorSupportTest {

    private static final Map<String, String> NO_ENV = Map.of();

    @Test
    void neverAndAlwaysIgnoreTheEnvironment() {
        assertFalse(ColorSupport.shouldColor("never", false, NO_ENV, true, false));
        assertTrue(ColorSupport.shouldColor("always", false, NO_ENV, false, true));
    }

    @Test
    void noColorFlagBeatsEverything() {
        assertFalse(ColorSupport.shouldColor("always", true, NO_ENV, true, false));
        assertFalse(ColorSupport.shouldColor("auto", true, NO_ENV, true, false));
    }

    @Test
    void autoColorsARealTerminal() {
        assertTrue(ColorSupport.shouldColor("auto", false, NO_ENV, true, false));
    }

    @Test
    void autoSkipsRedirectedOutput() {
        assertFalse(ColorSupport.shouldColor("auto", false, NO_ENV, false, false));
    }

    @Test
    void autoHonorsNoColorEnvironmentVariable() {
        assertFalse(ColorSupport.shouldColor("auto", false, Map.of("NO_COLOR", "1"), true, false));
        // an empty NO_COLOR does not count
        assertTrue(ColorSupport.shouldColor("auto", false, Map.of("NO_COLOR", ""), true, false));
    }

    @Test
    void autoSkipsDumbTerminals() {
        assertFalse(ColorSupport.shouldColor("auto", false, Map.of("TERM", "dumb"), true, false));
    }

    @Test
    void autoOnWindowsNeedsAModernTerminal() {
        assertFalse(ColorSupport.shouldColor("auto", false, NO_ENV, true, true));
        assertTrue(ColorSupport.shouldColor("auto", false, Map.of("WT_SESSION", "x"), true, true));
        assertTrue(ColorSupport.shouldColor("auto", false, Map.of("TERM_PROGRAM", "vscode"), true, true));
        assertTrue(ColorSupport.shouldColor("auto", false, Map.of("ConEmuANSI", "ON"), true, true));
        assertFalse(ColorSupport.shouldColor("auto", false,
                Map.of("WT_SESSION", "x", "NO_COLOR", "1"), true, true));
    }

    @Test
    void modeIsCaseInsensitiveAndNullMeansAuto() {
        assertTrue(ColorSupport.shouldColor(" ALWAYS ", false, NO_ENV, false, false));
        assertFalse(ColorSupport.shouldColor(null, false, NO_ENV, false, false));
    }

    @Test
    void rejectsUnknownMode() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ColorSupport.shouldColor("purple", false, NO_ENV, true, false));
        assertTrue(e.getMessage().contains("--color"));
        assertTrue(e.getMessage().contains("purple"));
    }
}