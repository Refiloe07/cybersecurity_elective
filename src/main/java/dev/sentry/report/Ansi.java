package dev.sentry.report;

import dev.sentry.detect.Severity;

/**
 * Wraps text in ANSI color codes, or passes it through untouched when color is off.
 * Because "off" returns the text unchanged, the same rendering code serves both modes.
 */
public final class Ansi {

    private static final String ESC = "\u001B[";
    private static final String RESET = ESC + "0m";

    private final boolean enabled;

    public Ansi(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean enabled() {
        return enabled;
    }

    public String bold(String text) {
        return wrap("1", text);
    }

    public String dim(String text) {
        return wrap("2", text);
    }

    /** Color for a severity: CRITICAL white-on-red, HIGH bold red, MEDIUM yellow, LOW cyan. */
    public String severity(Severity severity, String text) {
        String code = switch (severity) {
            case CRITICAL -> "1;97;41";
            case HIGH -> "1;31";
            case MEDIUM -> "33";
            case LOW -> "36";
        };
        return wrap(code, text);
    }

    private String wrap(String code, String text) {
        return enabled ? ESC + code + "m" + text + RESET : text;
    }
}