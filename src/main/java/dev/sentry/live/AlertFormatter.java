package dev.sentry.live;

import dev.sentry.detect.Finding;
import dev.sentry.report.Ansi;

import java.time.format.DateTimeFormatter;

/** Turns an {@link Alert} into one line of text. */
public final class AlertFormatter {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private AlertFormatter() {
    }

    public static String format(Alert alert, Ansi ansi) {
        Finding f = alert.finding();
        return String.format("%s  %s %-15s %s: %s%s",
                f.lastSeen().format(TIME),
                ansi.severity(f.severity(), String.format("[%-8s]", f.severity())),
                f.ip(), f.rule(), f.description(),
                alert.escalation() ? ansi.bold("  (escalated)") : "");
    }
}