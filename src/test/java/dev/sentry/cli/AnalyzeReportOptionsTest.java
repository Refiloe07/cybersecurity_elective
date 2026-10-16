package dev.sentry.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class AnalyzeReportOptionsTest {

    private record Run(int exitCode, String out, String err) { }

    private static Run run(String... args) {
        PrintStream oldOut = System.out;
        PrintStream oldErr = System.err;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
        try {
            int code = new CommandLine(new Main()).execute(args);
            return new Run(code, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
        } finally {
            System.setOut(oldOut);
            System.setErr(oldErr);
        }
    }

    private static String sampleLog(Path dir) {
        Path log = dir.resolve("auth.log");
        assertEquals(0, run("generate", "-o", log.toString(), "--year", "2026").exitCode());
        return log.toString();
    }

    @Test
    void defaultReportHasSummaryTableAndTimeline(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "--year", "2026");
        assertEquals(0, r.exitCode());
        assertTrue(r.out().contains("Findings: 5 (1 CRITICAL, 1 HIGH, 3 MEDIUM) across 3 IPs"));
        assertTrue(r.out().contains("Top offending IPs"));
        assertTrue(r.out().contains("Failed logins by hour"));
    }

    @Test
    void outputIsPlainWhenNotAnInteractiveTerminal(@TempDir Path dir) {
        assertFalse(run("analyze", sampleLog(dir), "--year", "2026").out().contains("\u001B"));
    }

    @Test
    void colorAlwaysAddsEscapeCodes(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "--year", "2026", "--color", "always");
        assertEquals(0, r.exitCode());
        assertTrue(r.out().contains("\u001B[1;97;41m[CRITICAL]\u001B[0m"));
    }

    @Test
    void noColorBeatsColorAlways(@TempDir Path dir) {
        String log = sampleLog(dir);
        assertFalse(run("analyze", log, "--year", "2026", "--color", "always", "--no-color").out().contains("\u001B"));
        assertFalse(run("analyze", log, "--year", "2026", "--no-color").out().contains("\u001B"));
        assertFalse(run("analyze", log, "--year", "2026", "--color", "never").out().contains("\u001B"));
    }

    @Test
    void invalidColorModeIsRejected(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "--color", "purple");
        assertEquals(2, r.exitCode());
        assertTrue(r.err().contains("--color"));
    }

    @Test
    void topOptionControlsTheTable(@TempDir Path dir) {
        String log = sampleLog(dir);
        assertFalse(run("analyze", log, "--year", "2026", "--top", "0").out().contains("Top offending IPs"));
        assertTrue(run("analyze", log, "--year", "2026", "--top", "2").out()
                .contains("Top offending IPs (top 2 of 3)"));
    }

    @Test
    void negativeTopIsRejected(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "--top", "-1");
        assertEquals(2, r.exitCode());
        assertTrue(r.err().contains("--top"));
    }

    @Test
    void noTimelineHidesTheChart(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "--year", "2026", "--no-timeline");
        assertEquals(0, r.exitCode());
        assertFalse(r.out().contains("Failed logins by hour"));
    }

    @Test
    void quietRunStillShowsTheTimelineButNoTable(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "--year", "2026", "-t", "20");
        assertTrue(r.out().contains("No suspicious activity detected."));
        assertFalse(r.out().contains("Top offending IPs"));
        assertTrue(r.out().contains("Failed logins by hour"));
    }
}