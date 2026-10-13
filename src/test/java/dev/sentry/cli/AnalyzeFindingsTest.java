package dev.sentry.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class AnalyzeFindingsTest {

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

    private static Path sampleLog(Path dir) {
        Path log = dir.resolve("auth.log");
        assertEquals(0, run("generate", "-o", log.toString(), "--year", "2026").exitCode());
        return log;
    }

    @Test
    void printsFindingsForSampleLog(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir).toString(), "--year", "2026");
        assertEquals(0, r.exitCode());
        assertTrue(r.out().contains("Brute-force findings: 3"));
        assertTrue(r.out().contains("[HIGH  ] 203.0.113.5"));
        assertTrue(r.out().contains("[MEDIUM] 203.0.113.9"));
        assertTrue(r.out().contains("window=10m"));
    }

    @Test
    void higherThresholdFindsNothing(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir).toString(), "--year", "2026", "-t", "20");
        assertEquals(0, r.exitCode());
        assertTrue(r.out().contains("No brute-force activity detected."));
    }

    @Test
    void invalidWindowIsRejected(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir).toString(), "-w", "banana");
        assertEquals(2, r.exitCode());
        assertTrue(r.err().contains("--window"));
    }

    @Test
    void zeroThresholdIsRejected(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir).toString(), "-t", "0");
        assertEquals(2, r.exitCode());
        assertTrue(r.err().contains("--threshold"));
    }
}