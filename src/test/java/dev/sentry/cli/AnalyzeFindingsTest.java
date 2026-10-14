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
    void printsAllRulesForSampleLog(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir).toString(), "--year", "2026");
        assertEquals(0, r.exitCode());
        assertTrue(r.out().contains("Findings: 5"));
        assertTrue(r.out().contains("[CRITICAL] 192.0.2.44"));
        assertTrue(r.out().contains("success-after-failures"));
        assertTrue(r.out().contains("[HIGH    ] 203.0.113.5"));
        assertTrue(r.out().contains("invalid-user: 8 non-existent usernames"));
        assertTrue(r.out().contains("window=10m"));
    }

    @Test
    void criticalFindingIsListedFirst(@TempDir Path dir) {
        String out = run("analyze", sampleLog(dir).toString(), "--year", "2026").out();
        assertTrue(out.indexOf("[CRITICAL]") < out.indexOf("[HIGH    ]"));
        assertTrue(out.indexOf("[HIGH    ]") < out.indexOf("[MEDIUM  ]"));
    }

    @Test
    void higherThresholdFindsNothing(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir).toString(), "--year", "2026", "-t", "20");
        assertEquals(0, r.exitCode());
        assertTrue(r.out().contains("No suspicious activity detected."));
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