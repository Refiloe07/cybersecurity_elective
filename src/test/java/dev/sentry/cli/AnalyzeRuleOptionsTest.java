package dev.sentry.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class AnalyzeRuleOptionsTest {

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
    void showsActiveRulesAndTheirThresholds(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "--year", "2026");
        assertEquals(0, r.exitCode());
        assertTrue(r.out().contains("Rules: brute-force=5, invalid-user=5, success-after-failures=5"));
        assertTrue(r.out().contains("Findings: 5"));
    }

    @Test
    void skipOptionRemovesARule(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "--year", "2026", "--skip", "brute-force");
        assertEquals(0, r.exitCode());
        assertTrue(r.out().contains("Findings: 2"));
        assertFalse(r.out().contains("brute-force"));
    }

    @Test
    void skipAcceptsRepeatedAndCommaSeparatedValues(@TempDir Path dir) {
        String log = sampleLog(dir);
        assertTrue(run("analyze", log, "--year", "2026", "-s", "brute-force", "-s", "invalid-user")
                .out().contains("Findings: 1"));
        assertTrue(run("analyze", log, "--year", "2026", "--skip", "brute-force,invalid-user")
                .out().contains("Findings: 1"));
    }

    @Test
    void ruleThresholdOverrideChangesFindings(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "--year", "2026", "-T", "success-after-failures=8");
        assertEquals(0, r.exitCode());
        assertTrue(r.out().contains("success-after-failures=8"));
        assertTrue(r.out().contains("Findings: 4"));
        assertFalse(r.out().contains("[CRITICAL]"));
    }

    @Test
    void ruleThresholdAcceptsSeveralRules(@TempDir Path dir) {
        String log = sampleLog(dir);
        assertTrue(run("analyze", log, "--year", "2026", "-T", "brute-force=20,invalid-user=20")
                .out().contains("Findings: 1"));
        assertTrue(run("analyze", log, "--year", "2026",
                "--rule-threshold", "brute-force=20", "--rule-threshold", "invalid-user=20")
                .out().contains("Findings: 1"));
    }

    @Test
    void unknownRuleInOverrideIsRejected(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "-T", "nope=3");
        assertEquals(2, r.exitCode());
        assertTrue(r.err().contains("unknown rule 'nope'"));
    }

    @Test
    void unknownRuleInSkipIsRejected(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "-s", "nope");
        assertEquals(2, r.exitCode());
        assertTrue(r.err().contains("unknown rule"));
    }

    @Test
    void zeroOverrideIsRejected(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "-T", "brute-force=0");
        assertEquals(2, r.exitCode());
        assertTrue(r.err().contains("brute-force"));
    }

    @Test
    void malformedOverrideIsRejected(@TempDir Path dir) {
        String log = sampleLog(dir);
        assertEquals(2, run("analyze", log, "-T", "brute-force=abc").exitCode());
        assertEquals(2, run("analyze", log, "-T", "brute-force").exitCode());
    }

    @Test
    void skippingEveryRuleReportsNothing(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "--year", "2026",
                "--skip", "brute-force,invalid-user,success-after-failures");
        assertEquals(0, r.exitCode());
        assertTrue(r.out().contains("Rules: (none)"));
        assertTrue(r.out().contains("No suspicious activity detected."));
    }
}