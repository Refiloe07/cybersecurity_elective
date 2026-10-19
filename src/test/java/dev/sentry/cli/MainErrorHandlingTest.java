package dev.sentry.cli;

import dev.sentry.Version;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;
import picocli.CommandLine.Command;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

class MainErrorHandlingTest {

    @Command(name = "boom")
    static class Boom implements Callable<Integer> {
        public Integer call() {
            throw new IllegalStateException("kaboom");
        }
    }

    @Command(name = "silent")
    static class Silent implements Callable<Integer> {
        public Integer call() {
            throw new NullPointerException();
        }
    }

    private record Run(int exitCode, String out, String err) { }

    /** The command line is built after the streams are swapped so its output is captured. */
    private static Run run(Supplier<CommandLine> commandLine, String... args) {
        PrintStream oldOut = System.out;
        PrintStream oldErr = System.err;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
        try {
            int code = commandLine.get().execute(args);
            return new Run(code, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
        } finally {
            System.setOut(oldOut);
            System.setErr(oldErr);
        }
    }

    private static Run run(String... args) {
        return run(() -> Main.newCommandLine(false), args);
    }

    private static Supplier<CommandLine> withSubcommand(boolean debug, Object subcommand) {
        return () -> {
            CommandLine cmd = Main.newCommandLine(debug);
            cmd.addSubcommand(subcommand);
            return cmd;
        };
    }

    @Test
    void aTypoSuggestsTheRightCommand() {
        Run r = run("analize", "x.log");
        assertEquals(2, r.exitCode());
        assertTrue(r.err().startsWith("error: Unmatched argument"));
        assertTrue(r.err().contains("Did you mean"));
        assertTrue(r.err().contains("analyze"));
        assertTrue(r.err().contains("Try 'sentry --help' for more information."));
        assertFalse(r.err().contains("Usage:"));
        assertFalse(r.out().contains("Usage:"));
    }

    @Test
    void anUnknownOptionNamesTheCommandInTheHint() {
        Run r = run("analyze", "x.log", "--bogus");
        assertEquals(2, r.exitCode());
        assertTrue(r.err().contains("Unknown option"));
        assertTrue(r.err().contains("Try 'sentry analyze --help' for more information."));
    }

    @Test
    void aMissingArgumentIsReportedBriefly() {
        Run r = run("analyze");
        assertEquals(2, r.exitCode());
        assertTrue(r.err().contains("Missing required parameter"));
    }

    @Test
    void aBadOptionValueMentionsTheOption() {
        Run r = run("analyze", "x.log", "-w", "banana");
        assertEquals(2, r.exitCode());
        assertTrue(r.err().contains("--window"));
    }

    @Test
    void aMissingRequiredOptionPointsAtTheRightHelp() {
        Run r = run("generate");
        assertEquals(2, r.exitCode());
        assertTrue(r.err().contains("Try 'sentry generate --help'"));
    }

    @Test
    void anUnexpectedProblemShowsAFriendlyMessage() {
        Run r = run(withSubcommand(false, new Boom()), "boom");
        assertEquals(1, r.exitCode());
        assertTrue(r.err().contains("error: unexpected problem: kaboom"));
        assertTrue(r.err().contains("SENTRY_DEBUG"));
        assertFalse(r.err().contains("\tat "));
    }

    @Test
    void debugModeShowsTheStackTrace() {
        Run r = run(withSubcommand(true, new Boom()), "boom");
        assertEquals(1, r.exitCode());
        assertTrue(r.err().contains("IllegalStateException"));
        assertTrue(r.err().contains("\tat "));
        assertFalse(r.err().contains("SENTRY_DEBUG"));
    }

    @Test
    void anExceptionWithoutAMessageStillReadsWell() {
        Run r = run(withSubcommand(false, new Silent()), "silent");
        assertTrue(r.err().contains("unexpected problem: NullPointerException"));
    }

    @Test
    void versionFlagPrintsTheVersion() {
        Run r = run("--version");
        assertEquals(0, r.exitCode());
        assertEquals("sentry " + Version.CURRENT, r.out().trim());
    }

    @Test
    void noArgumentsPrintsUsageAndSucceeds() {
        Run r = run();
        assertEquals(0, r.exitCode());
        assertTrue(r.out().contains("Usage: sentry"));
    }

    @Test
    void aFolderInsteadOfAFileIsExplained(@TempDir Path dir) {
        Run analyze = run("analyze", dir.toString());
        assertEquals(2, analyze.exitCode());
        assertTrue(analyze.err().contains("is a folder"));

        Run watch = run("watch", dir.toString());
        assertEquals(2, watch.exitCode());
        assertTrue(watch.err().contains("is a folder"));
    }
}