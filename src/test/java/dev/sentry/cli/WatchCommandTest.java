package dev.sentry.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class WatchCommandTest {

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
    void fromStartAnnouncesEveryIncidentInTheSampleLog(@TempDir Path dir) {
        Run r = run("watch", sampleLog(dir), "--from-start", "--for", "1s", "--year", "2026");
        assertEquals(0, r.exitCode());
        assertEquals(5, r.out().lines().count());
        assertTrue(r.out().contains("[CRITICAL] 192.0.2.44"));
        assertTrue(r.err().contains("Watching "));
        assertTrue(r.err().contains("Stopped. 5 alerts raised."));
        assertFalse(r.out().contains("Watching")); // status text stays off stdout
    }

    @Test
    void existingLinesAreIgnoredWithoutFromStart(@TempDir Path dir) {
        Run r = run("watch", sampleLog(dir), "--for", "1s", "--year", "2026");
        assertEquals(0, r.exitCode());
        assertEquals("", r.out());
        assertTrue(r.err().contains("Stopped. 0 alerts raised."));
    }

    @Test
    void linesAppendedWhileWatchingAreAlerted(@TempDir Path dir) throws Exception {
        Path log = dir.resolve("live.log");
        Files.write(log, new byte[0]);
        AtomicReference<Throwable> writerError = new AtomicReference<>();
        Thread writer = new Thread(() -> {
            try {
                Thread.sleep(400);
                Files.writeString(log,
                        "Oct  5 01:00:00 web01 sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2\n"
                      + "Oct  5 01:00:01 web01 sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2\n"
                      + "Oct  5 01:00:02 web01 sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2\n",
                        StandardOpenOption.APPEND);
            } catch (Exception e) {
                writerError.set(e);
            }
        });
        writer.start();

        Run r = run("watch", log.toString(), "--for", "3s", "--interval", "1s", "--year", "2026", "-t", "3");
        writer.join();

        assertNull(writerError.get());
        assertTrue(r.out().contains("brute-force"));
        assertTrue(r.out().contains("9.9.9.9"));
    }

    @Test
    void skippingEveryRuleRaisesNoAlerts(@TempDir Path dir) {
        Run r = run("watch", sampleLog(dir), "--from-start", "--for", "1s", "--year", "2026",
                "--skip", "brute-force,invalid-user,success-after-failures");
        assertEquals("", r.out());
    }

    @Test
    void colorAlwaysAddsEscapeCodes(@TempDir Path dir) {
        Run r = run("watch", sampleLog(dir), "--from-start", "--for", "1s", "--year", "2026", "--color", "always");
        assertTrue(r.out().contains("\u001B[1;97;41m[CRITICAL]\u001B[0m"));
    }

    @Test
    void missingFileIsRejected(@TempDir Path dir) {
        assertEquals(2, run("watch", dir.resolve("none.log").toString()).exitCode());
    }

    @Test
    void zeroThresholdIsRejected(@TempDir Path dir) {
        assertEquals(2, run("watch", sampleLog(dir), "-t", "0").exitCode());
    }

    @Test
    void unknownRuleIsRejected(@TempDir Path dir) {
        Run r = run("watch", sampleLog(dir), "-s", "nope");
        assertEquals(2, r.exitCode());
        assertTrue(r.err().contains("unknown rule"));
    }

    @Test
    void invalidColorAndDurationAreRejected(@TempDir Path dir) {
        String log = sampleLog(dir);
        assertEquals(2, run("watch", log, "--color", "purple").exitCode());
        assertEquals(2, run("watch", log, "--for", "banana").exitCode());
    }

    @Test
    void helpListsTheWatchCommand() {
        assertTrue(run("--help").out().contains("watch"));
    }
}