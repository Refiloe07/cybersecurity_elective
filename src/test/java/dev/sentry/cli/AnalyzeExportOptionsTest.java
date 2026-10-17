package dev.sentry.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AnalyzeExportOptionsTest {

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
    void jsonGoesToStandardOutputWithoutTheTextHeader(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "--year", "2026", "--format", "json");
        assertEquals(0, r.exitCode());
        assertTrue(r.out().startsWith("{\n"));
        assertTrue(r.out().contains("\"findings\": 5,"));
        assertFalse(r.out().contains("Read 48 lines"));
        assertEquals("", r.err());
    }

    @Test
    void formatNameIsCaseInsensitive(@TempDir Path dir) {
        assertTrue(run("analyze", sampleLog(dir), "--year", "2026", "-f", "JSON").out().startsWith("{"));
    }

    @Test
    void csvGoesToStandardOutput(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "--year", "2026", "--format", "csv");
        assertEquals(0, r.exitCode());
        assertTrue(r.out().startsWith("severity,rule,ip,"));
        assertFalse(r.out().contains("Read 48"));
    }

    @Test
    void quietRunGivesEmptyFindingsInJson(@TempDir Path dir) {
        String out = run("analyze", sampleLog(dir), "--year", "2026", "-f", "json", "-t", "20").out();
        assertTrue(out.contains("\"findings\": []"));
        assertTrue(out.contains("\"topOffenders\": []"));
    }

    @Test
    void unknownFormatIsRejected(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "--format", "xml");
        assertEquals(2, r.exitCode());
        assertTrue(r.err().contains("--format"));
    }

    @Test
    void outputWritesTheFileAndConfirms(@TempDir Path dir) throws Exception {
        String log = sampleLog(dir);
        String onScreen = run("analyze", log, "--year", "2026", "-f", "json").out();

        Path target = dir.resolve("nested").resolve("report.json");
        Run r = run("analyze", log, "--year", "2026", "-f", "json", "-o", target.toString());

        assertEquals(0, r.exitCode());
        assertTrue(r.out().contains("Wrote json report (5 findings) to"));
        assertEquals(1, r.out().lines().count());
        assertEquals(onScreen, Files.readString(target));
    }

    @Test
    void savedTextReportIsNeverColored(@TempDir Path dir) throws Exception {
        Path target = dir.resolve("report.txt");
        run("analyze", sampleLog(dir), "--year", "2026", "--color", "always", "-o", target.toString());
        String text = Files.readString(target);
        assertFalse(text.contains("\u001B"));
        assertTrue(text.contains("Read 48 lines"));
        assertTrue(text.contains("Findings: 5"));
    }

    @Test
    void csvFileMatchesWhatIsPrintedToTheScreen(@TempDir Path dir) throws Exception {
        String log = sampleLog(dir);
        String onScreen = run("analyze", log, "--year", "2026", "-f", "csv").out();
        Path target = dir.resolve("report.csv");
        run("analyze", log, "--year", "2026", "-f", "csv", "-o", target.toString());
        assertEquals(onScreen, Files.readString(target));
    }

    @Test
    void refusesToOverwriteTheInputLog(@TempDir Path dir) throws Exception {
        String log = sampleLog(dir);
        Run r = run("analyze", log, "-o", log);
        assertEquals(2, r.exitCode());
        assertTrue(r.err().contains("refusing to overwrite"));
        assertEquals(48, Files.readAllLines(Path.of(log)).size());
    }

    @Test
    void invalidColorIsStillRejectedWhenSavingToAFile(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "-o", dir.resolve("r.txt").toString(), "--color", "purple");
        assertEquals(2, r.exitCode());
    }

    @Test
    void unwritableOutputReturnsOne(@TempDir Path dir) {
        Run r = run("analyze", sampleLog(dir), "-o", dir.toString());
        assertEquals(1, r.exitCode());
        assertTrue(r.err().contains("could not write"));
    }

    @Test
    void hostileUsernameCannotInjectTerminalCodes(@TempDir Path dir) throws Exception {
        Path evil = dir.resolve("evil.log");
        Files.write(evil, List.of(
                "Oct 10 17:20:48 web01 sshd[1]: Failed password for invalid user \u001B[2J\u001B]0;pwned\u0007 from 1.1.1.1 port 22 ssh2"));
        Run r = run("analyze", evil.toString(), "--year", "2026", "-t", "1", "--color", "never");
        assertEquals(0, r.exitCode());
        assertFalse(r.out().contains("\u001B"));
        assertFalse(r.out().contains("\u0007"));
        assertTrue(r.out().contains("\\x1b[2J"));

        String json = run("analyze", evil.toString(), "--year", "2026", "-t", "1", "-f", "json").out();
        assertTrue(json.chars().allMatch(c -> c < 128));
    }

    @Test
    void hostileIpCannotInjectSpreadsheetFormulas(@TempDir Path dir) throws Exception {
        Path evil = dir.resolve("evil.log");
        Files.write(evil, List.of(
                "Oct 10 17:20:48 web01 sshd[1]: Failed password for root from =1+1 port 22 ssh2"));
        String csv = run("analyze", evil.toString(), "--year", "2026", "-t", "1", "-f", "csv").out();
        assertTrue(csv.contains(",'=1+1,"));
    }
}