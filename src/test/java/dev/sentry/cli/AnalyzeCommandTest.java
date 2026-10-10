package dev.sentry.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AnalyzeCommandTest {

    @Test
    void helpExitsZero() {
        int code = new CommandLine(new Main()).execute("--help");
        assertEquals(0, code);
    }

    @Test
    void missingFileReturnsTwo(@TempDir Path dir) {
        int code = new CommandLine(new Main()).execute("analyze", dir.resolve("nope.log").toString());
        assertEquals(2, code);
    }

    @Test
    void existingFileReturnsZero(@TempDir Path dir) throws Exception {
        Path log = dir.resolve("auth.log");
        Files.write(log, List.of("line one", "line two"));
        int code = new CommandLine(new Main()).execute("analyze", log.toString());
        assertEquals(0, code);
    }
}