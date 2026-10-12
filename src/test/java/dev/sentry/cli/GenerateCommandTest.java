package dev.sentry.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class GenerateCommandTest {

    @Test
    void writesLogThatAnalyzeCanRead(@TempDir Path dir) throws Exception {
        Path out = dir.resolve("nested").resolve("auth.log");

        int gen = new CommandLine(new Main()).execute("generate", "-o", out.toString(), "--year", "2026");
        assertEquals(0, gen);
        assertTrue(Files.exists(out));
        assertEquals(48, Files.readAllLines(out).size());

        int analyze = new CommandLine(new Main()).execute("analyze", out.toString(), "--year", "2026");
        assertEquals(0, analyze);
    }

    @Test
    void outputOptionIsRequired() {
        assertNotEquals(0, new CommandLine(new Main()).execute("generate"));
    }
}