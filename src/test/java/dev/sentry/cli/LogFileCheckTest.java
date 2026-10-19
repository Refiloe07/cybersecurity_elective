package dev.sentry.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

class LogFileCheckTest {

    @Test
    void anOrdinaryFileIsFine(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("a.log");
        Files.writeString(file, "x\n");
        assertNull(LogFileCheck.problem(file));
    }

    @Test
    void aMissingFileIsExplained(@TempDir Path dir) {
        Path missing = dir.resolve("none.log");
        assertEquals("file not found: " + missing, LogFileCheck.problem(missing));
    }

    @Test
    void aFolderIsExplained(@TempDir Path dir) {
        assertEquals(dir + " is a folder; give the path of a log file inside it", LogFileCheck.problem(dir));
    }

    @Test
    void anUnreadableFileIsExplained(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("secret.log");
        Files.writeString(file, "x\n");
        file.toFile().setReadable(false);
        try {
            // Windows and the root user can still read it; there is nothing to test then.
            assumeFalse(Files.isReadable(file), "this system ignores read permissions");
            assertTrue(LogFileCheck.problem(file).contains("permission denied"));
        } finally {
            file.toFile().setReadable(true);
        }
    }
}