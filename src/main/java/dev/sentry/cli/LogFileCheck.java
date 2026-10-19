package dev.sentry.cli;

import java.nio.file.Files;
import java.nio.file.Path;

/** Checks the log file argument and explains what is wrong in plain words. */
final class LogFileCheck {

    private LogFileCheck() {
    }

    /** Returns a message describing the problem, or null if the file can be used. */
    static String problem(Path file) {
        if (!Files.exists(file)) {
            return "file not found: " + file;
        }
        if (Files.isDirectory(file)) {
            return file + " is a folder; give the path of a log file inside it";
        }
        if (!Files.isRegularFile(file)) {
            return file + " is not a regular file";
        }
        if (!Files.isReadable(file)) {
            return "cannot read " + file + " (permission denied)";
        }
        return null;
    }
}