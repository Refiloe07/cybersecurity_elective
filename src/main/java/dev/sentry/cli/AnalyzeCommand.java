package dev.sentry.cli;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import java.util.stream.Stream;

@Command(
    name = "analyze",
    mixinStandardHelpOptions = true,
    description = "Analyze an auth log file and report suspicious activity."
)
public class AnalyzeCommand implements Callable<Integer> {

    @Parameters(index = "0", paramLabel = "LOGFILE", description = "Path to the auth log to analyze.")
    private Path logFile;

    @Option(names = {"-t", "--threshold"}, defaultValue = "5",
            description = "Failed logins before an IP is flagged (default: ${DEFAULT-VALUE}).")
    private int threshold;

    @Option(names = {"-w", "--window"}, defaultValue = "10m",
            description = "Time window for brute-force detection (default: ${DEFAULT-VALUE}).")
    private String window;

    @Override
    public Integer call() {
        if (!Files.isRegularFile(logFile)) {
            System.err.println("error: file not found: " + logFile);
            return 2;
        }

        // Day 1 placeholder: just prove we can read the file.
        // The real parser arrives on Day 2.
        try (Stream<String> lines = Files.lines(logFile)) {
            long count = lines.count();
            System.out.printf("Read %d lines from %s%n", count, logFile);
            System.out.printf("Settings: threshold=%d, window=%s%n", threshold, window);
            return 0;
        } catch (IOException | UncheckedIOException e) {
            System.err.println("error: could not read " + logFile
                    + " (is it a UTF-8 text file?): " + e.getMessage());
            return 1;
        }
    }
}