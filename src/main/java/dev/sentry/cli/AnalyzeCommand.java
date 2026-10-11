package dev.sentry.cli;

import dev.sentry.model.EventType;
import dev.sentry.parser.LogParser;
import dev.sentry.parser.ParseResult;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Year;
import java.util.concurrent.Callable;

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

    @Option(names = {"-y", "--year"},
            description = "Year to assume, since syslog lines have none (default: current year).")
    private int year = Year.now().getValue();

    @Override
    public Integer call() {
        if (!Files.isRegularFile(logFile)) {
            System.err.println("error: file not found: " + logFile);
            return 2;
        }

        try {
            ParseResult result = new LogParser(year).parseFile(logFile);
            long failed = result.events().stream()
                    .filter(e -> e.type() == EventType.FAILED_LOGIN).count();
            long accepted = result.events().size() - failed;

            System.out.printf("Read %d lines from %s%n", result.totalLines(), logFile);
            System.out.printf("Parsed %d SSH events (%d failed, %d accepted); skipped %d other lines%n",
                    result.events().size(), failed, accepted, result.skippedLines());
            System.out.printf("Settings: threshold=%d, window=%s, year=%d%n", threshold, window, year);
            return 0;
        } catch (IOException | UncheckedIOException e) {
            System.err.println("error: could not read " + logFile
                    + " (is it a UTF-8 text file?): " + e.getMessage());
            return 1;
        }
    }
}