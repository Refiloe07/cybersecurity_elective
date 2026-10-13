package dev.sentry.cli;

import dev.sentry.detect.BruteForceDetector;
import dev.sentry.detect.Finding;
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
import java.time.Duration;
import java.time.Year;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.Callable;

@Command(
    name = "analyze",
    mixinStandardHelpOptions = true,
    description = "Analyze an auth log file and report suspicious activity."
)
public class AnalyzeCommand implements Callable<Integer> {

    private static final DateTimeFormatter SHOWN_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Parameters(index = "0", paramLabel = "LOGFILE", description = "Path to the auth log to analyze.")
    private Path logFile;

    @Option(names = {"-t", "--threshold"}, defaultValue = "5",
            description = "Failed logins from one IP that count as brute force (default: ${DEFAULT-VALUE}).")
    private int threshold;

    @Option(names = {"-w", "--window"}, defaultValue = "10m", converter = DurationConverter.class,
            description = "Time window for the threshold, e.g. 30s, 10m, 2h, 1d (default: ${DEFAULT-VALUE}).")
    private Duration window;

    @Option(names = {"-y", "--year"},
            description = "Year to assume, since syslog lines have none (default: current year).")
    private int year = Year.now().getValue();

    @Override
    public Integer call() {
        if (!Files.isRegularFile(logFile)) {
            System.err.println("error: file not found: " + logFile);
            return 2;
        }
        if (threshold < 1) {
            System.err.println("error: --threshold must be at least 1");
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
            System.out.printf("Settings: threshold=%d, window=%s, year=%d%n",
                    threshold, DurationConverter.format(window), year);
            System.out.println();

            List<Finding> findings = new BruteForceDetector(threshold, window).detect(result.events());
            if (findings.isEmpty()) {
                System.out.println("No brute-force activity detected.");
            } else {
                System.out.printf("Brute-force findings: %d%n", findings.size());
                for (Finding f : findings) {
                    System.out.printf("  [%-6s] %-15s %s (%s to %s)%n",
                            f.severity(), f.ip(), f.description(),
                            f.firstSeen().format(SHOWN_TIME), f.lastSeen().format(SHOWN_TIME));
                }
            }
            return 0;
        } catch (IOException | UncheckedIOException e) {
            System.err.println("error: could not read " + logFile
                    + " (is it a UTF-8 text file?): " + e.getMessage());
            return 1;
        }
    }
}