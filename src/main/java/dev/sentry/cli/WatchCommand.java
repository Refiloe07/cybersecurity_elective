package dev.sentry.cli;

import dev.sentry.detect.RuleCatalog;
import dev.sentry.detect.RuleEngine;
import dev.sentry.live.AlertFormatter;
import dev.sentry.live.LiveMonitor;
import dev.sentry.live.LiveWatcher;
import dev.sentry.live.LogTailer;
import dev.sentry.report.Ansi;
import dev.sentry.report.ColorSupport;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Year;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

@Command(
    name = "watch",
    mixinStandardHelpOptions = true,
    description = "Follow a log file and print an alert the moment a rule fires (like tail -f)."
)
public class WatchCommand implements Callable<Integer> {

    @Parameters(index = "0", paramLabel = "LOGFILE", description = "Path to the auth log to follow.")
    private Path logFile;

    @Option(names = {"-t", "--threshold"}, defaultValue = "5",
            description = "Default threshold for every rule (default: ${DEFAULT-VALUE}).")
    private int threshold;

    @Option(names = {"-T", "--rule-threshold"}, split = ",", paramLabel = "RULE=N",
            description = "Override the threshold for one rule, e.g. brute-force=10. See 'sentry rules'.")
    private Map<String, Integer> ruleThresholds;

    @Option(names = {"-s", "--skip"}, split = ",", paramLabel = "RULE",
            description = "Do not run this rule. See 'sentry rules'.")
    private List<String> skipped;

    @Option(names = {"-w", "--window"}, defaultValue = "10m", converter = DurationConverter.class,
            description = "Time window the thresholds apply to, e.g. 30s, 10m, 2h (default: ${DEFAULT-VALUE}).")
    private Duration window;

    @Option(names = "--from-start",
            description = "Also analyze what is already in the file, not just new lines.")
    private boolean fromStart;

    @Option(names = "--interval", defaultValue = "1s", converter = DurationConverter.class,
            description = "How often to check the file for new lines (default: ${DEFAULT-VALUE}).")
    private Duration interval;

    @Option(names = "--for", converter = DurationConverter.class, paramLabel = "DURATION",
            description = "Stop after this long, e.g. 30s, 10m, 2h. Without it, watch until you press Ctrl+C.")
    private Duration runFor;

    @Option(names = "--color", defaultValue = "auto", paramLabel = "WHEN",
            description = "Colorize alerts: auto, always or never (default: ${DEFAULT-VALUE}).")
    private String color;

    @Option(names = "--no-color", description = "Same as --color never.")
    private boolean noColor;

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
        boolean useColor;
        try {
            useColor = ColorSupport.shouldColor(color, noColor);
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            return 2;
        }

        Map<String, Integer> overrides = ruleThresholds == null ? Map.of() : ruleThresholds;
        Set<String> skip = skipped == null ? Set.of() : new LinkedHashSet<>(skipped);
        RuleEngine engine;
        try {
            engine = RuleCatalog.buildEngine(threshold, overrides, skip, window);
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            return 2;
        }

        Ansi ansi = new Ansi(useColor);
        try {
            LogTailer tailer = new LogTailer(logFile, fromStart);
            LiveWatcher watcher = new LiveWatcher(tailer, new LiveMonitor(year, engine, window),
                    alert -> {
                        System.out.println(AlertFormatter.format(alert, ansi));
                        System.out.flush();
                    },
                    interval);

            // Status messages go to stderr so that stdout carries only alerts and can be piped.
            System.err.printf("Watching %s with rules: %s%s%n", logFile,
                    String.join(", ", engine.ruleNames()),
                    runFor == null ? ". Press Ctrl+C to stop." : " for " + DurationConverter.format(runFor) + ".");
            watcher.run(runFor);
            System.err.printf("Stopped. %d alert%s raised.%n",
                    watcher.alertCount(), watcher.alertCount() == 1 ? "" : "s");
            return 0;
        } catch (IOException e) {
            System.err.println("error: could not read " + logFile + ": " + e.getMessage());
            return 1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return 130;
        }
    }
}