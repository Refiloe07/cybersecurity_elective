package dev.sentry.cli;

import dev.sentry.detect.Finding;
import dev.sentry.detect.RuleCatalog;
import dev.sentry.detect.RuleEngine;
import dev.sentry.model.EventType;
import dev.sentry.parser.LogParser;
import dev.sentry.parser.ParseResult;
import dev.sentry.report.Ansi;
import dev.sentry.report.ColorSupport;
import dev.sentry.report.ReportRenderer;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Year;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

@Command(
    name = "analyze",
    mixinStandardHelpOptions = true,
    description = "Analyze an auth log file and report suspicious activity."
)
public class AnalyzeCommand implements Callable<Integer> {

    @Parameters(index = "0", paramLabel = "LOGFILE", description = "Path to the auth log to analyze.")
    private Path logFile;

    @Option(names = {"-t", "--threshold"}, defaultValue = "5",
            description = "Default threshold for every rule: how many failed logins or guessed usernames "
                    + "from one IP raise a finding (default: ${DEFAULT-VALUE}).")
    private int threshold;

    @Option(names = {"-T", "--rule-threshold"}, split = ",", paramLabel = "RULE=N",
            description = "Override the threshold for one rule, e.g. brute-force=10. "
                    + "Repeatable or comma-separated. See 'sentry rules'.")
    private Map<String, Integer> ruleThresholds;

    @Option(names = {"-s", "--skip"}, split = ",", paramLabel = "RULE",
            description = "Do not run this rule. Repeatable or comma-separated. See 'sentry rules'.")
    private List<String> skipped;

    @Option(names = {"-w", "--window"}, defaultValue = "10m", converter = DurationConverter.class,
            description = "Time window the thresholds apply to, e.g. 30s, 10m, 2h, 1d (default: ${DEFAULT-VALUE}).")
    private Duration window;

    @Option(names = "--color", defaultValue = "auto", paramLabel = "WHEN",
            description = "Colorize output: auto, always or never (default: ${DEFAULT-VALUE}). "
                    + "'auto' colors only on a real terminal that supports it, and honors NO_COLOR.")
    private String color;

    @Option(names = "--no-color", description = "Same as --color never.")
    private boolean noColor;

    @Option(names = "--top", defaultValue = "5", paramLabel = "N",
            description = "List the N most suspicious IPs in a summary table; 0 hides it (default: ${DEFAULT-VALUE}).")
    private int top;

    @Option(names = "--no-timeline", description = "Hide the failed-logins-by-hour chart.")
    private boolean noTimeline;

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
        if (top < 0) {
            System.err.println("error: --top must be 0 or more");
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

        try {
            ParseResult result = new LogParser(year).parseFile(logFile);
            long failed = result.events().stream()
                    .filter(e -> e.type() == EventType.FAILED_LOGIN).count();
            long accepted = result.events().size() - failed;

            String ruleSummary = engine.ruleNames().stream()
                    .map(name -> name + "=" + overrides.getOrDefault(name, threshold))
                    .collect(Collectors.joining(", "));

            System.out.printf("Read %d lines from %s%n", result.totalLines(), logFile);
            System.out.printf("Parsed %d SSH events (%d failed, %d accepted); skipped %d other lines%n",
                    result.events().size(), failed, accepted, result.skippedLines());
            System.out.printf("Settings: threshold=%d, window=%s, year=%d%n",
                    threshold, DurationConverter.format(window), year);
            System.out.printf("Rules: %s%n", ruleSummary.isEmpty() ? "(none)" : ruleSummary);
            System.out.println();

            List<Finding> findings = engine.run(result.events());
            String report = ReportRenderer.render(result.events(), findings, top, !noTimeline, new Ansi(useColor));
            System.out.print(report.replace("\n", System.lineSeparator()));
            return 0;
        } catch (IOException | UncheckedIOException e) {
            System.err.println("error: could not read " + logFile
                    + " (is it a UTF-8 text file?): " + e.getMessage());
            return 1;
        }
    }
}