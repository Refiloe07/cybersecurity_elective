package dev.sentry.detect;

import dev.sentry.model.LogEvent;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Runs every detection rule and returns one ranked list: most serious first, then
 * biggest, then earliest. (Day 6 replaces the hard-coded list with a rule engine.)
 */
public final class Analyzer {

    private Analyzer() {
    }

    public static List<Finding> analyze(List<LogEvent> events, int threshold, Duration window) {
        List<Finding> all = new ArrayList<>();
        all.addAll(new BruteForceDetector(threshold, window).detect(events));
        all.addAll(new InvalidUserDetector(threshold, window).detect(events));
        all.addAll(new SuccessAfterFailuresDetector(threshold, window).detect(events));

        all.sort(Comparator.comparing(Finding::severity).reversed()
                .thenComparing(Comparator.comparingInt(Finding::eventCount).reversed())
                .thenComparing(Finding::firstSeen)); // stable: rule order breaks exact ties
        return all;
    }
}