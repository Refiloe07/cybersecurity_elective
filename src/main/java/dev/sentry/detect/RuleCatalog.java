package dev.sentry.detect;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The list of every rule sentry knows about, and the one place that builds them.
 * Adding a rule means adding its name to {@link #names()} and a line to
 * {@link #create}; nothing else in the program needs to change.
 */
public final class RuleCatalog {

    private RuleCatalog() {
    }

    /** All rule names, in the order they run. */
    public static List<String> names() {
        return List.of(
                BruteForceDetector.RULE,
                InvalidUserDetector.RULE,
                SuccessAfterFailuresDetector.RULE);
    }

    public static Rule create(String name, int threshold, Duration window) {
        return switch (name) {
            case BruteForceDetector.RULE -> new BruteForceDetector(threshold, window);
            case InvalidUserDetector.RULE -> new InvalidUserDetector(threshold, window);
            case SuccessAfterFailuresDetector.RULE -> new SuccessAfterFailuresDetector(threshold, window);
            default -> throw new IllegalArgumentException(unknownRuleMessage(name));
        };
    }

    /**
     * Builds an engine with every rule except the skipped ones.
     *
     * @param defaultThreshold threshold used by any rule without its own override
     * @param overrides        per-rule thresholds, keyed by rule name
     * @param skipped          names of rules to leave out
     * @throws IllegalArgumentException for unknown rule names or a threshold below 1
     */
    public static RuleEngine buildEngine(int defaultThreshold, Map<String, Integer> overrides,
                                         Set<String> skipped, Duration window) {
        List<String> known = names();
        for (String name : overrides.keySet()) {
            requireKnown(name, known);
        }
        for (String name : skipped) {
            requireKnown(name, known);
        }

        List<Rule> rules = new ArrayList<>();
        for (String name : known) {
            if (skipped.contains(name)) {
                continue;
            }
            int threshold = overrides.getOrDefault(name, defaultThreshold);
            if (threshold < 1) {
                throw new IllegalArgumentException("threshold for " + name + " must be at least 1");
            }
            rules.add(create(name, threshold, window));
        }
        return new RuleEngine(rules);
    }

    private static void requireKnown(String name, List<String> known) {
        if (!known.contains(name)) {
            throw new IllegalArgumentException(unknownRuleMessage(name));
        }
    }

    private static String unknownRuleMessage(String name) {
        return "unknown rule '" + name + "' (known rules: " + String.join(", ", names()) + ")";
    }
}