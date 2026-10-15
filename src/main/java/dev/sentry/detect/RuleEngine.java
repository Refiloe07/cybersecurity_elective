package dev.sentry.detect;

import dev.sentry.model.LogEvent;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Runs a set of rules over the events and returns one ranked list of findings:
 * most serious first, then biggest, then earliest. Rules run in the order given,
 * and that order breaks exact ties.
 */
public class RuleEngine {

    private final List<Rule> rules;

    public RuleEngine(List<Rule> rules) {
        this.rules = List.copyOf(rules);
    }

    public List<String> ruleNames() {
        return rules.stream().map(Rule::name).toList();
    }

    public List<Finding> run(List<LogEvent> events) {
        List<Finding> all = new ArrayList<>();
        for (Rule rule : rules) {
            all.addAll(rule.detect(events));
        }
        all.sort(Comparator.comparing(Finding::severity).reversed()
                .thenComparing(Comparator.comparingInt(Finding::eventCount).reversed())
                .thenComparing(Finding::firstSeen)); // stable sort keeps rule order for exact ties
        return all;
    }
}