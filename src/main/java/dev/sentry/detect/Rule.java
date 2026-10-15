package dev.sentry.detect;

import dev.sentry.model.LogEvent;

import java.util.List;

/**
 * One detection rule. To add a new rule: write a class that implements this
 * interface, then add one line for it in {@link RuleCatalog}.
 */
public interface Rule {

    /** Short stable id used in the output and on the command line, e.g. "brute-force". */
    String name();

    /** One plain-English sentence describing what the rule looks for. */
    String description();

    /** Look through the events and return anything suspicious. */
    List<Finding> detect(List<LogEvent> events);
}