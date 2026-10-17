package dev.sentry.export;

import dev.sentry.detect.Finding;
import dev.sentry.report.ReportRenderer.OffenderRow;

import java.util.List;
import java.util.Map;

/**
 * Everything one analysis produced, in a form the exporters can write out.
 *
 * @param file           the log that was analyzed, as given on the command line
 * @param ruleThresholds the rules that ran, in order, with the threshold each used
 * @param offenders      every IP that has at least one finding, most serious first
 */
public record AnalysisReport(
        String file,
        int totalLines,
        int events,
        long failed,
        long accepted,
        int skippedLines,
        int threshold,
        String window,
        int year,
        Map<String, Integer> ruleThresholds,
        List<Finding> findings,
        List<OffenderRow> offenders) {
}