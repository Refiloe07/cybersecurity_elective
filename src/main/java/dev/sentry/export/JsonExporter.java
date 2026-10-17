package dev.sentry.export;

import dev.sentry.detect.Finding;
import dev.sentry.detect.Severity;
import dev.sentry.report.ReportRenderer.OffenderRow;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Writes an {@link AnalysisReport} as JSON. Timestamps are ISO-8601 local times
 * exactly as the server logged them; syslog carries no time zone.
 */
public final class JsonExporter {

    public static final String VERSION = "0.1.0";

    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");

    private JsonExporter() {
    }

    public static String toJson(AnalysisReport report) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("tool", "sentry");
        root.put("version", VERSION);
        root.put("file", report.file());

        Map<String, Object> settings = new LinkedHashMap<>();
        settings.put("threshold", report.threshold());
        settings.put("window", report.window());
        settings.put("year", report.year());
        root.put("settings", settings);

        List<Object> rules = new ArrayList<>();
        for (Map.Entry<String, Integer> rule : report.ruleThresholds().entrySet()) {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("name", rule.getKey());
            r.put("threshold", rule.getValue());
            rules.add(r);
        }
        root.put("rules", rules);

        Map<String, Object> bySeverity = new LinkedHashMap<>();
        Severity[] all = Severity.values();
        for (int i = all.length - 1; i >= 0; i--) { // most serious first, zeros included
            Severity s = all[i];
            bySeverity.put(s.name(), report.findings().stream().filter(f -> f.severity() == s).count());
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("lines", report.totalLines());
        summary.put("events", report.events());
        summary.put("failed", report.failed());
        summary.put("accepted", report.accepted());
        summary.put("skipped", report.skippedLines());
        summary.put("findings", report.findings().size());
        summary.put("ips", report.findings().stream().map(Finding::ip).distinct().count());
        summary.put("bySeverity", bySeverity);
        root.put("summary", summary);

        List<Object> findings = new ArrayList<>();
        for (Finding f : report.findings()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("severity", f.severity());
            m.put("rule", f.rule());
            m.put("ip", f.ip());
            m.put("firstSeen", time(f.firstSeen()));
            m.put("lastSeen", time(f.lastSeen()));
            m.put("eventCount", f.eventCount());
            m.put("description", f.description());
            findings.add(m);
        }
        root.put("findings", findings);

        List<Object> offenders = new ArrayList<>();
        for (OffenderRow o : report.offenders()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ip", o.ip());
            m.put("failed", o.failed());
            m.put("accepted", o.accepted());
            m.put("findings", o.findings());
            m.put("worst", o.worst());
            offenders.add(m);
        }
        root.put("topOffenders", offenders);

        return JsonWriter.toJson(root) + "\n";
    }

    private static String time(LocalDateTime t) {
        return t.format(ISO);
    }
}