package dev.sentry.report;

import dev.sentry.detect.Finding;
import dev.sentry.detect.Severity;
import dev.sentry.model.EventType;
import dev.sentry.model.LogEvent;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Turns events and findings into the text shown in the terminal: a summary line,
 * the ranked findings, a table of the most suspicious IPs, and a chart of failed
 * logins by hour. Pure text in, text out, so it is easy to test.
 */
public final class ReportRenderer {

    static final int BAR_WIDTH = 30;
    static final int MAX_TIMELINE_ROWS = 24;

    private static final DateTimeFormatter SHOWN_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter HOUR_LABEL = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:00");

    private ReportRenderer() {
    }

    /** One row of the "top offending IPs" table. */
    public record OffenderRow(String ip, int failed, int accepted, int findings, Severity worst) {
    }

    /**
     * @param topIps       how many IPs to list in the table (0 hides it)
     * @param showTimeline whether to draw the failed-logins-by-hour chart
     */
    public static String render(List<LogEvent> events, List<Finding> findings,
                                int topIps, boolean showTimeline, Ansi ansi) {
        StringBuilder out = new StringBuilder();

        if (findings.isEmpty()) {
            out.append("No suspicious activity detected.\n");
        } else {
            appendSummary(out, findings, ansi);
            for (Finding f : findings) {
                out.append(String.format("  %s %-15s %s: %s (%s to %s)\n",
                        ansi.severity(f.severity(), String.format("[%-8s]", f.severity())),
                        f.ip(), f.rule(), f.description(),
                        f.firstSeen().format(SHOWN_TIME), f.lastSeen().format(SHOWN_TIME)));
            }
            if (topIps > 0) {
                appendOffenders(out, events, findings, topIps, ansi);
            }
        }

        if (showTimeline) {
            appendTimeline(out, events, ansi);
        }
        return out.toString();
    }

    // ---- summary -------------------------------------------------------------

    private static void appendSummary(StringBuilder out, List<Finding> findings, Ansi ansi) {
        Map<Severity, Integer> counts = new EnumMap<>(Severity.class);
        for (Finding f : findings) {
            counts.merge(f.severity(), 1, Integer::sum);
        }
        List<String> parts = new ArrayList<>();
        Severity[] bySeriousness = Severity.values();
        for (int i = bySeriousness.length - 1; i >= 0; i--) {
            Severity s = bySeriousness[i];
            if (counts.containsKey(s)) {
                parts.add(ansi.severity(s, counts.get(s) + " " + s));
            }
        }
        long ips = findings.stream().map(Finding::ip).distinct().count();
        out.append(String.format("Findings: %d (%s) across %d %s\n",
                findings.size(), String.join(", ", parts), ips, ips == 1 ? "IP" : "IPs"));
    }

    // ---- top offending IPs -----------------------------------------------------

    /** IPs with at least one finding, most serious first, then most failed logins. */
    public static List<OffenderRow> topOffenders(List<LogEvent> events, List<Finding> findings, int limit) {
        Map<String, Integer> failed = new HashMap<>();
        Map<String, Integer> accepted = new HashMap<>();
        for (LogEvent e : events) {
            (e.type() == EventType.FAILED_LOGIN ? failed : accepted).merge(e.ip(), 1, Integer::sum);
        }

        Map<String, List<Finding>> byIp = findings.stream()
                .collect(Collectors.groupingBy(Finding::ip));

        List<OffenderRow> rows = new ArrayList<>();
        for (Map.Entry<String, List<Finding>> entry : byIp.entrySet()) {
            String ip = entry.getKey();
            Severity worst = entry.getValue().stream()
                    .map(Finding::severity).max(Comparator.naturalOrder()).orElseThrow();
            rows.add(new OffenderRow(ip, failed.getOrDefault(ip, 0), accepted.getOrDefault(ip, 0),
                    entry.getValue().size(), worst));
        }

        rows.sort(Comparator.comparing(OffenderRow::worst).reversed()
                .thenComparing(Comparator.comparingInt(OffenderRow::failed).reversed())
                .thenComparing(OffenderRow::ip));
        return rows.size() > limit ? List.copyOf(rows.subList(0, limit)) : List.copyOf(rows);
    }

    private static void appendOffenders(StringBuilder out, List<LogEvent> events,
                                        List<Finding> findings, int limit, Ansi ansi) {
        int total = (int) findings.stream().map(Finding::ip).distinct().count();
        List<OffenderRow> rows = topOffenders(events, findings, limit);

        out.append('\n');
        out.append(ansi.bold(total > rows.size()
                ? String.format("Top offending IPs (top %d of %d)", rows.size(), total)
                : "Top offending IPs")).append('\n');
        out.append(ansi.dim(String.format("  %-15s %7s %9s %9s  %s",
                "IP", "Failed", "Accepted", "Findings", "Worst"))).append('\n');
        for (OffenderRow r : rows) {
            out.append(String.format("  %-15s %7d %9d %9d  %s\n",
                    r.ip(), r.failed(), r.accepted(), r.findings(),
                    ansi.severity(r.worst(), r.worst().name())));
        }
    }

    // ---- timeline --------------------------------------------------------------

    /** Failed logins per hour, oldest hour first; hours without failures are left out. */
    public static Map<LocalDateTime, Long> failuresByHour(List<LogEvent> events) {
        return events.stream()
                .filter(e -> e.type() == EventType.FAILED_LOGIN)
                .collect(Collectors.groupingBy(e -> e.timestamp().truncatedTo(ChronoUnit.HOURS),
                        TreeMap::new, Collectors.counting()));
    }

    private static void appendTimeline(StringBuilder out, List<LogEvent> events, Ansi ansi) {
        Map<LocalDateTime, Long> hours = failuresByHour(events);
        if (hours.isEmpty()) {
            return;
        }

        boolean trimmed = hours.size() > MAX_TIMELINE_ROWS;
        Map<LocalDateTime, Long> shown = trimmed ? busiest(hours) : hours;

        long max = shown.values().stream().mapToLong(Long::longValue).max().orElse(1);
        int digits = String.valueOf(max).length();

        out.append('\n');
        out.append(ansi.bold(trimmed
                ? String.format("Failed logins by hour (%d busiest of %d)", shown.size(), hours.size())
                : "Failed logins by hour")).append('\n');
        for (Map.Entry<LocalDateTime, Long> en : shown.entrySet()) {
            int width = (int) Math.max(1, Math.round(en.getValue() * (double) BAR_WIDTH / max));
            out.append(String.format("  %s  %s %" + digits + "d\n",
                    en.getKey().format(HOUR_LABEL),
                    ansi.severity(Severity.MEDIUM, "#".repeat(width) + " ".repeat(BAR_WIDTH - width)),
                    en.getValue()));
        }
    }

    private static Map<LocalDateTime, Long> busiest(Map<LocalDateTime, Long> hours) {
        Map<LocalDateTime, Long> top = new TreeMap<>();
        hours.entrySet().stream()
                .sorted(Map.Entry.<LocalDateTime, Long>comparingByValue().reversed()
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(MAX_TIMELINE_ROWS)
                .forEach(en -> top.put(en.getKey(), en.getValue()));
        return top;
    }
}