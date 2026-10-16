package dev.sentry.report;

import dev.sentry.detect.Finding;
import dev.sentry.detect.RuleCatalog;
import dev.sentry.detect.Severity;
import dev.sentry.model.EventType;
import dev.sentry.model.LogEvent;
import dev.sentry.parser.LogParser;
import dev.sentry.report.ReportRenderer.OffenderRow;
import dev.sentry.tools.SampleLogGenerator;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ReportRendererTest {

    private static final Ansi OFF = new Ansi(false);
    private static final Ansi ON = new Ansi(true);

    private final List<LogEvent> events =
            new LogParser(2026).parseLines(new SampleLogGenerator(2026, 42).generate()).events();
    private final List<Finding> findings =
            RuleCatalog.buildEngine(5, Map.of(), Set.of(), Duration.ofMinutes(10)).run(events);

    private String plain() {
        return ReportRenderer.render(events, findings, 5, true, OFF);
    }

    private static String stripAnsi(String s) {
        return s.replaceAll("\u001B\\[[0-9;]*m", "");
    }

    @Test
    void summaryCountsEachSeverity() {
        assertTrue(plain().contains("Findings: 5 (1 CRITICAL, 1 HIGH, 3 MEDIUM) across 3 IPs"));
    }

    @Test
    void summaryUsesSingularForOneIp() {
        String out = ReportRenderer.render(events, List.of(findings.get(0)), 5, false, OFF);
        assertTrue(out.contains("Findings: 1 (1 CRITICAL) across 1 IP\n"));
    }

    @Test
    void findingsKeepTheirRankOrder() {
        String out = plain();
        assertTrue(out.contains("[CRITICAL] 192.0.2.44"));
        assertTrue(out.contains("[HIGH    ] 203.0.113.5"));
        assertTrue(out.indexOf("[CRITICAL]") < out.indexOf("[HIGH    ]"));
        assertTrue(out.indexOf("[HIGH    ]") < out.indexOf("[MEDIUM  ]"));
    }

    @Test
    void offendersAreRankedBySeverityThenFailures() {
        List<OffenderRow> rows = ReportRenderer.topOffenders(events, findings, 10);
        assertEquals(List.of(
                new OffenderRow("192.0.2.44", 7, 1, 2, Severity.CRITICAL),
                new OffenderRow("203.0.113.5", 12, 0, 1, Severity.HIGH),
                new OffenderRow("203.0.113.9", 8, 0, 2, Severity.MEDIUM)), rows);
    }

    @Test
    void offenderListRespectsTheLimit() {
        assertEquals(2, ReportRenderer.topOffenders(events, findings, 2).size());
        assertTrue(ReportRenderer.topOffenders(events, List.of(), 5).isEmpty());
    }

    @Test
    void tableShowsCountsAndWorstSeverity() {
        String out = plain();
        assertTrue(out.contains("Top offending IPs\n"));
        assertTrue(out.contains("  192.0.2.44            7         1         2  CRITICAL"));
        assertTrue(out.contains("  203.0.113.5          12         0         1  HIGH"));
    }

    @Test
    void tableCanBeHiddenAndAnnouncesTruncation() {
        assertFalse(ReportRenderer.render(events, findings, 0, true, OFF).contains("Top offending IPs"));
        assertTrue(ReportRenderer.render(events, findings, 2, true, OFF)
                .contains("Top offending IPs (top 2 of 3)"));
    }

    @Test
    void groupsFailuresByHour() {
        Map<LocalDateTime, Long> hours = ReportRenderer.failuresByHour(events);
        assertEquals(List.of(
                LocalDateTime.of(2026, 10, 5, 2, 0), LocalDateTime.of(2026, 10, 5, 3, 0),
                LocalDateTime.of(2026, 10, 5, 17, 0), LocalDateTime.of(2026, 10, 5, 22, 0)),
                new ArrayList<>(hours.keySet()));
        assertEquals(List.of(12L, 8L, 2L, 7L), new ArrayList<>(hours.values()));
    }

    @Test
    void timelineBarsScaleToTheBusiestHour() {
        String out = plain();
        assertTrue(out.contains("Failed logins by hour\n"));
        assertTrue(out.contains("  2026-10-05 02:00  " + "#".repeat(30) + " 12"));
        assertTrue(out.contains("  2026-10-05 03:00  " + "#".repeat(20) + " ".repeat(10) + "  8"));
        assertTrue(out.contains("  2026-10-05 17:00  " + "#".repeat(5) + " ".repeat(25) + "  2"));
    }

    @Test
    void timelineCanBeHidden() {
        assertFalse(ReportRenderer.render(events, findings, 5, false, OFF).contains("Failed logins by hour"));
    }

    @Test
    void longTimelineShowsOnlyTheBusiestHours() {
        List<LogEvent> many = new ArrayList<>();
        for (int hour = 0; hour < 30; hour++) {
            for (int n = 0; n <= hour; n++) { // later hours are busier
                many.add(new LogEvent(LocalDateTime.of(2026, 10, 1, 0, 0).plusHours(hour).plusSeconds(n),
                        EventType.FAILED_LOGIN, "password", "root", false, "1.1.1.1", 22));
            }
        }
        String out = ReportRenderer.render(many, List.of(), 5, true, OFF);
        assertTrue(out.contains("Failed logins by hour (24 busiest of 30)"));
        assertEquals(24, out.lines().filter(l -> l.startsWith("  2026-")).count());
        assertTrue(out.contains("2026-10-02 05:00"));  // the busiest hour is kept
        assertFalse(out.contains("2026-10-01 00:00")); // the quietest is dropped
        assertTrue(out.indexOf("2026-10-01 06:00") < out.indexOf("2026-10-02 05:00")); // still in time order
    }

    @Test
    void quietLogSaysSoButStillShowsTheTimeline() {
        String out = ReportRenderer.render(events, List.of(), 5, true, OFF);
        assertTrue(out.contains("No suspicious activity detected."));
        assertFalse(out.contains("Top offending"));
        assertTrue(out.contains("Failed logins by hour"));
    }

    @Test
    void emptyInputGivesJustTheQuietMessage() {
        assertEquals("No suspicious activity detected.\n", ReportRenderer.render(List.of(), List.of(), 5, true, OFF));
    }

    @Test
    void colorOnlyAddsEscapeCodes() {
        String colored = ReportRenderer.render(events, findings, 5, true, ON);
        assertTrue(colored.contains("\u001B[1;97;41m[CRITICAL]\u001B[0m"));
        assertEquals(plain(), stripAnsi(colored));
    }

    @Test
    void plainOutputHasNoEscapeCodesOrCarriageReturns() {
        assertFalse(plain().contains("\u001B"));
        assertFalse(plain().contains("\r"));
    }
}