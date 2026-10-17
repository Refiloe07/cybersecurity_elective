package dev.sentry.export;

import dev.sentry.detect.Finding;
import dev.sentry.detect.RuleCatalog;
import dev.sentry.detect.Severity;
import dev.sentry.model.LogEvent;
import dev.sentry.parser.LogParser;
import dev.sentry.report.ReportRenderer;
import dev.sentry.tools.SampleLogGenerator;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class JsonExporterTest {

    private final List<LogEvent> events =
            new LogParser(2026).parseLines(new SampleLogGenerator(2026, 42).generate()).events();
    private final List<Finding> findings =
            RuleCatalog.buildEngine(5, Map.of(), Set.of(), Duration.ofMinutes(10)).run(events);

    private AnalysisReport reportFor(List<Finding> list) {
        Map<String, Integer> rules = new LinkedHashMap<>();
        for (String name : RuleCatalog.names()) {
            rules.put(name, 5);
        }
        return new AnalysisReport("auth.log", 48, events.size(), 29, 7, 12, 5, "10m", 2026, rules, list,
                ReportRenderer.topOffenders(events, list, Integer.MAX_VALUE));
    }

    /** True if every brace and bracket outside of strings is matched. */
    private static boolean balanced(String json) {
        int depth = 0;
        boolean inString = false;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    inString = false;
                }
            } else if (c == '"') {
                inString = true;
            } else if (c == '{' || c == '[') {
                depth++;
            } else if (c == '}' || c == ']') {
                depth--;
                if (depth < 0) {
                    return false;
                }
            }
        }
        return depth == 0 && !inString;
    }

    @Test
    void containsToolMetadataAndSettings() {
        String json = JsonExporter.toJson(reportFor(findings));
        assertTrue(json.contains("\"tool\": \"sentry\""));
        assertTrue(json.contains("\"version\": \"0.1.0\""));
        assertTrue(json.contains("\"file\": \"auth.log\""));
        assertTrue(json.contains("\"threshold\": 5,"));
        assertTrue(json.contains("\"window\": \"10m\""));
        assertTrue(json.contains("\"year\": 2026"));
    }

    @Test
    void summaryHasCountsAndSeverityBreakdown() {
        String json = JsonExporter.toJson(reportFor(findings));
        assertTrue(json.contains("\"lines\": 48,"));
        assertTrue(json.contains("\"events\": 36,"));
        assertTrue(json.contains("\"failed\": 29,"));
        assertTrue(json.contains("\"accepted\": 7,"));
        assertTrue(json.contains("\"skipped\": 12,"));
        assertTrue(json.contains("\"findings\": 5,"));
        assertTrue(json.contains("\"ips\": 3,"));
        assertTrue(json.contains("\"CRITICAL\": 1,"));
        assertTrue(json.contains("\"HIGH\": 1,"));
        assertTrue(json.contains("\"MEDIUM\": 3,"));
        assertTrue(json.contains("\"LOW\": 0"));
    }

    @Test
    void listsFindingsInRankOrderWithIsoTimes() {
        String json = JsonExporter.toJson(reportFor(findings));
        assertEquals(5, json.lines().filter(l -> l.contains("\"rule\":")).count());
        assertTrue(json.indexOf("\"severity\": \"CRITICAL\"") < json.indexOf("\"severity\": \"HIGH\""));
        assertTrue(json.contains("\"firstSeen\": \"2026-10-05T22:30:00\""));
        assertTrue(json.contains("\"lastSeen\": \"2026-10-05T22:30:16\""));
        assertTrue(json.contains("\"eventCount\": 8,"));
    }

    @Test
    void listsOffendingIps() {
        String json = JsonExporter.toJson(reportFor(findings));
        assertTrue(json.contains("\"topOffenders\": ["));
        assertTrue(json.contains("\"worst\": \"CRITICAL\""));
        assertTrue(json.contains("\"failed\": 12,"));
    }

    @Test
    void noFindingsGivesEmptyArrays() {
        String json = JsonExporter.toJson(reportFor(List.of()));
        assertTrue(json.contains("\"findings\": []"));
        assertTrue(json.contains("\"topOffenders\": []"));
        assertTrue(json.contains("\"findings\": 0,"));
        assertTrue(json.contains("\"CRITICAL\": 0,"));
    }

    @Test
    void outputIsPureAsciiAndEndsWithANewline() {
        String json = JsonExporter.toJson(reportFor(findings));
        assertTrue(json.chars().allMatch(c -> c < 128));
        assertTrue(json.endsWith("}\n"));
        assertTrue(json.startsWith("{\n"));
    }

    @Test
    void bracesAndBracketsAreBalanced() {
        assertTrue(balanced(JsonExporter.toJson(reportFor(findings))));
        assertTrue(balanced(JsonExporter.toJson(reportFor(List.of()))));
    }

    @Test
    void attackerControlledTextIsEscaped() {
        LocalDateTime t = LocalDateTime.of(2026, 10, 5, 12, 0, 0);
        Finding nasty = new Finding("brute-force", Severity.HIGH, "1.2.3.4", t, t, 1,
                "users tried: say \"hi\"\u001B[2J");
        String json = JsonExporter.toJson(reportFor(List.of(nasty)));
        assertTrue(json.contains("say \\\"hi\\\"\\u001b[2J"));
        assertFalse(json.contains("\u001B"));
        assertTrue(balanced(json));
    }
}