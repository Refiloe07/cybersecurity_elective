package dev.sentry.export;

import dev.sentry.detect.Finding;
import dev.sentry.detect.RuleCatalog;
import dev.sentry.model.LogEvent;
import dev.sentry.parser.LogParser;
import dev.sentry.tools.SampleLogGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class CsvExporterTest {

    @Test
    void plainTextIsLeftAlone() {
        assertEquals("abc", CsvExporter.cell("abc"));
        assertEquals("a=b", CsvExporter.cell("a=b"));
        assertEquals("", CsvExporter.cell(""));
        assertEquals("", CsvExporter.cell(null));
    }

    @Test
    void commasQuotesAndNewlinesAreQuoted() {
        assertEquals("\"a,b\"", CsvExporter.cell("a,b"));
        assertEquals("\"say \"\"hi\"\"\"", CsvExporter.cell("say \"hi\""));
        assertEquals("\"a\nb\"", CsvExporter.cell("a\nb"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"=1+1", "+1", "-1", "@x", "\tx"})
    void formulaStartersGetALeadingApostrophe(String value) {
        assertEquals("'" + value, CsvExporter.cell(value));
    }

    @Test
    void formulaStarterThatAlsoNeedsQuotesGetsBoth() {
        assertEquals("\"'=a,b\"", CsvExporter.cell("=a,b"));
    }

    @Test
    void noFindingsGivesOnlyTheHeader() {
        assertEquals("severity,rule,ip,first_seen,last_seen,event_count,description\r\n",
                CsvExporter.findingsToCsv(List.of()));
    }

    @Test
    void writesOneRowPerFindingWithCrlfLineEnds() {
        List<LogEvent> events = new LogParser(2026).parseLines(new SampleLogGenerator(2026, 42).generate()).events();
        List<Finding> findings = RuleCatalog.buildEngine(5, Map.of(), Set.of(), Duration.ofMinutes(10)).run(events);
        String csv = CsvExporter.findingsToCsv(findings);
        String[] lines = csv.split("\r\n");

        assertEquals(6, lines.length);
        assertEquals(CsvExporter.HEADER, lines[0]);
        assertEquals("CRITICAL,success-after-failures,192.0.2.44,2026-10-05 22:30:00,2026-10-05 22:30:16,8,"
                + "login as 'deploy' succeeded after 7 failed attempts from the same IP", lines[1]);
        assertTrue(csv.contains("\"8 failed logins; users tried: admin, ftp, guest, oracle, postgres +3 more\""));
        assertTrue(csv.endsWith("\r\n"));
    }
}