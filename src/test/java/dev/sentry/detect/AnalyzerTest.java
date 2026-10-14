package dev.sentry.detect;

import dev.sentry.model.EventType;
import dev.sentry.model.LogEvent;
import dev.sentry.parser.LogParser;
import dev.sentry.tools.SampleLogGenerator;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AnalyzerTest {

    private static final Duration WINDOW = Duration.ofMinutes(10);

    @Test
    void ranksSampleLogFindingsMostSeriousFirst() {
        List<LogEvent> events = new LogParser(2026).parseLines(new SampleLogGenerator(2026, 42).generate()).events();
        List<Finding> findings = Analyzer.analyze(events, 5, WINDOW);

        assertEquals(List.of("success-after-failures", "brute-force", "brute-force", "invalid-user", "brute-force"),
                findings.stream().map(Finding::rule).toList());
        assertEquals(List.of("192.0.2.44", "203.0.113.5", "203.0.113.9", "203.0.113.9", "192.0.2.44"),
                findings.stream().map(Finding::ip).toList());
        assertEquals(List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.MEDIUM, Severity.MEDIUM),
                findings.stream().map(Finding::severity).toList());
    }

    @Test
    void ordinaryActivityProducesNoFindings() {
        LocalDateTime t = LocalDateTime.of(2026, 10, 5, 9, 0, 0);
        List<LogEvent> events = List.of(
                new LogEvent(t, EventType.ACCEPTED_LOGIN, "publickey", "alice", false, "198.51.100.7", 22),
                new LogEvent(t.plusSeconds(100), EventType.FAILED_LOGIN, "password", "alice", false, "198.51.100.7", 22),
                new LogEvent(t.plusSeconds(110), EventType.ACCEPTED_LOGIN, "password", "alice", false, "198.51.100.7", 22));
        assertTrue(Analyzer.analyze(events, 5, WINDOW).isEmpty());
    }
}