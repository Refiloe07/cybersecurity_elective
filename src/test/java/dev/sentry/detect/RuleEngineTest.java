package dev.sentry.detect;

import dev.sentry.model.EventType;
import dev.sentry.model.LogEvent;
import dev.sentry.parser.LogParser;
import dev.sentry.tools.SampleLogGenerator;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class RuleEngineTest {

    private static final Duration WINDOW = Duration.ofMinutes(10);

    private final List<LogEvent> sample =
            new LogParser(2026).parseLines(new SampleLogGenerator(2026, 42).generate()).events();

    private static RuleEngine engine(Map<String, Integer> overrides, Set<String> skipped) {
        return RuleCatalog.buildEngine(5, overrides, skipped, WINDOW);
    }

    @Test
    void ranksSampleLogFindingsMostSeriousFirst() {
        List<Finding> findings = engine(Map.of(), Set.of()).run(sample);

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
        assertTrue(engine(Map.of(), Set.of()).run(events).isEmpty());
    }

    @Test
    void skippedRuleProducesNoFindings() {
        RuleEngine engine = engine(Map.of(), Set.of("brute-force"));
        assertEquals(List.of("invalid-user", "success-after-failures"), engine.ruleNames());
        assertEquals(2, engine.run(sample).size());
    }

    @Test
    void perRuleThresholdOverrideChangesTheResult() {
        // deploy had 7 failures before succeeding, so a threshold of 8 no longer flags it
        List<Finding> findings = engine(Map.of("success-after-failures", 8), Set.of()).run(sample);
        assertEquals(4, findings.size());
        assertTrue(findings.stream().noneMatch(f -> f.severity() == Severity.CRITICAL));
    }

    @Test
    void skippingEveryRuleFindsNothing() {
        Set<String> all = new LinkedHashSet<>(RuleCatalog.names());
        assertTrue(engine(Map.of(), all).run(sample).isEmpty());
    }

    @Test
    void emptyEngineFindsNothing() {
        assertTrue(new RuleEngine(List.of()).run(sample).isEmpty());
    }

    @Test
    void customRuleCanBePluggedIn() {
        Rule custom = new Rule() {
            public String name() {
                return "custom";
            }

            public String description() {
                return "demo";
            }

            public List<Finding> detect(List<LogEvent> events) {
                LocalDateTime t = LocalDateTime.of(2026, 1, 1, 0, 0);
                return List.of(new Finding("custom", Severity.LOW, "1.2.3.4", t, t, 1, "hello"));
            }
        };
        RuleEngine engine = new RuleEngine(List.of(new BruteForceDetector(5, WINDOW), custom));

        assertEquals(List.of("brute-force", "custom"), engine.ruleNames());
        List<Finding> findings = engine.run(sample);
        assertEquals("custom", findings.get(findings.size() - 1).rule()); // LOW ranks last
    }
}