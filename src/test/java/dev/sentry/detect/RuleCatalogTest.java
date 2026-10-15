package dev.sentry.detect;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class RuleCatalogTest {

    private static final Duration WINDOW = Duration.ofMinutes(10);

    @Test
    void listsRulesInRunOrder() {
        assertEquals(List.of("brute-force", "invalid-user", "success-after-failures"), RuleCatalog.names());
    }

    @Test
    void createsEachRuleByName() {
        for (String name : RuleCatalog.names()) {
            assertEquals(name, RuleCatalog.create(name, 3, WINDOW).name());
        }
    }

    @Test
    void everyRuleHasADescription() {
        for (String name : RuleCatalog.names()) {
            assertFalse(RuleCatalog.create(name, 3, WINDOW).description().isBlank());
        }
    }

    @Test
    void unknownRuleNameIsRejectedWithHelpfulMessage() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> RuleCatalog.create("nope", 3, WINDOW));
        assertTrue(e.getMessage().contains("unknown rule 'nope'"));
        assertTrue(e.getMessage().contains("brute-force"));
    }

    @Test
    void buildEngineRejectsUnknownOverride() {
        assertThrows(IllegalArgumentException.class,
                () -> RuleCatalog.buildEngine(5, Map.of("nope", 1), Set.of(), WINDOW));
    }

    @Test
    void buildEngineRejectsUnknownSkip() {
        assertThrows(IllegalArgumentException.class,
                () -> RuleCatalog.buildEngine(5, Map.of(), Set.of("nope"), WINDOW));
    }

    @Test
    void buildEngineRejectsThresholdBelowOne() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> RuleCatalog.buildEngine(5, Map.of("brute-force", 0), Set.of(), WINDOW));
        assertTrue(e.getMessage().contains("brute-force"));
        assertTrue(e.getMessage().contains("at least 1"));
    }

    @Test
    void badOverrideIsIgnoredWhenThatRuleIsSkipped() {
        RuleEngine engine = RuleCatalog.buildEngine(5, Map.of("brute-force", 0), Set.of("brute-force"), WINDOW);
        assertEquals(2, engine.ruleNames().size());
    }
}