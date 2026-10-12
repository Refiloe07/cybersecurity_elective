package dev.sentry.tools;

import dev.sentry.model.EventType;
import dev.sentry.model.LogEvent;
import dev.sentry.parser.LogParser;
import dev.sentry.parser.ParseResult;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SampleLogGeneratorTest {

    private final List<String> lines = new SampleLogGenerator(2026, 42).generate();
    private final ParseResult result = new LogParser(2026).parseLines(lines);

    private long count(java.util.function.Predicate<LogEvent> filter) {
        return result.events().stream().filter(filter).count();
    }

    @Test
    void sameSeedGivesSameLog() {
        assertEquals(lines, new SampleLogGenerator(2026, 42).generate());
    }

    @Test
    void differentSeedChangesPortsButNotScenarios() {
        List<String> other = new SampleLogGenerator(2026, 7).generate();
        assertNotEquals(lines, other);
        assertEquals(lines.size(), other.size());
    }

    @Test
    void parsesExpectedTotals() {
        assertEquals(48, result.totalLines());
        assertEquals(36, result.events().size());
        assertEquals(12, result.skippedLines());
        assertEquals(29, count(e -> e.type() == EventType.FAILED_LOGIN));
        assertEquals(7, count(e -> e.type() == EventType.ACCEPTED_LOGIN));
    }

    @Test
    void containsBruteForceBurst() {
        assertEquals(12, count(e -> e.ip().equals("203.0.113.5")
                && e.type() == EventType.FAILED_LOGIN && e.user().equals("root")));
    }

    @Test
    void containsUsernameSpray() {
        assertEquals(8, count(e -> e.invalidUser() && e.ip().equals("203.0.113.9")));
        assertEquals(8, count(LogEvent::invalidUser));
    }

    @Test
    void containsSuccessAfterFailures() {
        List<LogEvent> deploy = result.events().stream()
                .filter(e -> e.ip().equals("192.0.2.44")).toList();
        assertEquals(8, deploy.size());
        assertEquals(EventType.ACCEPTED_LOGIN, deploy.get(deploy.size() - 1).type());
        assertEquals(7, deploy.stream().filter(e -> e.type() == EventType.FAILED_LOGIN).count());
    }

    @Test
    void linesAreInChronologicalOrder() {
        for (int i = 1; i < result.events().size(); i++) {
            assertFalse(result.events().get(i).timestamp()
                    .isBefore(result.events().get(i - 1).timestamp()));
        }
    }

    @Test
    void onlyUsesDocumentationIpRanges() {
        for (LogEvent e : result.events()) {
            assertTrue(e.ip().startsWith("203.0.113.") || e.ip().startsWith("198.51.100.")
                    || e.ip().startsWith("192.0.2."), "unexpected IP: " + e.ip());
        }
    }
}