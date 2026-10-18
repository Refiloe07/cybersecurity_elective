package dev.sentry.live;

import dev.sentry.detect.RuleCatalog;
import dev.sentry.detect.Severity;
import dev.sentry.tools.SampleLogGenerator;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class LiveMonitorTest {

    private static final Duration WINDOW = Duration.ofMinutes(10);

    private static LiveMonitor monitor(int threshold) {
        return new LiveMonitor(2026, RuleCatalog.buildEngine(threshold, Map.of(), Set.of(), WINDOW), WINDOW);
    }

    private static String fail(String time, String user, String ip) {
        return time + " web01 sshd[1]: Failed password for " + user + " from " + ip + " port 22 ssh2";
    }

    private static String ok(String time, String user, String ip) {
        return time + " web01 sshd[1]: Accepted password for " + user + " from " + ip + " port 22 ssh2";
    }

    private static List<String> sample() {
        return new SampleLogGenerator(2026, 42).generate();
    }

    private static List<String> burst(String prefix, String ip) {
        return List.of(fail(prefix + "0", "root", ip), fail(prefix + "1", "root", ip), fail(prefix + "2", "root", ip));
    }

    @Test
    void wholeLogInOneBatchReportsEveryIncident() {
        List<Alert> alerts = monitor(5).accept(sample());

        assertEquals(List.of("brute-force", "brute-force", "invalid-user", "brute-force", "success-after-failures"),
                alerts.stream().map(a -> a.finding().rule()).toList());
        assertEquals(List.of("203.0.113.5", "203.0.113.9", "203.0.113.9", "192.0.2.44", "192.0.2.44"),
                alerts.stream().map(a -> a.finding().ip()).toList());
        assertTrue(alerts.stream().noneMatch(Alert::escalation));
        List<LocalDateTime> times = alerts.stream().map(a -> a.finding().lastSeen()).toList();
        assertEquals(times.stream().sorted().toList(), times);
    }

    @Test
    void lineByLineAlertsAtTheThresholdAndEscalates() {
        LiveMonitor monitor = monitor(5);
        List<Alert> alerts = new ArrayList<>();
        for (String line : sample()) {
            alerts.addAll(monitor.accept(List.of(line)));
        }

        assertEquals(6, alerts.size());
        assertEquals(Severity.MEDIUM, alerts.get(0).finding().severity());
        assertEquals(LocalDateTime.of(2026, 10, 5, 2, 14, 4), alerts.get(0).finding().lastSeen()); // the 5th failure

        List<Alert> escalations = alerts.stream().filter(Alert::escalation).toList();
        assertEquals(1, escalations.size());
        assertEquals("203.0.113.5", escalations.get(0).finding().ip());
        assertEquals(Severity.HIGH, escalations.get(0).finding().severity());

        Alert last = alerts.get(alerts.size() - 1);
        assertEquals(Severity.CRITICAL, last.finding().severity());
        assertEquals("192.0.2.44", last.finding().ip());
    }

    @Test
    void continuingAttackStaysQuiet() {
        LiveMonitor monitor = monitor(3);
        assertEquals(1, monitor.accept(burst("Oct  5 01:00:0", "9.9.9.9")).size());
        assertEquals(0, monitor.accept(List.of(fail("Oct  5 01:05:00", "root", "9.9.9.9"))).size());
    }

    @Test
    void differentIpAlertsSeparately() {
        LiveMonitor monitor = monitor(3);
        monitor.accept(burst("Oct  5 01:00:0", "9.9.9.9"));
        assertEquals(1, monitor.accept(burst("Oct  5 01:05:0", "8.8.8.8")).size());
    }

    @Test
    void newBurstAfterAQuietPeriodAlertsAgain() {
        LiveMonitor monitor = monitor(3);
        assertEquals(1, monitor.accept(burst("Oct  5 01:00:0", "9.9.9.9")).size());
        assertEquals(1, monitor.accept(burst("Oct  5 03:00:0", "9.9.9.9")).size());
        assertTrue(monitor.bufferedEvents() <= 3); // the old burst has been forgotten
    }

    @Test
    void successAfterFailuresAlertsCriticalOnce() {
        LiveMonitor monitor = monitor(3);
        assertEquals(1, monitor.accept(List.of(
                fail("Oct  5 10:00:00", "a", "6.6.6.6"),
                fail("Oct  5 10:00:01", "b", "6.6.6.6"),
                fail("Oct  5 10:00:02", "c", "6.6.6.6"))).size());

        List<Alert> success = monitor.accept(List.of(ok("Oct  5 10:00:05", "a", "6.6.6.6")));
        assertEquals(1, success.size());
        assertEquals(Severity.CRITICAL, success.get(0).finding().severity());

        assertTrue(monitor.accept(List.of(ok("Oct  5 10:00:09", "a", "6.6.6.6"))).isEmpty());
    }

    @Test
    void yearRolloverIsHandled() {
        List<Alert> alerts = monitor(3).accept(List.of(
                fail("Dec 31 23:59:58", "root", "7.7.7.7"),
                fail("Dec 31 23:59:59", "root", "7.7.7.7"),
                fail("Jan  1 00:00:00", "root", "7.7.7.7")));
        assertEquals(1, alerts.size());
        assertEquals(2026, alerts.get(0).finding().firstSeen().getYear());
        assertEquals(2027, alerts.get(0).finding().lastSeen().getYear());
    }

    @Test
    void garbageAndEmptyInputRaiseNothing() {
        LiveMonitor monitor = monitor(3);
        assertTrue(monitor.accept(List.of("garbage", "", "Oct 5 CRON something")).isEmpty());
        assertTrue(monitor.accept(List.of()).isEmpty());
    }

    @Test
    void longReplayStaysSmallAndStillFindsEarlyAttacks() {
        List<String> lines = new ArrayList<>();
        for (int day = 1; day <= 3; day++) {
            for (int minute = 0; minute < 24 * 60; minute++) {
                lines.add(ok(String.format(Locale.ROOT, "Oct %2d %02d:%02d:00", day, minute / 60, minute % 60),
                        "alice", "198.51.100.7"));
            }
        }
        lines.addAll(burst("Oct  1 05:00:0", "1.2.3.4"));
        lines.addAll(burst("Oct  3 20:00:0", "1.2.3.4"));
        lines.sort(Comparator.comparing((String l) -> l.substring(0, 15)));

        LiveMonitor monitor = monitor(3);
        List<Alert> alerts = monitor.accept(lines);

        assertEquals(2, alerts.stream().filter(a -> a.finding().ip().equals("1.2.3.4")).count());
        assertTrue(monitor.bufferedEvents() < 60);
    }
}