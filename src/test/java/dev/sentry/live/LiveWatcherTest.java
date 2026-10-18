package dev.sentry.live;

import dev.sentry.detect.RuleCatalog;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class LiveWatcherTest {

    private static final Duration WINDOW = Duration.ofMinutes(10);
    private static final String ATTACK =
            "Oct  5 01:00:00 web01 sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2\n"
          + "Oct  5 01:00:01 web01 sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2\n"
          + "Oct  5 01:00:02 web01 sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2\n";

    private static LiveWatcher watcher(Path file, List<Alert> seen) throws Exception {
        LiveMonitor monitor = new LiveMonitor(2026,
                RuleCatalog.buildEngine(3, Map.of(), Set.of(), WINDOW), WINDOW);
        return new LiveWatcher(new LogTailer(file, false), monitor, seen::add, Duration.ofMillis(50));
    }

    @Test
    void raisesAnAlertWhenNewLinesCompleteAnAttack(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("w.log");
        Files.write(file, new byte[0]);
        List<Alert> seen = new ArrayList<>();
        LiveWatcher watcher = watcher(file, seen);

        assertTrue(watcher.pollOnce().isEmpty());
        Files.write(file, ATTACK.getBytes(StandardCharsets.UTF_8), StandardOpenOption.APPEND);

        assertEquals(1, watcher.pollOnce().size());
        assertEquals(1, seen.size());
        assertEquals(1, watcher.alertCount());
        assertTrue(watcher.pollOnce().isEmpty()); // nothing new, nothing repeated
    }

    @Test
    void runStopsAfterTheRequestedTime(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("w.log");
        Files.write(file, new byte[0]);
        LiveWatcher watcher = watcher(file, new ArrayList<>());

        long start = System.nanoTime();
        watcher.run(Duration.ofMillis(300));
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;

        assertTrue(elapsedMs >= 250, "stopped too early: " + elapsedMs);
        assertTrue(elapsedMs < 5000, "ran too long: " + elapsedMs);
    }
}