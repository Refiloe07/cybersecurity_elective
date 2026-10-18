package dev.sentry.live;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/** Ties a {@link LogTailer} to a {@link LiveMonitor} and hands every alert to a callback. */
public final class LiveWatcher {

    private final LogTailer tailer;
    private final LiveMonitor monitor;
    private final Consumer<Alert> onAlert;
    private final Duration interval;
    private int alertCount;

    public LiveWatcher(LogTailer tailer, LiveMonitor monitor, Consumer<Alert> onAlert, Duration interval) {
        this.tailer = tailer;
        this.monitor = monitor;
        this.onAlert = onAlert;
        this.interval = interval;
    }

    /** Reads whatever is new and raises alerts for it. */
    public List<Alert> pollOnce() throws IOException {
        List<Alert> alerts = monitor.accept(tailer.poll());
        for (Alert alert : alerts) {
            onAlert.accept(alert);
        }
        alertCount += alerts.size();
        return alerts;
    }

    public int alertCount() {
        return alertCount;
    }

    /**
     * Keeps polling. Runs forever when {@code runTime} is null, otherwise stops once that
     * much time has passed (after one last poll).
     */
    public void run(Duration runTime) throws IOException, InterruptedException {
        long start = System.nanoTime();
        while (true) {
            pollOnce();
            boolean expired = runTime != null && System.nanoTime() - start >= runTime.toNanos();
            if (expired) {
                return;
            }
            if (tailer.moreAvailable()) {
                continue; // still catching up on a big file; do not sleep
            }
            long sleep = interval.toNanos();
            if (runTime != null) {
                sleep = Math.min(sleep, runTime.toNanos() - (System.nanoTime() - start));
            }
            if (sleep > 0) {
                TimeUnit.NANOSECONDS.sleep(sleep);
            }
        }
    }
}