package dev.sentry.tools;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.TextStyle;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;

/**
 * Generates a fake, realistic-looking sshd auth.log for demos and tests.
 *
 * Only reserved documentation IP ranges are used (RFC 5737), so no real addresses
 * ever appear. The same seed always produces the same log. The seed only affects
 * ports and process ids, so the scenarios below are identical for every seed:
 *
 * <ul>
 *   <li>normal logins by alice, bob and carol, plus alice mistyping her password twice</li>
 *   <li>12 failed root logins from 203.0.113.5, one per second (brute force)</li>
 *   <li>8 guessed usernames from 203.0.113.9 (username spray)</li>
 *   <li>7 failed logins then a success for "deploy" from 192.0.2.44</li>
 *   <li>unrelated noise lines (cron, systemd-logind)</li>
 * </ul>
 */
public class SampleLogGenerator {

    private static final String HOST = "web01";
    private static final String[] SPRAY_USERS =
            {"admin", "test", "oracle", "postgres", "ubuntu", "guest", "user", "ftp"};

    private record Entry(LocalDateTime time, String text) { }

    private final int year;
    private final long seed;
    private Random random;
    private final List<Entry> entries = new ArrayList<>();

    public SampleLogGenerator(int year, long seed) {
        this.year = year;
        this.seed = seed;
    }

    /** Build the log, oldest line first. */
    public List<String> generate() {
        random = new Random(seed);
        entries.clear();
        LocalDate day = LocalDate.of(year, 10, 5);

        // Normal activity
        accepted(at(day, 8, 2, 11), "publickey", "alice", "198.51.100.7");
        accepted(at(day, 8, 15, 40), "password", "bob", "198.51.100.8");
        accepted(at(day, 9, 30, 5), "publickey", "alice", "198.51.100.7");
        accepted(at(day, 10, 11, 59), "publickey", "carol", "198.51.100.9");
        accepted(at(day, 13, 45, 22), "password", "bob", "198.51.100.8");
        failed(at(day, 17, 57, 50), "alice", false, "198.51.100.7");   // typo
        failed(at(day, 17, 57, 55), "alice", false, "198.51.100.7");   // typo
        accepted(at(day, 17, 58, 3), "password", "alice", "198.51.100.7");

        // Noise sshd analysis should ignore
        other(at(day, 8, 0, 1), "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)");
        other(at(day, 8, 2, 12), "systemd-logind", "New session 4 of user alice.");
        other(at(day, 9, 0, 1), "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)");
        other(at(day, 10, 0, 1), "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)");

        // Brute force: one IP hammering root
        for (int i = 0; i < 12; i++) {
            failed(at(day, 2, 14, i), "root", false, "203.0.113.5");
        }

        // Username spray: one IP guessing accounts that do not exist
        for (int i = 0; i < SPRAY_USERS.length; i++) {
            failed(at(day, 3, 40, i * 3), SPRAY_USERS[i], true, "203.0.113.9");
        }

        // Success after many failures: possible compromise
        for (int i = 0; i < 7; i++) {
            failed(at(day, 22, 30, i * 2), "deploy", false, "192.0.2.44");
        }
        accepted(at(day, 22, 30, 16), "password", "deploy", "192.0.2.44");

        entries.sort((a, b) -> a.time().compareTo(b.time())); // stable: keeps insertion order within a second
        return entries.stream().map(e -> stamp(e.time()) + " " + HOST + " " + e.text()).toList();
    }

    private LocalDateTime at(LocalDate day, int hour, int minute, int second) {
        // plusMinutes/plusSeconds normalise any overflow
        return day.atStartOfDay().plusHours(hour).plusMinutes(minute).plusSeconds(second);
    }

    private void accepted(LocalDateTime t, String method, String user, String ip) {
        add(t, sshd() + "Accepted " + method + " for " + user + " from " + ip + " port " + port() + " ssh2");
    }

    private void failed(LocalDateTime t, String user, boolean invalid, String ip) {
        if (invalid) {
            // Real sshd logs a separate "Invalid user" line first
            add(t, sshd() + "Invalid user " + user + " from " + ip + " port " + port());
        }
        add(t, sshd() + "Failed password for " + (invalid ? "invalid user " : "") + user
                + " from " + ip + " port " + port() + " ssh2");
    }

    private void other(LocalDateTime t, String program, String message) {
        add(t, program + "[" + (100 + random.nextInt(900)) + "]: " + message);
    }

    private void add(LocalDateTime t, String text) {
        entries.add(new Entry(t, text));
    }

    private String sshd() {
        return "sshd[" + (1000 + random.nextInt(9000)) + "]: ";
    }

    private int port() {
        return 1024 + random.nextInt(60000);
    }

    private static final DateTimeFormatter CLOCK = DateTimeFormatter.ofPattern("HH:mm:ss");

    /** Classic syslog stamp: month abbreviation, space-padded day, time. */
    private static String stamp(LocalDateTime t) {
        return String.format(Locale.ENGLISH, "%s %2d %s",
                t.getMonth().getDisplayName(TextStyle.SHORT, Locale.ENGLISH),
                t.getDayOfMonth(),
                t.format(CLOCK));
    }
}