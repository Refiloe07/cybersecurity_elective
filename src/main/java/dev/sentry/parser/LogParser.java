package dev.sentry.parser;

import dev.sentry.model.EventType;
import dev.sentry.model.LogEvent;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Parses sshd lines from a Linux auth.log into {@link LogEvent}s.
 *
 * Handles lines such as:
 * <pre>
 * Oct 10 17:20:48 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 4242 ssh2
 * Oct 10 17:20:48 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 4242 ssh2
 * Oct 10 17:21:02 web01 sshd[1240]: Accepted password for alice from 198.51.100.7 port 51000 ssh2
 * </pre>
 */
public class LogParser {

    private static final Pattern LINE = Pattern.compile(
            "^(\\w{3})\\s+(\\d{1,2})\\s+(\\d{2}:\\d{2}:\\d{2})\\s+\\S+\\s+sshd(?:\\[\\d+\\])?:\\s+"
          + "(Failed|Accepted)\\s+(\\S+)\\s+for\\s+(invalid user\\s+)?(\\S+)\\s+from\\s+(\\S+)\\s+port\\s+(\\d+)");

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("MMM d HH:mm:ss uuuu", Locale.ENGLISH)
                    .withResolverStyle(ResolverStyle.STRICT);

    private final int year;

    /** @param year syslog lines carry no year, so we assume this one */
    public LogParser(int year) {
        this.year = year;
    }

    /** Parse a single line; empty if it is not an SSH login event we recognise. */
    public Optional<LogEvent> parseLine(String line) {
        if (line == null) {
            return Optional.empty();
        }
        Matcher m = LINE.matcher(line);
        if (!m.find()) {
            return Optional.empty();
        }
        try {
            LocalDateTime time = LocalDateTime.parse(
                    m.group(1) + " " + m.group(2) + " " + m.group(3) + " " + year, TIME_FORMAT);
            EventType type = m.group(4).equals("Failed") ? EventType.FAILED_LOGIN : EventType.ACCEPTED_LOGIN;
            return Optional.of(new LogEvent(
                    time,
                    type,
                    Sanitizer.visible(m.group(5)),
                    Sanitizer.visible(m.group(7)),
                    m.group(6) != null,
                    Sanitizer.visible(m.group(8)),
                    Integer.parseInt(m.group(9))));
        } catch (DateTimeParseException | NumberFormatException e) {
            return Optional.empty(); // e.g. Feb 29 in a non-leap year, absurd port number
        }
    }

    /** Parse every line of a file (UTF-8). */
    public ParseResult parseFile(Path file) throws IOException {
        try (Stream<String> lines = Files.lines(file)) {
            return parseLines(lines.toList());
        }
    }

    /** Parse already-loaded lines. */
    public ParseResult parseLines(List<String> lines) {
        List<LogEvent> events = new ArrayList<>();
        for (String line : lines) {
            parseLine(line).ifPresent(events::add);
        }
        return new ParseResult(events, lines.size(), lines.size() - events.size());
    }
}