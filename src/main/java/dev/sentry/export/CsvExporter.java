package dev.sentry.export;

import dev.sentry.detect.Finding;

import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Writes findings as CSV (RFC 4180: comma separated, CRLF line ends, fields with
 * commas, quotes or line breaks wrapped in quotes).
 *
 * Text cells that start with = + - @ or a tab or carriage return get a leading
 * apostrophe. Otherwise a spreadsheet would run a cell such as =HYPERLINK(...) as a
 * formula, and usernames in a log are chosen by the attacker.
 */
public final class CsvExporter {

    public static final String HEADER = "severity,rule,ip,first_seen,last_seen,event_count,description";

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final String EOL = "\r\n";

    private CsvExporter() {
    }

    public static String findingsToCsv(List<Finding> findings) {
        StringBuilder out = new StringBuilder(HEADER).append(EOL);
        for (Finding f : findings) {
            out.append(cell(f.severity().name())).append(',')
                    .append(cell(f.rule())).append(',')
                    .append(cell(f.ip())).append(',')
                    .append(cell(f.firstSeen().format(TIME))).append(',')
                    .append(cell(f.lastSeen().format(TIME))).append(',')
                    .append(f.eventCount()).append(',')
                    .append(cell(f.description())).append(EOL);
        }
        return out.toString();
    }

    public static String cell(String value) {
        String s = value == null ? "" : value;
        if (!s.isEmpty() && "=+-@\t\r".indexOf(s.charAt(0)) >= 0) {
            s = "'" + s;
        }
        boolean needsQuotes = s.indexOf(',') >= 0 || s.indexOf('"') >= 0
                || s.indexOf('\n') >= 0 || s.indexOf('\r') >= 0;
        return needsQuotes ? "\"" + s.replace("\"", "\"\"") + "\"" : s;
    }
}