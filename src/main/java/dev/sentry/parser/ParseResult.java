package dev.sentry.parser;

import dev.sentry.model.LogEvent;

import java.util.List;

/**
 * Outcome of parsing a whole log.
 *
 * @param events       successfully parsed events, in file order
 * @param totalLines   lines read
 * @param skippedLines lines that were not SSH login events (or were malformed)
 */
public record ParseResult(List<LogEvent> events, int totalLines, int skippedLines) {
}