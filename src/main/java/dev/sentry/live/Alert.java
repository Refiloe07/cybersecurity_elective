package dev.sentry.live;

import dev.sentry.detect.Finding;

/**
 * One alert raised while watching a log.
 *
 * @param finding    what was found
 * @param escalation true if this incident was already alerted and has now become more serious
 */
public record Alert(Finding finding, boolean escalation) {
}