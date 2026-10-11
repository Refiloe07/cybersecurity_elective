package dev.sentry.model;

import java.time.LocalDateTime;

/**
 * One parsed SSH authentication event.
 *
 * @param timestamp   when it happened (syslog has no year, so the parser supplies one)
 * @param type        failed or accepted login
 * @param method      auth method, e.g. "password" or "publickey"
 * @param user        the username that was tried
 * @param invalidUser true if the account does not exist on the server
 * @param ip          source IP address
 * @param port        source port
 */
public record LogEvent(
        LocalDateTime timestamp,
        EventType type,
        String method,
        String user,
        boolean invalidUser,
        String ip,
        int port) {
}