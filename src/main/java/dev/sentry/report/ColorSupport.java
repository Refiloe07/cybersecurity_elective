package dev.sentry.report;

import java.io.Console;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Decides whether to print colors. */
public final class ColorSupport {

    private static final List<String> MODES = List.of("auto", "always", "never");

    private ColorSupport() {
    }

    /**
     * @param mode             "auto", "always" or "never"
     * @param noColorFlag      true if --no-color was given (beats everything)
     * @param env              environment variables
     * @param stdoutIsTerminal true when output goes to a real terminal, not a file or pipe
     * @param windows          true on Windows, where old consoles cannot show ANSI colors
     * @throws IllegalArgumentException if mode is not auto, always or never
     */
    public static boolean shouldColor(String mode, boolean noColorFlag, Map<String, String> env,
                                      boolean stdoutIsTerminal, boolean windows) {
        String m = mode == null ? "auto" : mode.trim().toLowerCase(Locale.ROOT);
        if (!MODES.contains(m)) {
            throw new IllegalArgumentException("--color must be auto, always or never but was '" + mode + "'");
        }
        if (noColorFlag || m.equals("never")) {
            return false;
        }
        if (m.equals("always")) {
            return true;
        }

        // auto: only color a real terminal that is known to understand it
        String noColor = env.get("NO_COLOR"); // https://no-color.org
        if (noColor != null && !noColor.isEmpty()) {
            return false;
        }
        if (!stdoutIsTerminal || "dumb".equals(env.get("TERM"))) {
            return false;
        }
        if (windows) {
            // Windows Terminal and the VS Code terminal handle ANSI; the old console may not
            return env.containsKey("WT_SESSION")
                    || env.containsKey("TERM_PROGRAM")
                    || env.containsKey("ANSICON")
                    || "ON".equalsIgnoreCase(env.get("ConEmuANSI"));
        }
        return true;
    }

    /** Uses the real environment. */
    public static boolean shouldColor(String mode, boolean noColorFlag) {
        return shouldColor(mode, noColorFlag, System.getenv(), stdoutIsTerminal(), isWindows());
    }

    static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows");
    }

    /**
     * Java 22+ always returns a Console, even when output is redirected, and offers
     * isTerminal() to tell the difference. On older Java a non-null Console means a terminal.
     */
    static boolean stdoutIsTerminal() {
        Console console = System.console();
        if (console == null) {
            return false;
        }
        try {
            return (boolean) Console.class.getMethod("isTerminal").invoke(console);
        } catch (ReflectiveOperationException | ClassCastException e) {
            return true;
        }
    }
}