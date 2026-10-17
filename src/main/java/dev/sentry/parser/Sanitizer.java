package dev.sentry.parser;

/**
 * Makes untrusted text from a log safe to print.
 *
 * Usernames and other fields in a log are written by whoever is attacking the
 * server. A username can contain terminal escape codes that clear the screen,
 * change the window title or hide text, or invisible Unicode characters that make
 * text look different from what it is. Those are replaced by a visible escape like
 * {@code \x1b}, so the attempt is still reported but cannot affect your terminal.
 */
public final class Sanitizer {

    private Sanitizer() {
    }

    /** Returns the text with control and invisible characters replaced by visible hex escapes. */
    public static String visible(String text) {
        StringBuilder out = null;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (needsEscape(c)) {
                if (out == null) {
                    out = new StringBuilder(text.length() + 8);
                    out.append(text, 0, i);
                }
                out.append(c < 0x100 ? String.format("\\x%02x", (int) c) : String.format("\\u%04x", (int) c));
            } else if (out != null) {
                out.append(c);
            }
        }
        return out == null ? text : out.toString();
    }

    private static boolean needsEscape(char c) {
        if (c < 0x20 || (c >= 0x7F && c <= 0x9F)) {
            return true; // ASCII and C1 control characters, including ESC and DEL
        }
        int type = Character.getType(c);
        return type == Character.FORMAT                  // invisible: zero-width, bidi overrides
                || type == Character.LINE_SEPARATOR
                || type == Character.PARAGRAPH_SEPARATOR;
    }
}