package dev.sentry.parser;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SanitizerTest {

    @Test
    void plainTextIsReturnedUnchanged() {
        String s = "admin";
        assertSame(s, Sanitizer.visible(s));
        assertEquals("", Sanitizer.visible(""));
    }

    @Test
    void escapeCharacterBecomesVisible() {
        assertEquals("\\x1b[2Jx", Sanitizer.visible("\u001B[2Jx"));
    }

    @Test
    void otherControlCharactersBecomeVisible() {
        assertEquals("a\\x07b", Sanitizer.visible("a\u0007b"));
        assertEquals("\\x7f", Sanitizer.visible("\u007f"));
        assertEquals("\\x9b", Sanitizer.visible("\u009b"));
        assertEquals("a\\x0ab", Sanitizer.visible("a\nb"));
    }

    @Test
    void invisibleUnicodeBecomesVisible() {
        assertEquals("ab\\u202ecd", Sanitizer.visible("ab\u202ecd")); // right-to-left override
        assertEquals("a\\u200bb", Sanitizer.visible("a\u200bb"));     // zero-width space
        assertEquals("\\u2028", Sanitizer.visible("\u2028"));         // line separator
    }

    @Test
    void ordinaryUnicodeAndBackslashesAreKept() {
        assertEquals("Jos\u00e9 \u0418\u0432\u0430\u043d \u65e5\u672c", Sanitizer.visible("Jos\u00e9 \u0418\u0432\u0430\u043d \u65e5\u672c"));
        assertEquals("a\\b", Sanitizer.visible("a\\b"));
    }
}