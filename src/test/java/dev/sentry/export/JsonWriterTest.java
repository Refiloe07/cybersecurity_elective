package dev.sentry.export;

import dev.sentry.detect.Severity;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JsonWriterTest {

    @Test
    void writesScalars() {
        assertEquals("null", JsonWriter.toJson(null));
        assertEquals("true", JsonWriter.toJson(true));
        assertEquals("42", JsonWriter.toJson(42));
        assertEquals("7", JsonWriter.toJson(7L));
        assertEquals("1.5", JsonWriter.toJson(1.5));
        assertEquals("\"hi\"", JsonWriter.toJson("hi"));
    }

    @Test
    void escapesQuotesBackslashesAndControlCharacters() {
        assertEquals("\"a\\\"b\\\\c\"", JsonWriter.toJson("a\"b\\c"));
        assertEquals("\"\\n\\r\\t\\b\\f\\u0001\\u001b\"", JsonWriter.toJson("\n\r\t\b\f\u0001\u001B"));
    }

    @Test
    void writesNonAsciiAsUnicodeEscapes() {
        assertEquals("\"caf\\u00e9\"", JsonWriter.toJson("caf\u00e9"));
        assertEquals("\"\\ud83d\\ude00\"", JsonWriter.toJson("\uD83D\uDE00")); // emoji, as a surrogate pair
        assertEquals("\"\\u007f\"", JsonWriter.toJson("\u007f"));
        assertEquals("\"\\u202e\"", JsonWriter.toJson("\u202e"));
    }

    @Test
    void prettyPrintsNestedStructures() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("a", 1);
        map.put("b", List.of(1, 2));
        map.put("c", new LinkedHashMap<>(Map.of("d", "x")));
        map.put("e", Severity.HIGH);
        map.put("f", null);

        assertEquals("{\n  \"a\": 1,\n  \"b\": [\n    1,\n    2\n  ],\n  \"c\": {\n    \"d\": \"x\"\n  },\n"
                + "  \"e\": \"HIGH\",\n  \"f\": null\n}", JsonWriter.toJson(map));
    }

    @Test
    void emptyContainersStayOnOneLine() {
        assertEquals("{}", JsonWriter.toJson(new LinkedHashMap<>()));
        assertEquals("[]", JsonWriter.toJson(List.of()));
    }

    @Test
    void rejectsNanAndInfinity() {
        assertThrows(IllegalArgumentException.class, () -> JsonWriter.toJson(Double.NaN));
        assertThrows(IllegalArgumentException.class, () -> JsonWriter.toJson(Double.POSITIVE_INFINITY));
    }

    @Test
    void rejectsNonStringKeys() {
        assertThrows(IllegalArgumentException.class, () -> JsonWriter.toJson(Map.of(1, "x")));
    }

    @Test
    void rejectsUnsupportedTypes() {
        assertThrows(IllegalArgumentException.class, () -> JsonWriter.toJson(new Object()));
    }
}