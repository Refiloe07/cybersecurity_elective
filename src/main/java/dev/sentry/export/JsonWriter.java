package dev.sentry.export;

import java.util.Map;

/**
 * A small JSON writer for the program's own output. It handles null, booleans,
 * numbers, strings, enums, maps with string keys, and lists. Output is pretty
 * printed with two-space indents and is pure ASCII: every non-ASCII character is
 * written as a \\uXXXX escape, so the result survives any console or file encoding.
 */
public final class JsonWriter {

    private JsonWriter() {
    }

    public static String toJson(Object value) {
        StringBuilder out = new StringBuilder();
        write(value, out, 0);
        return out.toString();
    }

    private static void write(Object value, StringBuilder out, int depth) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String s) {
            string(s, out);
        } else if (value instanceof Boolean || value instanceof Integer
                || value instanceof Long || value instanceof Short || value instanceof Byte) {
            out.append(value);
        } else if (value instanceof Double || value instanceof Float) {
            if (!Double.isFinite(((Number) value).doubleValue())) {
                throw new IllegalArgumentException("JSON cannot represent NaN or infinity");
            }
            out.append(value);
        } else if (value instanceof Enum<?> e) {
            string(e.name(), out);
        } else if (value instanceof Map<?, ?> map) {
            object(map, out, depth);
        } else if (value instanceof Iterable<?> items) {
            array(items, out, depth);
        } else {
            throw new IllegalArgumentException("unsupported JSON value type: " + value.getClass().getName());
        }
    }

    private static void object(Map<?, ?> map, StringBuilder out, int depth) {
        if (map.isEmpty()) {
            out.append("{}");
            return;
        }
        out.append("{\n");
        boolean first = true;
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IllegalArgumentException("JSON object keys must be strings");
            }
            if (!first) {
                out.append(",\n");
            }
            first = false;
            indent(out, depth + 1);
            string(key, out);
            out.append(": ");
            write(entry.getValue(), out, depth + 1);
        }
        out.append('\n');
        indent(out, depth);
        out.append('}');
    }

    private static void array(Iterable<?> items, StringBuilder out, int depth) {
        if (!items.iterator().hasNext()) {
            out.append("[]");
            return;
        }
        out.append("[\n");
        boolean first = true;
        for (Object item : items) {
            if (!first) {
                out.append(",\n");
            }
            first = false;
            indent(out, depth + 1);
            write(item, out, depth + 1);
        }
        out.append('\n');
        indent(out, depth);
        out.append(']');
    }

    private static void indent(StringBuilder out, int depth) {
        out.append("  ".repeat(depth));
    }

    private static void string(String s, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20 || c > 0x7E) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
}