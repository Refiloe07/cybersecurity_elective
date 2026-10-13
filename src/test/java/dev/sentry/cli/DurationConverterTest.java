package dev.sentry.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import picocli.CommandLine.TypeConversionException;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class DurationConverterTest {

    @Test
    void parsesAllUnits() {
        assertEquals(Duration.ofSeconds(30), DurationConverter.parse("30s"));
        assertEquals(Duration.ofMinutes(10), DurationConverter.parse("10m"));
        assertEquals(Duration.ofHours(2), DurationConverter.parse("2h"));
        assertEquals(Duration.ofDays(1), DurationConverter.parse("1d"));
    }

    @Test
    void trimsWhitespace() {
        assertEquals(Duration.ofMinutes(5), DurationConverter.parse(" 5m "));
    }

    @ParameterizedTest
    @ValueSource(strings = {"abc", "10", "0m", "-5m", "10x", "", "1.5h",
            "99999999999999999999m", "9999999999999999d"})
    void rejectsBadValues(String value) {
        assertThrows(TypeConversionException.class, () -> DurationConverter.parse(value));
    }

    @Test
    void rejectsNull() {
        assertThrows(TypeConversionException.class, () -> DurationConverter.parse(null));
    }

    @Test
    void formatsShortestExactForm() {
        assertEquals("10m", DurationConverter.format(Duration.ofMinutes(10)));
        assertEquals("90s", DurationConverter.format(Duration.ofSeconds(90)));
        assertEquals("2h", DurationConverter.format(Duration.ofHours(2)));
        assertEquals("2d", DurationConverter.format(Duration.ofHours(48)));
    }
}