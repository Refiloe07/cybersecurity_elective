package dev.sentry.cli;

import picocli.CommandLine.ITypeConverter;
import picocli.CommandLine.TypeConversionException;

import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Converts values like 30s, 10m, 2h or 1d into a {@link Duration}. */
public class DurationConverter implements ITypeConverter<Duration> {

    private static final Pattern FORMAT = Pattern.compile("^(\\d+)([smhd])$");

    @Override
    public Duration convert(String value) {
        return parse(value);
    }

    public static Duration parse(String value) {
        Matcher m = FORMAT.matcher(value == null ? "" : value.trim());
        if (!m.matches()) {
            throw new TypeConversionException(
                    "expected a number followed by s, m, h or d (e.g. 30s, 10m, 2h, 1d) but was '" + value + "'");
        }
        long amount;
        try {
            amount = Long.parseLong(m.group(1));
        } catch (NumberFormatException e) {
            throw new TypeConversionException("number is too large: '" + value + "'");
        }
        if (amount <= 0) {
            throw new TypeConversionException("duration must be greater than zero but was '" + value + "'");
        }
        try {
            return switch (m.group(2)) {
                case "s" -> Duration.ofSeconds(amount);
                case "m" -> Duration.ofMinutes(amount);
                case "h" -> Duration.ofHours(amount);
                default -> Duration.ofDays(amount);
            };
        } catch (ArithmeticException e) {
            throw new TypeConversionException("duration is too large: '" + value + "'");
        }
    }

    /** Shortest exact form, e.g. PT10M becomes "10m", PT90S stays "90s". */
    public static String format(Duration d) {
        long s = d.getSeconds();
        if (s % 86400 == 0) {
            return (s / 86400) + "d";
        }
        if (s % 3600 == 0) {
            return (s / 3600) + "h";
        }
        if (s % 60 == 0) {
            return (s / 60) + "m";
        }
        return s + "s";
    }
}