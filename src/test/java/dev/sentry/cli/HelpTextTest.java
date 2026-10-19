package dev.sentry.cli;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HelpTextTest {

    private static String help(String... args) {
        PrintStream oldOut = System.out;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        try {
            assertEquals(0, Main.newCommandLine(false).execute(args));
            return out.toString(StandardCharsets.UTF_8);
        } finally {
            System.setOut(oldOut);
        }
    }

    @Test
    void mainHelpListsEveryCommandExitCodesAndExamples() {
        String text = help("--help");
        for (String command : List.of("analyze", "generate", "rules", "watch")) {
            assertTrue(text.contains(command), "missing command: " + command);
        }
        assertTrue(text.contains("Exit codes:"));
        assertTrue(text.contains("Wrong usage"));
        assertTrue(text.contains("Examples:"));
        assertTrue(text.contains("sentry watch /var/log/auth.log"));
    }

    @Test
    void analyzeHelpHasExamplesAndStillListsOptions() {
        String text = help("analyze", "--help");
        assertTrue(text.contains("Examples:"));
        assertTrue(text.contains("-f json -o out.json"));
        assertTrue(text.contains("--rule-threshold"));
        assertTrue(text.contains("--format"));
    }

    @Test
    void watchHelpHasExamples() {
        String text = help("watch", "--help");
        assertTrue(text.contains("Examples:"));
        assertTrue(text.contains("--from-start"));
    }

    @Test
    void exampleLinesAreNeverWrappedIntoOrphanFragments() {
        for (String[] args : List.of(new String[] {"--help"}, new String[] {"analyze", "--help"},
                new String[] {"watch", "--help"})) {
            String text = help(args);
            String afterExamples = text.substring(text.indexOf("Examples:"));
            boolean tidy = afterExamples.lines().skip(1).filter(l -> !l.isBlank())
                    .allMatch(l -> l.startsWith("  sentry ") || l.startsWith("Run 'sentry"));
            assertTrue(tidy, "a help example wrapped onto a second line:\n" + afterExamples);
        }
    }
}