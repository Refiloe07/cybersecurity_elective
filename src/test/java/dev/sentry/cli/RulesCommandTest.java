package dev.sentry.cli;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class RulesCommandTest {

    private static String capture(String... args) {
        PrintStream oldOut = System.out;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        try {
            assertEquals(0, new CommandLine(new Main()).execute(args));
            return out.toString(StandardCharsets.UTF_8);
        } finally {
            System.setOut(oldOut);
        }
    }

    @Test
    void listsEveryRuleWithItsDescription() {
        String out = capture("rules");
        assertTrue(out.contains("brute-force"));
        assertTrue(out.contains("invalid-user"));
        assertTrue(out.contains("success-after-failures"));
        assertTrue(out.contains("Many failed logins from one IP in a short time."));
    }

    @Test
    void helpMentionsTheRulesCommand() {
        assertTrue(capture("--help").contains("rules"));
    }
}