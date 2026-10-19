package dev.sentry;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

class VersionTest {

    @Test
    void matchesTheVersionInPom() throws Exception {
        String pom = Files.readString(Path.of("pom.xml"));
        Matcher m = Pattern.compile("<artifactId>sentry</artifactId>\\s*<version>([^<]+)</version>").matcher(pom);
        assertTrue(m.find(), "could not find the project version in pom.xml");
        assertEquals(m.group(1), Version.CURRENT);
    }

    @Test
    void looksLikeAVersionNumber() {
        assertTrue(Version.CURRENT.matches("\\d+\\.\\d+\\.\\d+(-SNAPSHOT)?"));
    }
}