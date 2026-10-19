package dev.sentry;

/**
 * The program version, in one place. A test checks it matches pom.xml, so the two
 * cannot drift apart. The release workflow checks it matches the git tag.
 */
public final class Version {

    public static final String CURRENT = "1.0.0";

    private Version() {
    }
}