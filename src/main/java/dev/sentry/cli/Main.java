package dev.sentry.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(
    name = "sentry",
    mixinStandardHelpOptions = true,
    version = "sentry 0.1.0",
    description = "Analyzes auth logs and flags suspicious activity.",
    subcommands = { AnalyzeCommand.class }
)
public class Main implements Runnable {

    @Override
    public void run() {
        // No subcommand given: show usage.
        CommandLine.usage(this, System.out);
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Main()).execute(args);
        System.exit(exitCode);
    }
}