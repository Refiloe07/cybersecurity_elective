package dev.sentry.cli;

import dev.sentry.Version;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.UnmatchedArgumentException;

import java.io.PrintWriter;

@Command(
    name = "sentry",
    mixinStandardHelpOptions = true,
    version = "sentry " + Version.CURRENT,
    description = "Reads SSH auth logs and tells you who is trying to break in.",
    usageHelpAutoWidth = true,
    exitCodeListHeading = "%nExit codes:%n",
    exitCodeList = {
        "0:Success (findings are reported, not treated as failure)",
        "1:A file could not be read or written, or an unexpected error occurred",
        "2:Wrong usage: bad option, unknown rule, missing file"
    },
    footerHeading = "%nExamples:%n",
    footer = {
        "  sentry generate -o samples/auth.log      make a fake log to practice on",
        "  sentry analyze samples/auth.log          find suspicious activity",
        "  sentry watch /var/log/auth.log           alert live as attacks happen",
        "  sentry rules                             list the detection rules",
        "",
        "Run 'sentry <command> --help' for the options of one command."
    },
    subcommands = { AnalyzeCommand.class, GenerateCommand.class, RulesCommand.class, WatchCommand.class }
)
public class Main implements Runnable {

    @Override
    public void run() {
        // No subcommand given: show usage.
        CommandLine.usage(this, System.out);
    }

    /**
     * Builds the command line with friendly error handling: a short message and a hint
     * instead of a wall of usage text for mistakes, and no stack trace for unexpected
     * problems unless {@code debug} is set.
     */
    public static CommandLine newCommandLine(boolean debug) {
        CommandLine cmd = new CommandLine(new Main());

        cmd.setParameterExceptionHandler((ex, args) -> {
            CommandLine failed = ex.getCommandLine();
            PrintWriter err = failed.getErr();
            err.println("error: " + ex.getMessage());
            UnmatchedArgumentException.printSuggestions(ex, err);
            err.println("Try '" + failed.getCommandSpec().qualifiedName() + " --help' for more information.");
            err.flush();
            return failed.getCommandSpec().exitCodeOnInvalidInput();
        });

        cmd.setExecutionExceptionHandler((ex, failed, parseResult) -> {
            PrintWriter err = failed.getErr();
            String message = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
            err.println("error: unexpected problem: " + message);
            if (debug) {
                ex.printStackTrace(err);
            } else {
                err.println("Run again with the SENTRY_DEBUG environment variable set to see the details.");
            }
            err.flush();
            return failed.getCommandSpec().exitCodeOnExecutionException();
        });
        return cmd;
    }

    public static void main(String[] args) {
        int exitCode = newCommandLine(System.getenv("SENTRY_DEBUG") != null).execute(args);
        System.exit(exitCode);
    }
}