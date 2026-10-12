package dev.sentry.cli;

import dev.sentry.tools.SampleLogGenerator;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Year;
import java.util.List;
import java.util.concurrent.Callable;

@Command(
    name = "generate",
    mixinStandardHelpOptions = true,
    description = "Generate a fake auth.log containing realistic attack patterns, for demos and tests."
)
public class GenerateCommand implements Callable<Integer> {

    @Option(names = {"-o", "--output"}, required = true, paramLabel = "FILE",
            description = "Where to write the generated log.")
    private Path output;

    @Option(names = {"-s", "--seed"}, defaultValue = "42",
            description = "Random seed; the same seed gives the same log (default: ${DEFAULT-VALUE}).")
    private long seed;

    @Option(names = {"-y", "--year"},
            description = "Year to use in the log (default: current year).")
    private int year = Year.now().getValue();

    @Override
    public Integer call() {
        List<String> lines = new SampleLogGenerator(year, seed).generate();
        try {
            Path parent = output.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(output, lines);
            System.out.printf("Wrote %d lines to %s%n", lines.size(), output);
            return 0;
        } catch (IOException e) {
            System.err.println("error: could not write " + output + ": " + e.getMessage());
            return 1;
        }
    }
}