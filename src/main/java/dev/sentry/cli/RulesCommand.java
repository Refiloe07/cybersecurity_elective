package dev.sentry.cli;

import dev.sentry.detect.Rule;
import dev.sentry.detect.RuleCatalog;
import picocli.CommandLine.Command;

import java.time.Duration;
import java.util.concurrent.Callable;

@Command(
    name = "rules",
    mixinStandardHelpOptions = true,
    description = "List the detection rules sentry can run."
)
public class RulesCommand implements Callable<Integer> {

    @Override
    public Integer call() {
        System.out.println("Detection rules:");
        for (String name : RuleCatalog.names()) {
            Rule rule = RuleCatalog.create(name, 1, Duration.ofMinutes(1));
            System.out.printf("  %-24s %s%n", rule.name(), rule.description());
        }
        System.out.println();
        System.out.println("Use with analyze:  --skip NAME   or   --rule-threshold NAME=N");
        return 0;
    }
}