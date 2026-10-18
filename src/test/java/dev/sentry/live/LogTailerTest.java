package dev.sentry.live;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LogTailerTest {

    private static void append(Path file, String text) throws IOException {
        Files.writeString(file, text, StandardOpenOption.APPEND);
    }

    @Test
    void startsAtTheEndAndSeesOnlyNewLines(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("t.log");
        Files.writeString(file, "one\ntwo\n");
        LogTailer tailer = new LogTailer(file, false);

        assertEquals(List.of(), tailer.poll());
        append(file, "three\n");
        assertEquals(List.of("three"), tailer.poll());
        assertEquals(List.of(), tailer.poll());
    }

    @Test
    void canReadWhatIsAlreadyThere(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("t.log");
        Files.writeString(file, "one\ntwo\n");
        assertEquals(List.of("one", "two"), new LogTailer(file, true).poll());
    }

    @Test
    void halfWrittenLineWaitsForItsNewlineAndCrlfIsStripped(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("t.log");
        Files.writeString(file, "");
        LogTailer tailer = new LogTailer(file, true);

        append(file, "abc");
        assertEquals(List.of(), tailer.poll());
        append(file, "def\r\nnext\n");
        assertEquals(List.of("abcdef", "next"), tailer.poll());
    }

    @Test
    void restartsFromTheTopWhenTheFileShrinks(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("t.log");
        Files.writeString(file, "a long first line\nanother long line\n");
        LogTailer tailer = new LogTailer(file, true);
        tailer.poll();

        Files.writeString(file, "x\n"); // rotated: new, shorter content
        assertEquals(List.of("x"), tailer.poll());
    }

    @Test
    void multiByteCharacterSplitAcrossReadsIsNotCorrupted(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("t.log");
        Files.write(file, new byte[0]);
        LogTailer tailer = new LogTailer(file, true);

        Files.write(file, new byte[] {'a', (byte) 0xC3}, StandardOpenOption.APPEND);
        assertEquals(List.of(), tailer.poll());
        Files.write(file, new byte[] {(byte) 0xA9, '\n'}, StandardOpenOption.APPEND);
        assertEquals(List.of("a\u00e9"), tailer.poll());
    }

    @Test
    void toleratesTheFileDisappearingAndReturning(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("t.log");
        Files.writeString(file, "aaaa\nbbbb\n");
        LogTailer tailer = new LogTailer(file, true);
        tailer.poll();

        Files.delete(file);
        assertEquals(List.of(), tailer.poll());
        Files.writeString(file, "new\n");
        assertEquals(List.of("new"), tailer.poll());
    }

    @Test
    void readsABigFileInChunks(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("big.log");
        String line = "x".repeat(99) + "\n";
        Files.writeString(file, line.repeat(7000));
        LogTailer tailer = new LogTailer(file, true);

        int total = tailer.poll().size();
        assertTrue(tailer.moreAvailable());
        int polls = 1;
        while (tailer.moreAvailable()) {
            total += tailer.poll().size();
            polls++;
        }
        assertEquals(7000, total);
        assertTrue(polls >= 3);
    }

    @Test
    void anEnormousLineWithoutNewlineIsEmittedInsteadOfGrowingForever(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("huge.log");
        byte[] data = new byte[LogTailer.CHUNK * 6];
        Arrays.fill(data, (byte) 'x');
        Files.write(file, data);
        LogTailer tailer = new LogTailer(file, true);

        List<String> lines = new ArrayList<>(tailer.poll());
        while (tailer.moreAvailable()) {
            lines.addAll(tailer.poll());
        }
        assertEquals(1, lines.size());
        assertTrue(lines.get(0).length() > LogTailer.MAX_LINE);
    }

    @Test
    void missingFileAtStartIsAnError(@TempDir Path dir) {
        assertThrows(IOException.class, () -> new LogTailer(dir.resolve("nope.log"), true));
    }
}