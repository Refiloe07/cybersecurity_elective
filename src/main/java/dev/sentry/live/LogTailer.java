package dev.sentry.live;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads the new lines of a growing file, like {@code tail -f}, without blocking.
 *
 * <ul>
 *   <li>Only whole lines are returned; a half-written line waits for its newline.</li>
 *   <li>If the file shrinks or is replaced (log rotation), reading restarts from the top.</li>
 *   <li>If the file disappears for a moment, it simply waits for it to come back.</li>
 *   <li>At most {@link #CHUNK} bytes are read per call, so a huge file never fills memory.</li>
 * </ul>
 */
public final class LogTailer {

    static final int CHUNK = 256 * 1024;
    static final int MAX_LINE = 1024 * 1024;

    private final Path file;
    private final ByteArrayOutputStream pending = new ByteArrayOutputStream();
    private long position;
    private Object fileKey;
    private boolean moreAvailable;

    /** @param fromStart true to read what is already in the file; false to wait for new lines */
    public LogTailer(Path file, boolean fromStart) throws IOException {
        this.file = file;
        BasicFileAttributes attrs = Files.readAttributes(file, BasicFileAttributes.class);
        this.fileKey = attrs.fileKey();
        this.position = fromStart ? 0 : attrs.size();
    }

    /** True if the last call left unread data behind, so call again straight away. */
    public boolean moreAvailable() {
        return moreAvailable;
    }

    /** Returns the complete lines that appeared since the last call (without line endings). */
    public List<String> poll() throws IOException {
        moreAvailable = false;

        BasicFileAttributes attrs;
        try {
            attrs = Files.readAttributes(file, BasicFileAttributes.class);
        } catch (NoSuchFileException e) {
            return List.of();
        }
        Object key = attrs.fileKey();
        long size = attrs.size();

        boolean replaced = key != null && fileKey != null && !key.equals(fileKey);
        if (replaced || size < position) {
            position = 0;
            pending.reset();
        }
        fileKey = key;
        if (size <= position) {
            return List.of();
        }

        int toRead = (int) Math.min(CHUNK, size - position);
        ByteBuffer buffer = ByteBuffer.allocate(toRead);
        try (SeekableByteChannel channel = Files.newByteChannel(file, StandardOpenOption.READ)) {
            channel.position(position);
            while (buffer.hasRemaining() && channel.read(buffer) >= 0) {
                // keep reading until the buffer is full or the file ends
            }
        } catch (NoSuchFileException e) {
            return List.of();
        }

        int read = buffer.position();
        position += read;
        pending.write(buffer.array(), 0, read);
        moreAvailable = position < size;
        return takeCompleteLines();
    }

    private List<String> takeCompleteLines() {
        byte[] data = pending.toByteArray();
        int lastNewline = -1;
        for (int i = data.length - 1; i >= 0; i--) {
            if (data[i] == '\n') {
                lastNewline = i;
                break;
            }
        }

        if (lastNewline < 0) {
            if (data.length > MAX_LINE) { // one absurdly long line: emit it rather than grow forever
                pending.reset();
                return List.of(new String(data, StandardCharsets.UTF_8));
            }
            return List.of();
        }

        // Decode only up to the last newline so a multi-byte character is never cut in half.
        String text = new String(data, 0, lastNewline, StandardCharsets.UTF_8);
        pending.reset();
        pending.write(data, lastNewline + 1, data.length - lastNewline - 1);

        List<String> lines = new ArrayList<>();
        for (String line : text.split("\n", -1)) {
            lines.add(line.endsWith("\r") ? line.substring(0, line.length() - 1) : line);
        }
        return lines;
    }
}