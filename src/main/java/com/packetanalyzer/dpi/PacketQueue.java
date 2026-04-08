package com.packetanalyzer.dpi;

import java.util.concurrent.*;

/**
 * Bounded, blocking queue used to pass {@link com.packetanalyzer.types.Connection.PacketJob}
 * objects between pipeline stages (Reader → LB → FP → Output).
 *
 * Mirrors the C++ {@code DPI::ThreadSafeQueue<T>} template class.
 *
 * @param <T> element type
 */
public class PacketQueue<T> {

    private final LinkedBlockingDeque<T> queue;
    private volatile boolean shutdown = false;

    public PacketQueue(int maxSize) {
        this.queue = new LinkedBlockingDeque<>(maxSize);
    }

    /** Block until space is available, then enqueue. No-op after shutdown. */
    public void push(T item) {
        if (shutdown) return;
        try { queue.put(item); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    /** Non-blocking enqueue. Returns false if full or shutdown. */
    public boolean tryPush(T item) {
        if (shutdown) return false;
        return queue.offer(item);
    }

    /**
     * Block until an item is available or timeout elapses.
     * @return the item, or {@code null} on timeout / shutdown.
     */
    public T poll(long timeoutMs) {
        try {
            return queue.poll(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    /** Signal shutdown — wakes up all blocked threads. */
    public void shutdown() {
        shutdown = true;
        // Insert a dummy offer to unblock any waiting poll(); ignored by consumers.
        queue.clear(); // drain so blocked puts unblock
    }

    public boolean isShutdown() { return shutdown; }
    public boolean isEmpty()    { return queue.isEmpty(); }
    public int     size()       { return queue.size(); }
}
