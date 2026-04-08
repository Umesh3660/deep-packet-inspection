package com.packetanalyzer.dpi;

import com.packetanalyzer.types.Connection.PacketJob;
import com.packetanalyzer.types.FiveTuple;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A single load-balancer thread.
 * Receives packets from its input queue and dispatches them to
 * the appropriate fast-path processor based on the five-tuple hash.
 *
 * Mirrors the C++ {@code DPI::LoadBalancer} class.
 */
public class LoadBalancer {

    private final int                        lbId;
    private final int                        fpStartId;
    private final List<PacketQueue<PacketJob>> fpQueues;
    final         PacketQueue<PacketJob>     inputQueue;

    private final AtomicLong received   = new AtomicLong();
    private final AtomicLong dispatched = new AtomicLong();

    private volatile boolean running = false;
    private Thread thread;

    public LoadBalancer(int lbId, List<PacketQueue<PacketJob>> fpQueues, int fpStartId) {
        this.lbId      = lbId;
        this.fpStartId = fpStartId;
        this.fpQueues  = fpQueues;
        this.inputQueue = new PacketQueue<>(10_000);
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void start() {
        if (running) return;
        running = true;
        thread = new Thread(this::run, "LB-" + lbId);
        thread.setDaemon(true);
        thread.start();
        System.out.printf("[LB%d] Started (serving FP%d-FP%d)%n",
            lbId, fpStartId, fpStartId + fpQueues.size() - 1);
    }

    public void stop() {
        if (!running) return;
        running = false;
        inputQueue.shutdown();
        if (thread != null) {
            try { thread.join(2000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        System.out.println("[LB" + lbId + "] Stopped");
    }

    // ── Main loop ─────────────────────────────────────────────────────────────

    private void run() {
        while (running) {
            PacketJob job = inputQueue.poll(100);
            if (job == null) continue;
            received.incrementAndGet();
            int idx = selectFP(job.tuple);
            fpQueues.get(idx).push(job);
            dispatched.incrementAndGet();
        }
    }

    private int selectFP(FiveTuple tuple) {
        return Math.abs(tuple.hashCode()) % fpQueues.size();
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    public long getReceived()   { return received.get(); }
    public long getDispatched() { return dispatched.get(); }
}
