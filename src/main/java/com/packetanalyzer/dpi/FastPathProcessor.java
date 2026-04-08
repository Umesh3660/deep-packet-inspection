package com.packetanalyzer.dpi;

import com.packetanalyzer.extractor.SNIExtractor;
import com.packetanalyzer.rules.RuleManager;
import com.packetanalyzer.tracker.ConnectionTracker;
import com.packetanalyzer.types.*;

import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

/**
 * A single fast-path processing thread.
 * Responsible for connection tracking, DPI (SNI/HTTP/DNS extraction),
 * rule matching, and forwarding/dropping decisions.
 *
 * Mirrors the C++ {@code DPI::FastPathProcessor} class.
 */
public class FastPathProcessor {

    private final int fpId;
    final PacketQueue<Connection.PacketJob> inputQueue;
    private final ConnectionTracker          connTracker;
    private final RuleManager                ruleManager;
    private final BiConsumer<Connection.PacketJob, PacketAction> outputCallback;

    // Statistics
    private final AtomicLong processed      = new AtomicLong();
    private final AtomicLong forwarded      = new AtomicLong();
    private final AtomicLong dropped        = new AtomicLong();
    private final AtomicLong sniExtractions = new AtomicLong();
    private final AtomicLong classHits      = new AtomicLong();

    private volatile boolean running = false;
    private Thread thread;

    public FastPathProcessor(int fpId, RuleManager ruleManager,
                             BiConsumer<Connection.PacketJob, PacketAction> outputCallback) {
        this.fpId           = fpId;
        this.ruleManager    = ruleManager;
        this.outputCallback = outputCallback;
        this.inputQueue     = new PacketQueue<>(10_000);
        this.connTracker    = new ConnectionTracker(fpId);
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void start() {
        if (running) return;
        running = true;
        thread = new Thread(this::run, "FP-" + fpId);
        thread.setDaemon(true);
        thread.start();
        System.out.println("[FP" + fpId + "] Started");
    }

    public void stop() {
        if (!running) return;
        running = false;
        inputQueue.shutdown();
        if (thread != null) {
            try { thread.join(2000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        System.out.println("[FP" + fpId + "] Stopped (processed " + processed.get() + " packets)");
    }

    // ── Main loop ─────────────────────────────────────────────────────────────

    private void run() {
        while (running) {
            Connection.PacketJob job = inputQueue.poll(100);
            if (job == null) {
                connTracker.cleanupStale(300);
                continue;
            }
            processed.incrementAndGet();
            PacketAction action = processPacket(job);
            if (outputCallback != null) outputCallback.accept(job, action);
            if (action == PacketAction.DROP) dropped.incrementAndGet();
            else                             forwarded.incrementAndGet();
        }
    }

    // ── Packet processing ─────────────────────────────────────────────────────

    private PacketAction processPacket(Connection.PacketJob job) {
        Connection conn = connTracker.getOrCreateConnection(job.tuple);
        connTracker.updateConnection(conn, job.data.length, true);

        if (job.tuple.protocol == 6) updateTCPState(conn, job.tcpFlags);

        if (conn.state == ConnectionState.BLOCKED) return PacketAction.DROP;

        if (conn.state != ConnectionState.CLASSIFIED && job.payloadLength > 0) {
            inspectPayload(job, conn);
        }

        return checkRules(job, conn);
    }

    private void inspectPayload(Connection.PacketJob job, Connection conn) {
        if (job.payloadLength == 0 || job.payloadOffset >= job.data.length) return;

        if (tryExtractSNI(job, conn))       return;
        if (tryExtractHTTPHost(job, conn))  return;

        // DNS (port 53)
        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            var domain = com.packetanalyzer.extractor.DNSExtractorPublic.extractQuery(job.payloadData, job.payloadLength);
            if (domain.isPresent()) {
                connTracker.classifyConnection(conn, AppType.DNS, domain.get());
                return;
            }
        }

        // Fallback port-based classification
        if      (job.tuple.dstPort == 80)  connTracker.classifyConnection(conn, AppType.HTTP,  "");
        else if (job.tuple.dstPort == 443) connTracker.classifyConnection(conn, AppType.HTTPS, "");
    }

    private boolean tryExtractSNI(Connection.PacketJob job, Connection conn) {
        if (job.tuple.dstPort != 443 && job.payloadLength < 50) return false;
        if (job.payloadData == null || job.payloadLength == 0)   return false;

        var sni = SNIExtractor.extract(job.payloadData, job.payloadLength);
        if (sni.isPresent()) {
            sniExtractions.incrementAndGet();
            AppType app = AppType.fromSni(sni.get());
            connTracker.classifyConnection(conn, app, sni.get());
            if (app != AppType.UNKNOWN && app != AppType.HTTPS) classHits.incrementAndGet();
            return true;
        }
        return false;
    }

    private boolean tryExtractHTTPHost(Connection.PacketJob job, Connection conn) {
        if (job.tuple.dstPort != 80)                           return false;
        if (job.payloadData == null || job.payloadLength == 0) return false;

        var host = com.packetanalyzer.extractor.HTTPHostExtractorPublic.extract(job.payloadData, job.payloadLength);
        if (host.isPresent()) {
            AppType app = AppType.fromSni(host.get());
            connTracker.classifyConnection(conn, app, host.get());
            if (app != AppType.UNKNOWN && app != AppType.HTTP) classHits.incrementAndGet();
            return true;
        }
        return false;
    }

    private PacketAction checkRules(Connection.PacketJob job, Connection conn) {
        if (ruleManager == null) return PacketAction.FORWARD;

        RuleManager.BlockReason reason = ruleManager.shouldBlock(
            job.tuple.srcIp, job.tuple.dstPort, conn.appType, conn.sni);

        if (reason != null) {
            System.out.println("[FP" + fpId + "] BLOCKED: " + reason.type + " " + reason.detail);
            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }
        return PacketAction.FORWARD;
    }

    private void updateTCPState(Connection conn, int flags) {
        final int SYN = 0x02, ACK = 0x10, FIN = 0x01, RST = 0x04;

        if ((flags & SYN) != 0) {
            if ((flags & ACK) != 0) conn.synAckSeen = true;
            else                    conn.synSeen     = true;
        }
        if (conn.synSeen && conn.synAckSeen && (flags & ACK) != 0 && conn.state == ConnectionState.NEW)
            conn.state = ConnectionState.ESTABLISHED;
        if ((flags & FIN) != 0) conn.finSeen = true;
        if ((flags & RST) != 0) conn.state = ConnectionState.CLOSED;
        if (conn.finSeen && (flags & ACK) != 0) conn.state = ConnectionState.CLOSED;
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    public ConnectionTracker getConnectionTracker() { return connTracker; }
    public int getId() { return fpId; }

    public static class FPStats {
        public final long packetsProcessed;
        public final long packetsForwarded;
        public final long packetsDropped;
        public final long connectionsTracked;
        public final long sniExtractions;
        public final long classificationHits;

        FPStats(long proc, long fwd, long drop, long conns, long sni, long hits) {
            packetsProcessed   = proc;
            packetsForwarded   = fwd;
            packetsDropped     = drop;
            connectionsTracked = conns;
            sniExtractions     = sni;
            classificationHits = hits;
        }
    }

    public FPStats getStats() {
        return new FPStats(processed.get(), forwarded.get(), dropped.get(),
            connTracker.getActiveCount(), sniExtractions.get(), classHits.get());
    }
}
