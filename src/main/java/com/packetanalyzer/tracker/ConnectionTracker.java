package com.packetanalyzer.tracker;

import com.packetanalyzer.types.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Maintains a per-fast-path flow table.
 * Mirrors the C++ {@code DPI::ConnectionTracker} class.
 */
public class ConnectionTracker {

    private final int    fpId;
    private final int    maxConnections;

    private final Map<FiveTuple, Connection> connections = new LinkedHashMap<>();

    private long totalSeen       = 0;
    private long classifiedCount = 0;
    private long blockedCount    = 0;

    public ConnectionTracker(int fpId) { this(fpId, 100_000); }

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId           = fpId;
        this.maxConnections = maxConnections;
    }

    // ── CRUD ──────────────────────────────────────────────────────────────────

    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) return conn;

        if (connections.size() >= maxConnections) evictOldest();

        conn = new Connection(tuple);
        connections.put(tuple, conn);
        totalSeen++;
        return conn;
    }

    public Connection getConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) return conn;
        return connections.get(tuple.reverse());
    }

    public void updateConnection(Connection conn, int packetSize, boolean isOutbound) {
        if (conn == null) return;
        conn.lastSeen = Instant.now();
        if (isOutbound) { conn.packetsOut++; conn.bytesOut += packetSize; }
        else            { conn.packetsIn++;  conn.bytesIn  += packetSize; }
    }

    public void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn == null) return;
        if (conn.state != ConnectionState.CLASSIFIED) {
            conn.appType = app;
            conn.sni     = sni;
            conn.state   = ConnectionState.CLASSIFIED;
            classifiedCount++;
        }
    }

    public void blockConnection(Connection conn) {
        if (conn == null) return;
        conn.state  = ConnectionState.BLOCKED;
        conn.action = PacketAction.DROP;
        blockedCount++;
    }

    public void closeConnection(FiveTuple tuple) {
        Connection c = connections.get(tuple);
        if (c != null) c.state = ConnectionState.CLOSED;
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────

    /** Remove stale/closed connections. Returns count removed. */
    public int cleanupStale(long timeoutSeconds) {
        Instant cutoff = Instant.now().minus(timeoutSeconds, ChronoUnit.SECONDS);
        int removed = 0;
        Iterator<Map.Entry<FiveTuple, Connection>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Connection c = it.next().getValue();
            if (c.state == ConnectionState.CLOSED || c.lastSeen.isBefore(cutoff)) {
                it.remove();
                removed++;
            }
        }
        return removed;
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public int getActiveCount() { return connections.size(); }

    public Connection.TrackerStats getStats() {
        return new Connection.TrackerStats(
            connections.size(), totalSeen, classifiedCount, blockedCount);
    }

    public void clear() { connections.clear(); }

    public void forEach(java.util.function.Consumer<Connection> cb) {
        connections.values().forEach(cb);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private void evictOldest() {
        Connection oldest      = null;
        FiveTuple  oldestKey   = null;
        for (Map.Entry<FiveTuple, Connection> e : connections.entrySet()) {
            if (oldest == null || e.getValue().lastSeen.isBefore(oldest.lastSeen)) {
                oldest    = e.getValue();
                oldestKey = e.getKey();
            }
        }
        if (oldestKey != null) connections.remove(oldestKey);
    }
}
