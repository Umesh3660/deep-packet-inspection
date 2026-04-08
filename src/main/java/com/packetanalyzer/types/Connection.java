package com.packetanalyzer.types;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

// ❌ REMOVE these two — they already live in their own files:
// enum ConnectionState { NEW, ESTABLISHED, CLASSIFIED, BLOCKED, CLOSED }
// enum PacketAction { FORWARD, DROP, INSPECT, LOG_ONLY }

public class Connection {
    public FiveTuple       tuple;
    public ConnectionState state   = ConnectionState.NEW;   // ✅ uses ConnectionState.java
    public AppType         appType = AppType.UNKNOWN;
    public String          sni     = "";

    public long packetsIn  = 0;
    public long packetsOut = 0;
    public long bytesIn    = 0;
    public long bytesOut   = 0;

    public Instant firstSeen = Instant.now();
    public Instant lastSeen  = Instant.now();

    public PacketAction action = PacketAction.FORWARD;      // ✅ uses PacketAction.java

    public boolean synSeen    = false;
    public boolean synAckSeen = false;
    public boolean finSeen    = false;

    public Connection(FiveTuple tuple) {
        this.tuple = tuple;
    }

    public static class TrackerStats {
        public final long activeConnections;
        public final long totalConnectionsSeen;
        public final long classifiedConnections;
        public final long blockedConnections;

        public TrackerStats(long active, long total, long classified, long blocked) {
            this.activeConnections     = active;
            this.totalConnectionsSeen  = total;
            this.classifiedConnections = classified;
            this.blockedConnections    = blocked;
        }
    }

    public static class DPIStats {
        public final AtomicLong totalPackets      = new AtomicLong();
        public final AtomicLong totalBytes        = new AtomicLong();
        public final AtomicLong forwardedPackets  = new AtomicLong();
        public final AtomicLong droppedPackets    = new AtomicLong();
        public final AtomicLong tcpPackets        = new AtomicLong();
        public final AtomicLong udpPackets        = new AtomicLong();
        public final AtomicLong otherPackets      = new AtomicLong();
        public final AtomicLong activeConnections = new AtomicLong();
    }

    public static class PacketJob {
        public int       packetId;
        public FiveTuple tuple;
        public byte[]    data;
        public int       ethOffset;
        public int       ipOffset;
        public int       transportOffset;
        public int       payloadOffset;
        public int       payloadLength;
        public int       tcpFlags;
        public byte[]    payloadData;
        public long      tsSec;
        public long      tsUsec;

        public PacketJob() {}
    }
}