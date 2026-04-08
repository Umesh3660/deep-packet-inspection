package com.packetanalyzer.types;

import java.util.Objects;

/**
 * Uniquely identifies a network connection/flow by its 5-tuple.
 */
public class FiveTuple {
    public final long srcIp;   // stored as unsigned 32-bit in a long
    public final long dstIp;
    public final int  srcPort; // unsigned 16-bit in an int
    public final int  dstPort;
    public final int  protocol; // TCP=6, UDP=17

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp    = srcIp;
        this.dstIp    = dstIp;
        this.srcPort  = srcPort;
        this.dstPort  = dstPort;
        this.protocol = protocol;
    }

    /** Create the reverse tuple (for bidirectional flow matching). */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple)) return false;
        FiveTuple t = (FiveTuple) o;
        return srcIp == t.srcIp && dstIp == t.dstIp
                && srcPort == t.srcPort && dstPort == t.dstPort
                && protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        // Mirrors the C++ FiveTupleHash combining all fields
        int h = 0;
        h ^= Long.hashCode(srcIp)  + 0x9e3779b9 + (h << 6) + (h >>> 2);
        h ^= Long.hashCode(dstIp)  + 0x9e3779b9 + (h << 6) + (h >>> 2);
        h ^= Integer.hashCode(srcPort)  + 0x9e3779b9 + (h << 6) + (h >>> 2);
        h ^= Integer.hashCode(dstPort)  + 0x9e3779b9 + (h << 6) + (h >>> 2);
        h ^= Integer.hashCode(protocol) + 0x9e3779b9 + (h << 6) + (h >>> 2);
        return h;
    }

    @Override
    public String toString() {
        return ipToString(srcIp) + ":" + srcPort
             + " -> "
             + ipToString(dstIp) + ":" + dstPort
             + " (" + (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") + ")";
    }

    public static String ipToString(long ip) {
        return ((ip) & 0xFF) + "."
             + ((ip >> 8)  & 0xFF) + "."
             + ((ip >> 16) & 0xFF) + "."
             + ((ip >> 24) & 0xFF);
    }
}
