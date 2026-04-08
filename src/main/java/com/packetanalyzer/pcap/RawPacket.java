package com.packetanalyzer.pcap;

/**
 * Holds the raw bytes of a single captured packet together with its
 * per-packet PCAP header fields.
 *
 * Mirrors the C++ {@code PacketAnalyzer::RawPacket} struct.
 */
public class RawPacket {
    public final long   tsSec;    // timestamp seconds
    public final long   tsUsec;   // timestamp microseconds
    public final long   origLen;  // original length on the wire
    public final byte[] data;     // captured bytes

    public RawPacket(long tsSec, long tsUsec, long origLen, byte[] data) {
        this.tsSec   = tsSec;
        this.tsUsec  = tsUsec;
        this.origLen = origLen;
        this.data    = data;
    }
}
