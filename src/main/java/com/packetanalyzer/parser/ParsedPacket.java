package com.packetanalyzer.parser;

/**
 * Human-readable representation of a parsed network packet.
 * Mirrors the C++ {@code PacketAnalyzer::ParsedPacket} struct.
 */
public class ParsedPacket {

    // Timestamps
    public long tsSec;
    public long tsUsec;

    // Ethernet layer
    public String srcMac  = "";
    public String destMac = "";
    public int    etherType;

    // IP layer
    public boolean hasIp      = false;
    public int     ipVersion;
    public String  srcIp      = "";
    public String  destIp     = "";
    public int     protocol;   // TCP=6, UDP=17, ICMP=1
    public int     ttl;

    // Transport layer
    public boolean hasTcp = false;
    public boolean hasUdp = false;
    public int     srcPort;
    public int     destPort;

    // TCP-specific
    public int  tcpFlags;
    public long seqNumber;
    public long ackNumber;

    // Payload
    public int    payloadLength = 0;
    public byte[] payloadData   = null;
    public int    payloadOffset = 0;   // offset into the original raw data array
}
