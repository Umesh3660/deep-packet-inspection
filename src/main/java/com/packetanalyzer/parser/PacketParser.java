package com.packetanalyzer.parser;

import com.packetanalyzer.pcap.RawPacket;

/**
 * Parses raw packet bytes into a human-readable {@link ParsedPacket}.
 * Mirrors the C++ {@code PacketAnalyzer::PacketParser} class.
 */
public class PacketParser {

    // ── EtherType constants ───────────────────────────────────────────────────
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP  = 0x0806;

    // ── Protocol constants ────────────────────────────────────────────────────
    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP  = 6;
    public static final int PROTO_UDP  = 17;

    // ── TCP flag constants ────────────────────────────────────────────────────
    public static final int FLAG_FIN = 0x01;
    public static final int FLAG_SYN = 0x02;
    public static final int FLAG_RST = 0x04;
    public static final int FLAG_PSH = 0x08;
    public static final int FLAG_ACK = 0x10;
    public static final int FLAG_URG = 0x20;

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Parse a raw packet.
     * @return a populated {@link ParsedPacket}, or {@code null} on failure.
     */
    public static ParsedPacket parse(RawPacket raw) {
        ParsedPacket p = new ParsedPacket();
        p.tsSec  = raw.tsSec;
        p.tsUsec = raw.tsUsec;

        byte[] data = raw.data;
        int    len  = data.length;
        int[]  off  = {0};   // mutable offset, passed as single-element array

        if (!parseEthernet(data, len, p, off)) return null;

        if (p.etherType == ETHERTYPE_IPV4) {
            if (!parseIPv4(data, len, p, off)) return null;

            if (p.protocol == PROTO_TCP) {
                if (!parseTCP(data, len, p, off)) return null;
            } else if (p.protocol == PROTO_UDP) {
                if (!parseUDP(data, len, p, off)) return null;
            }
        }

        if (off[0] < len) {
            p.payloadLength = len - off[0];
            p.payloadOffset = off[0];
            // Slice payload bytes
            p.payloadData = new byte[p.payloadLength];
            System.arraycopy(data, off[0], p.payloadData, 0, p.payloadLength);
        }

        return p;
    }

    // ── Layer parsers ─────────────────────────────────────────────────────────

    private static boolean parseEthernet(byte[] data, int len, ParsedPacket p, int[] off) {
        if (len < 14) return false;

        p.destMac  = macToString(data, 0);
        p.srcMac   = macToString(data, 6);
        p.etherType = readUint16BE(data, 12);

        off[0] = 14;
        return true;
    }

    private static boolean parseIPv4(byte[] data, int len, ParsedPacket p, int[] off) {
        int base = off[0];
        if (len < base + 20) return false;

        int versionIhl = data[base] & 0xFF;
        p.ipVersion    = (versionIhl >> 4) & 0x0F;
        int ihl        = versionIhl & 0x0F;

        if (p.ipVersion != 4) return false;

        int ipHdrLen = ihl * 4;
        if (ipHdrLen < 20 || len < base + ipHdrLen) return false;

        p.ttl      = data[base + 8] & 0xFF;
        p.protocol = data[base + 9] & 0xFF;

        p.srcIp  = ipToString(data, base + 12);
        p.destIp = ipToString(data, base + 16);

        p.hasIp = true;
        off[0]  = base + ipHdrLen;
        return true;
    }

    private static boolean parseTCP(byte[] data, int len, ParsedPacket p, int[] off) {
        int base = off[0];
        if (len < base + 20) return false;

        p.srcPort  = readUint16BE(data, base);
        p.destPort = readUint16BE(data, base + 2);
        p.seqNumber = readUint32BE(data, base + 4);
        p.ackNumber = readUint32BE(data, base + 8);

        int dataOffset  = (data[base + 12] & 0xFF) >> 4;
        int tcpHdrLen   = dataOffset * 4;
        p.tcpFlags      = data[base + 13] & 0xFF;

        if (tcpHdrLen < 20 || len < base + tcpHdrLen) return false;

        p.hasTcp = true;
        off[0]   = base + tcpHdrLen;
        return true;
    }

    private static boolean parseUDP(byte[] data, int len, ParsedPacket p, int[] off) {
        int base = off[0];
        if (len < base + 8) return false;

        p.srcPort  = readUint16BE(data, base);
        p.destPort = readUint16BE(data, base + 2);

        p.hasUdp = true;
        off[0]   = base + 8;
        return true;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    public static String macToString(byte[] data, int off) {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", data[off + i] & 0xFF));
        }
        return sb.toString();
    }

    public static String ipToString(byte[] data, int off) {
        return (data[off]   & 0xFF) + "."
             + (data[off+1] & 0xFF) + "."
             + (data[off+2] & 0xFF) + "."
             + (data[off+3] & 0xFF);
    }

    public static String protocolToString(int protocol) {
        switch (protocol) {
            case PROTO_ICMP: return "ICMP";
            case PROTO_TCP:  return "TCP";
            case PROTO_UDP:  return "UDP";
            default:         return "Unknown(" + protocol + ")";
        }
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & FLAG_SYN) != 0) sb.append("SYN ");
        if ((flags & FLAG_ACK) != 0) sb.append("ACK ");
        if ((flags & FLAG_FIN) != 0) sb.append("FIN ");
        if ((flags & FLAG_RST) != 0) sb.append("RST ");
        if ((flags & FLAG_PSH) != 0) sb.append("PSH ");
        if ((flags & FLAG_URG) != 0) sb.append("URG ");
        String s = sb.toString().trim();
        return s.isEmpty() ? "none" : s;
    }

    // ── Byte-order helpers ────────────────────────────────────────────────────

    public static int readUint16BE(byte[] data, int off) {
        return ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF);
    }

    public static long readUint32BE(byte[] data, int off) {
        return ((long)(data[off]   & 0xFF) << 24)
             | ((long)(data[off+1] & 0xFF) << 16)
             | ((long)(data[off+2] & 0xFF) << 8)
             |  (long)(data[off+3] & 0xFF);
    }
}
