package com.packetanalyzer.pcap;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Reads libpcap (.pcap) files.
 * Mirrors the C++ {@code PacketAnalyzer::PcapReader} class.
 */
public class PcapReader implements Closeable {

    // ── PCAP magic numbers ───────────────────────────────────────────────────
    private static final long PCAP_MAGIC_NATIVE  = 0xa1b2c3d4L;
    private static final long PCAP_MAGIC_SWAPPED = 0xd4c3b2a1L;

    // ── State ────────────────────────────────────────────────────────────────
    private DataInputStream in;
    private boolean needsByteSwap = false;

    // Global header fields (public for the engine to inspect)
    public int  versionMajor;
    public int  versionMinor;
    public long snaplen;
    public long network;

    // ── Open / Close ─────────────────────────────────────────────────────────

    public boolean open(String filename) {
        try {
            in = new DataInputStream(new BufferedInputStream(new FileInputStream(filename)));
            return readGlobalHeader(filename);
        } catch (IOException e) {
            System.err.println("Error: Could not open file: " + filename + " — " + e.getMessage());
            return false;
        }
    }

    private boolean readGlobalHeader(String filename) throws IOException {
        // 24-byte global header
        byte[] hdr = new byte[24];
        if (in.read(hdr) != 24) {
            System.err.println("Error: Could not read PCAP global header");
            return false;
        }

        // Read magic as little-endian first (most pcap files are little-endian / native)
        long magic = ByteBuffer.wrap(hdr, 0, 4).order(ByteOrder.LITTLE_ENDIAN).getInt() & 0xFFFFFFFFL;

        if (magic == PCAP_MAGIC_NATIVE) {
            // File is little-endian (same as most x86 machines) — no swap needed
            needsByteSwap = false;
        } else if (magic == PCAP_MAGIC_SWAPPED) {
            // File is big-endian — we need to swap when reading
            needsByteSwap = true;
        } else {
            System.err.printf("Error: Invalid PCAP magic number: 0x%08X%n", magic);
            return false;
        }

        // Little-endian file → LITTLE_ENDIAN, big-endian file → BIG_ENDIAN
        ByteOrder order = needsByteSwap ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        ByteBuffer buf  = ByteBuffer.wrap(hdr).order(order);
        buf.position(4); // skip magic
        versionMajor = buf.getShort() & 0xFFFF;
        versionMinor = buf.getShort() & 0xFFFF;
        buf.getInt();    // thiszone (ignored)
        buf.getInt();    // sigfigs  (ignored)
        snaplen  = buf.getInt() & 0xFFFFFFFFL;
        network  = buf.getInt() & 0xFFFFFFFFL;

        System.out.println("Opened PCAP file: " + filename);
        System.out.println("  Version: " + versionMajor + "." + versionMinor);
        System.out.println("  Snaplen: " + snaplen + " bytes");
        System.out.println("  Link type: " + network + (network == 1 ? " (Ethernet)" : ""));
        return true;
    }

    @Override
    public void close() {
        if (in != null) {
            try { in.close(); } catch (IOException ignored) {}
            in = null;
        }
    }

    public boolean isOpen() { return in != null; }

    // ── Packet reading ────────────────────────────────────────────────────────

    /**
     * Reads the next packet from the file.
     * @return a {@link RawPacket}, or {@code null} at EOF.
     */
    public RawPacket readNextPacket() {
        if (in == null) return null;
        try {
            byte[] phdr = new byte[16];
            int read = 0;
            while (read < 16) {
                int r = in.read(phdr, read, 16 - read);
                if (r < 0) return null; // EOF
                read += r;
            }

            ByteOrder order = needsByteSwap ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
            ByteBuffer buf  = ByteBuffer.wrap(phdr).order(order);

            long tsSec   = buf.getInt() & 0xFFFFFFFFL;
            long tsUsec  = buf.getInt() & 0xFFFFFFFFL;
            long inclLen = buf.getInt() & 0xFFFFFFFFL;
            long origLen = buf.getInt() & 0xFFFFFFFFL;

            if (inclLen > snaplen || inclLen > 65535) {
                System.err.println("Error: Invalid packet length: " + inclLen);
                return null;
            }

            byte[] data = new byte[(int) inclLen];
            in.readFully(data);

            return new RawPacket(tsSec, tsUsec, origLen, data);
        } catch (EOFException e) {
            return null; // clean EOF
        } catch (IOException e) {
            System.err.println("Error reading packet: " + e.getMessage());
            return null;
        }
    }

    // ── Global header accessor ────────────────────────────────────────────────

    /** Write a 24-byte PCAP global header to the given stream (little-endian). */
    public void writeGlobalHeader(DataOutputStream out) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) PCAP_MAGIC_NATIVE);
        buf.putShort((short) versionMajor);
        buf.putShort((short) versionMinor);
        buf.putInt(0);  // thiszone
        buf.putInt(0);  // sigfigs
        buf.putInt((int) snaplen);
        buf.putInt((int) network);
        out.write(buf.array());
    }
}