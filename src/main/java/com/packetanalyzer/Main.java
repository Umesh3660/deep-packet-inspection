package com.packetanalyzer;

import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.parser.ParsedPacket;
import com.packetanalyzer.pcap.PcapReader;
import com.packetanalyzer.pcap.RawPacket;

import java.time.*;
import java.time.format.DateTimeFormatter;
import com.packetanalyzer.dpi.DPIEngine;
import com.packetanalyzer.types.AppType;

/**
 * Command-line entry point: reads a PCAP file and prints a human-readable
 * summary of each packet (Ethernet / IP / TCP / UDP / Payload preview).
 *
 * Mirrors the C++ {@code main.cpp}.
 *
 * Usage:
 *   java -jar packet-analyzer.jar &lt;pcap_file&gt; [max_packets]
 */
public class Main {

    private static final DateTimeFormatter TS_FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static void main(String[] args) {

        String inputFile  = "C:\\Users\\LENOVO\\Downloads\\Packet_analyzer-main\\Packet_analyzer-main\\output.pcap";
        String outputFile = "C:\\Users\\LENOVO\\Downloads\\filtered_output.pcap";

        DPIEngine.Config cfg = new DPIEngine.Config();
        cfg.numLoadBalancers = 2;
        cfg.fpsPerLb = 2;

        DPIEngine engine = new DPIEngine(cfg);
        engine.initialize();

        // Block by app
        engine.blockApp(AppType.YOUTUBE);
        engine.blockApp(AppType.TIKTOK);
        engine.blockApp(AppType.FACEBOOK);
        engine.blockApp(AppType.INSTAGRAM);
        engine.blockApp(AppType.TWITTER);

        // Block by domain
        engine.blockDomain("*.facebook.com");
        engine.blockDomain("*.youtube.com");
        engine.blockDomain("*.twitter.com");

        // Block by IP
        engine.blockIP("157.240.1.35");    // Facebook
        engine.blockIP("157.240.1.174");   // Facebook/Instagram
        engine.blockIP("104.244.42.65");   // Twitter

        // Process
        engine.processFile(inputFile, outputFile);
    }

    // ── Packet printer ────────────────────────────────────────────────────────

    private static void printPacketSummary(ParsedPacket pkt, int num) {
        // Timestamp
        Instant instant = Instant.ofEpochSecond(pkt.tsSec, pkt.tsUsec * 1000L);
        String  ts      = TS_FMT.format(instant.atZone(ZoneId.systemDefault()));

        System.out.println("\n========== Packet #" + num + " ==========");
        System.out.printf("Time: %s.%06d%n", ts, pkt.tsUsec);

        // Ethernet
        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + pkt.srcMac);
        System.out.println("  Destination MAC: " + pkt.destMac);
        System.out.printf( "  EtherType:       0x%04X%s%n",
            pkt.etherType,
            pkt.etherType == PacketParser.ETHERTYPE_IPV4 ? " (IPv4)"
          : pkt.etherType == PacketParser.ETHERTYPE_IPV6 ? " (IPv6)"
          : pkt.etherType == PacketParser.ETHERTYPE_ARP  ? " (ARP)" : "");

        // IP
        if (pkt.hasIp) {
            System.out.println("\n[IPv" + pkt.ipVersion + "]");
            System.out.println("  Source IP:      " + pkt.srcIp);
            System.out.println("  Destination IP: " + pkt.destIp);
            System.out.println("  Protocol:       " + PacketParser.protocolToString(pkt.protocol));
            System.out.println("  TTL:            " + pkt.ttl);
        }

        // TCP
        if (pkt.hasTcp) {
            System.out.println("\n[TCP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
            System.out.println("  Sequence Number:  " + pkt.seqNumber);
            System.out.println("  Ack Number:       " + pkt.ackNumber);
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(pkt.tcpFlags));
        }

        // UDP
        if (pkt.hasUdp) {
            System.out.println("\n[UDP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
        }

        // Payload preview
        if (pkt.payloadLength > 0 && pkt.payloadData != null) {
            System.out.println("\n[Payload]");
            System.out.println("  Length: " + pkt.payloadLength + " bytes");
            int previewLen = Math.min(pkt.payloadLength, 32);
            System.out.print("  Preview: ");
            for (int i = 0; i < previewLen; i++) {
                System.out.printf("%02x ", pkt.payloadData[i] & 0xFF);
            }
            if (pkt.payloadLength > 32) System.out.print("...");
            System.out.println();
        }
    }

    // ── DPI engine entry point ────────────────────────────────────────────────

    /**
     * Alternative main that runs the full DPI engine pipeline.
     *
     * Usage: java -cp ... com.packetanalyzer.Main --dpi &lt;input.pcap&gt; &lt;output.pcap&gt; [rules.txt]
     */
    public static void runDPIEngine(String[] args) {
        if (args.length < 3) {
            System.err.println("DPI usage: --dpi <input.pcap> <output.pcap> [rules_file]");
            System.exit(1);
        }

        String inputFile  = args[1];
        String outputFile = args[2];
        String rulesFile  = args.length >= 4 ? args[3] : "";

        com.packetanalyzer.dpi.DPIEngine.Config cfg = new com.packetanalyzer.dpi.DPIEngine.Config();
        cfg.rulesFile = rulesFile;

        com.packetanalyzer.dpi.DPIEngine engine = new com.packetanalyzer.dpi.DPIEngine(cfg);

        // Example: block YouTube and TikTok
        engine.initialize();
        engine.blockApp(com.packetanalyzer.types.AppType.YOUTUBE);
        engine.blockApp(com.packetanalyzer.types.AppType.TIKTOK);
        engine.blockDomain("*.facebook.com");

        engine.processFile(inputFile, outputFile);
    }

    private static void printUsage() {
        System.out.println("Usage: java -jar packet-analyzer.jar <pcap_file> [max_packets]");
        System.out.println("\nArguments:");
        System.out.println("  pcap_file   - Path to a .pcap file");
        System.out.println("  max_packets - (Optional) Maximum packets to display");
        System.out.println("\nExamples:");
        System.out.println("  java -jar packet-analyzer.jar capture.pcap");
        System.out.println("  java -jar packet-analyzer.jar capture.pcap 10");
        System.out.println("\nFor DPI engine mode:");
        System.out.println("  Call Main.runDPIEngine(new String[]{\"--dpi\", \"in.pcap\", \"out.pcap\"})");
    }
}
