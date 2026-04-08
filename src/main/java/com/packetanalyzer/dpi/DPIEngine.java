package com.packetanalyzer.dpi;

import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.parser.ParsedPacket;
import com.packetanalyzer.pcap.PcapReader;
import com.packetanalyzer.pcap.RawPacket;
import com.packetanalyzer.rules.RuleManager;
import com.packetanalyzer.tracker.ConnectionTracker;
import com.packetanalyzer.types.*;
import com.packetanalyzer.types.Connection.DPIStats;
import com.packetanalyzer.types.Connection.PacketJob;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Main DPI engine orchestrator.
 *
 * Architecture:
 *   PcapReader ──► LB threads ──► FP threads ──► OutputQueue ──► PCAP writer
 *
 * Mirrors the C++ {@code DPI::DPIEngine} class.
 */
public class DPIEngine {

    // ── Configuration ─────────────────────────────────────────────────────────

    public static class Config {
        public int    numLoadBalancers = 2;
        public int    fpsPerLb        = 2;
        public int    queueSize       = 10_000;
        public String rulesFile       = "";
        public boolean verbose        = false;
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final Config   config;
    private RuleManager    ruleManager;

    private List<FastPathProcessor> fps = new ArrayList<>();
    private List<LoadBalancer>      lbs = new ArrayList<>();

    private final PacketQueue<PacketJob> outputQueue = new PacketQueue<>(10_000);

    private final DPIStats       stats      = new DPIStats();
    private final AtomicBoolean  running    = new AtomicBoolean(false);

    private Thread outputThread;
    private Thread readerThread;

    private DataOutputStream outputStream;
    private final Object     outputLock = new Object();

    // ── Constructor ───────────────────────────────────────────────────────────

    public DPIEngine(Config config) {
        this.config = config;
        printBanner();
    }

    private void printBanner() {
        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0                            ║");
        System.out.println("║               Deep Packet Inspection System                   ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ Configuration:                                                ║");
        System.out.printf( "║   Load Balancers:    %3d                                       ║%n", config.numLoadBalancers);
        System.out.printf( "║   FPs per LB:        %3d                                       ║%n", config.fpsPerLb);
        System.out.printf( "║   Total FP threads:  %3d                                       ║%n", config.numLoadBalancers * config.fpsPerLb);
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    // ── Initialization ────────────────────────────────────────────────────────

    public boolean initialize() {
        ruleManager = new RuleManager();
        if (!config.rulesFile.isEmpty()) ruleManager.loadRules(config.rulesFile);

        int totalFps = config.numLoadBalancers * config.fpsPerLb;

        // Create FP processors
        for (int i = 0; i < totalFps; i++) {
            fps.add(new FastPathProcessor(i, ruleManager, this::handleOutput));
        }

        // Create LBs, each assigned a slice of FP queues
        for (int lb = 0; lb < config.numLoadBalancers; lb++) {
            List<PacketQueue<PacketJob>> queues = new ArrayList<>();
            for (int f = 0; f < config.fpsPerLb; f++) {
                queues.add(fps.get(lb * config.fpsPerLb + f).inputQueue);
            }
            lbs.add(new LoadBalancer(lb, queues, lb * config.fpsPerLb));
        }

        System.out.println("[DPIEngine] Initialized successfully");
        return true;
    }

    // ── Start / Stop ──────────────────────────────────────────────────────────

    public void start() {
        if (running.get()) return;
        running.set(true);

        outputThread = new Thread(this::outputThreadFunc, "Output-Writer");
        outputThread.setDaemon(true);
        outputThread.start();

        fps.forEach(FastPathProcessor::start);
        lbs.forEach(LoadBalancer::start);

        System.out.println("[DPIEngine] All threads started");
    }

    public void stop() {
        if (!running.get()) return;
        running.set(false);

        lbs.forEach(LoadBalancer::stop);
        fps.forEach(FastPathProcessor::stop);

        outputQueue.shutdown();
        if (outputThread != null) {
            try { outputThread.join(3000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        System.out.println("[DPIEngine] All threads stopped");
    }

    // ── Process file ──────────────────────────────────────────────────────────

    public boolean processFile(String inputFile, String outputFile) {
        System.out.println("\n[DPIEngine] Processing: " + inputFile);
        System.out.println("[DPIEngine] Output to:  " + outputFile + "\n");

        if (ruleManager == null && !initialize()) return false;

        try {
            outputStream = new DataOutputStream(
                new BufferedOutputStream(new FileOutputStream(outputFile)));
        } catch (IOException e) {
            System.err.println("[DPIEngine] Cannot open output file: " + e.getMessage());
            return false;
        }

        start();

        // Run reader on current thread (or a dedicated thread)
        readerThread = new Thread(() -> readerThreadFunc(inputFile), "PCAP-Reader");
        readerThread.start();

        try { readerThread.join(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }

        // Let queues drain
        try { Thread.sleep(500); } catch (InterruptedException ignored) {}

        stop();

        try { outputStream.close(); } catch (IOException ignored) {}

        System.out.println(generateReport());
        System.out.println(generateClassificationReport());
        return true;
    }

    // ── Reader thread ─────────────────────────────────────────────────────────

    private void readerThreadFunc(String inputFile) {
        PcapReader reader = new PcapReader();
        if (!reader.open(inputFile)) {
            System.err.println("[Reader] Cannot open input file");
            return;
        }

        // Write output PCAP global header
        writeOutputHeader(reader);

        int packetId = 0;
        System.out.println("[Reader] Starting packet processing...");

        RawPacket raw;
        while ((raw = reader.readNextPacket()) != null) {
            ParsedPacket parsed = PacketParser.parse(raw);
            if (parsed == null) continue;
            if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;

            PacketJob job = createPacketJob(raw, parsed, packetId++);

            stats.totalPackets.incrementAndGet();
            stats.totalBytes.addAndGet(raw.data.length);
            if (parsed.hasTcp)       stats.tcpPackets.incrementAndGet();
            else if (parsed.hasUdp)  stats.udpPackets.incrementAndGet();

            // Route to appropriate LB
            LoadBalancer lb = selectLB(job.tuple);
            lb.inputQueue.push(job);
        }

        System.out.println("[Reader] Finished reading " + packetId + " packets");
        reader.close();
    }

    private LoadBalancer selectLB(FiveTuple tuple) {
        return lbs.get(Math.abs(tuple.hashCode()) % lbs.size());
    }

    // ── PacketJob factory ─────────────────────────────────────────────────────

    private PacketJob createPacketJob(RawPacket raw, ParsedPacket parsed, int packetId) {
        PacketJob job = new PacketJob();
        job.packetId = packetId;
        job.tsSec    = raw.tsSec;
        job.tsUsec   = raw.tsUsec;
        job.data     = raw.data;

        // Build five-tuple from parsed IPs (stored as dotted-decimal strings)
        job.tuple = new FiveTuple(
            RuleManager.parseIP(parsed.srcIp),
            RuleManager.parseIP(parsed.destIp),
            parsed.srcPort,
            parsed.destPort,
            parsed.protocol
        );

        job.tcpFlags       = parsed.tcpFlags;
        job.ethOffset      = 0;
        job.ipOffset       = 14;

        int ipHdrLen = ((raw.data.length > 14) ? ((raw.data[14] & 0x0F) * 4) : 20);
        job.transportOffset = 14 + ipHdrLen;

        if (parsed.hasTcp && raw.data.length > job.transportOffset + 12) {
            int tcpHdrLen = ((raw.data[job.transportOffset + 12] & 0xFF) >> 4) * 4;
            job.payloadOffset = job.transportOffset + tcpHdrLen;
        } else if (parsed.hasUdp) {
            job.payloadOffset = job.transportOffset + 8;
        } else {
            job.payloadOffset = job.transportOffset;
        }

        if (job.payloadOffset < raw.data.length) {
            job.payloadLength = raw.data.length - job.payloadOffset;
            job.payloadData   = Arrays.copyOfRange(raw.data, job.payloadOffset, raw.data.length);
        }

        return job;
    }

    // ── Output handling ───────────────────────────────────────────────────────

    private void handleOutput(PacketJob job, PacketAction action) {
        if (action == PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }
        stats.forwardedPackets.incrementAndGet();
        outputQueue.push(job);
    }

    private void outputThreadFunc() {
        while (running.get() || !outputQueue.isEmpty()) {
            PacketJob job = outputQueue.poll(100);
            if (job != null) writeOutputPacket(job);
        }
    }

    private void writeOutputHeader(PcapReader reader) {
        synchronized (outputLock) {
            try { reader.writeGlobalHeader(outputStream); }
            catch (IOException e) { System.err.println("[Output] Header write error: " + e.getMessage()); }
        }
    }

    private void writeOutputPacket(PacketJob job) {
        synchronized (outputLock) {
            try {
                // 16-byte packet header (little-endian)
                ByteBuffer hdr = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
                hdr.putInt((int) job.tsSec);
                hdr.putInt((int) job.tsUsec);
                hdr.putInt(job.data.length);
                hdr.putInt(job.data.length);
                outputStream.write(hdr.array());
                outputStream.write(job.data);
            } catch (IOException e) {
                System.err.println("[Output] Packet write error: " + e.getMessage());
            }
        }
    }

    // ── Rule management API ───────────────────────────────────────────────────

    public void blockIP(String ip)       { if (ruleManager != null) ruleManager.blockIP(ip); }
    public void unblockIP(String ip)     { if (ruleManager != null) ruleManager.unblockIP(ip); }
    public void blockApp(AppType app)    { if (ruleManager != null) ruleManager.blockApp(app); }
    public void unblockApp(AppType app)  { if (ruleManager != null) ruleManager.unblockApp(app); }
    public void blockDomain(String d)    { if (ruleManager != null) ruleManager.blockDomain(d); }
    public void unblockDomain(String d)  { if (ruleManager != null) ruleManager.unblockDomain(d); }
    public boolean loadRules(String f)   { return ruleManager != null && ruleManager.loadRules(f); }
    public boolean saveRules(String f)   { return ruleManager != null && ruleManager.saveRules(f); }

    // ── Reporting ─────────────────────────────────────────────────────────────

    public String generateReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append(  "║                    DPI ENGINE STATISTICS                      ║\n");
        sb.append(  "╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(  "║ PACKET STATISTICS                                             ║\n");
        sb.append(String.format("║   Total Packets:      %12d                        ║%n", stats.totalPackets.get()));
        sb.append(String.format("║   Total Bytes:        %12d                        ║%n", stats.totalBytes.get()));
        sb.append(String.format("║   TCP Packets:        %12d                        ║%n", stats.tcpPackets.get()));
        sb.append(String.format("║   UDP Packets:        %12d                        ║%n", stats.udpPackets.get()));
        sb.append(  "╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(  "║ FILTERING STATISTICS                                          ║\n");
        sb.append(String.format("║   Forwarded:          %12d                        ║%n", stats.forwardedPackets.get()));
        sb.append(String.format("║   Dropped/Blocked:    %12d                        ║%n", stats.droppedPackets.get()));

        long total = stats.totalPackets.get();
        if (total > 0) {
            double dropRate = 100.0 * stats.droppedPackets.get() / total;
            sb.append(String.format("║   Drop Rate:          %11.2f%%                        ║%n", dropRate));
        }

        if (ruleManager != null) {
            RuleManager.RuleStats rs = ruleManager.getStats();
            sb.append(  "╠══════════════════════════════════════════════════════════════╣\n");
            sb.append(  "║ BLOCKING RULES                                                ║\n");
            sb.append(String.format("║   Blocked IPs:        %12d                        ║%n", rs.blockedIps));
            sb.append(String.format("║   Blocked Apps:       %12d                        ║%n", rs.blockedApps));
            sb.append(String.format("║   Blocked Domains:    %12d                        ║%n", rs.blockedDomains));
            sb.append(String.format("║   Blocked Ports:      %12d                        ║%n", rs.blockedPorts));
        }
        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }

    public String generateClassificationReport() {
        Map<AppType, Long> appCounts = new HashMap<>();
        Map<String, Long>  snCounts  = new HashMap<>();
        long totalClassified = 0, totalUnknown = 0;

        for (FastPathProcessor fp : fps) {
            ConnectionTracker ct = fp.getConnectionTracker();
            for (Connection conn : ct.getAllConnections()) {
                appCounts.merge(conn.appType, 1L, Long::sum);
                if (conn.appType == AppType.UNKNOWN) totalUnknown++;
                else totalClassified++;
                if (!conn.sni.isEmpty()) snCounts.merge(conn.sni, 1L, Long::sum);
            }
        }

        long total = totalClassified + totalUnknown;
        double classifiedPct = total > 0 ? 100.0 * totalClassified / total : 0;

        StringBuilder sb = new StringBuilder();
        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append(  "║                 APPLICATION CLASSIFICATION REPORT             ║\n");
        sb.append(  "╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(String.format("║ Total Connections:    %10d                           ║%n", total));
        sb.append(String.format("║ Classified:           %10d (%.1f%%)                  ║%n", totalClassified, classifiedPct));
        sb.append(String.format("║ Unidentified:         %10d (%.1f%%)                  ║%n", totalUnknown, 100.0 - classifiedPct));
        sb.append(  "╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(  "║                    APPLICATION DISTRIBUTION                   ║\n");
        sb.append(  "╠══════════════════════════════════════════════════════════════╣\n");

        appCounts.entrySet().stream()
            .sorted(Map.Entry.<AppType, Long>comparingByValue().reversed())
            .forEach(e -> {
                double pct = total > 0 ? 100.0 * e.getValue() / total : 0;
                int barLen = (int)(pct / 5);
                String bar = "#".repeat(Math.max(0, barLen));
                sb.append(String.format("║ %-15s %8d %5.1f%% %-20s   ║%n",
                    AppType.toString(e.getKey()), e.getValue(), pct, bar));
            });

        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }

    public DPIStats getStats() { return stats; }
}
