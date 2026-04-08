# Packet Analyzer — Java Port

A complete Java port of the C++ `Packet_analyzer` project.

## Project Structure

```
src/main/java/com/packetanalyzer/
├── Main.java                          ← CLI entry point (mirrors main.cpp)
├── pcap/
│   ├── PcapReader.java                ← Reads .pcap files
│   └── RawPacket.java                 ← Raw packet data holder
├── parser/
│   ├── PacketParser.java              ← Parses Ethernet/IP/TCP/UDP headers
│   └── ParsedPacket.java              ← Human-readable parsed packet
├── types/
│   ├── AppType.java                   ← Application enum + SNI→App mapping
│   ├── FiveTuple.java                 ← 5-tuple (src/dst IP, port, proto)
│   ├── Connection.java                ← Connection state, DPIStats, PacketJob
│   ├── ConnectionState.java           ← NEW / ESTABLISHED / CLASSIFIED / …
│   └── PacketAction.java              ← FORWARD / DROP / INSPECT / LOG_ONLY
├── extractor/
│   ├── SNIExtractor.java              ← TLS Client Hello → SNI hostname
│   ├── HTTPHostExtractorPublic.java   ← HTTP Host header extraction
│   └── DNSExtractorPublic.java        ← DNS query domain extraction
├── tracker/
│   └── ConnectionTracker.java         ← Per-FP flow table
├── rules/
│   └── RuleManager.java               ← IP / App / Domain / Port blocking rules
└── dpi/
    ├── PacketQueue.java               ← Bounded blocking queue (thread-safe)
    ├── FastPathProcessor.java         ← Per-FP DPI + rule-check worker thread
    ├── LoadBalancer.java              ← Hash-based LB dispatching to FP threads
    └── DPIEngine.java                 ← Main orchestrator (full pipeline)
```

## Building

Requires **Java 17+** and **Maven 3.6+**.

```bash
cd PacketAnalyzerJava
mvn package -q
```

This produces `target/packet-analyzer-1.0.0.jar`.

## Running

### Packet Viewer Mode (mirrors `main.cpp`)

Prints a detailed human-readable dump of each packet:

```bash
java -jar target/packet-analyzer-1.0.0.jar capture.pcap
java -jar target/packet-analyzer-1.0.0.jar capture.pcap 10   # first 10 packets
```

### DPI Engine Mode (mirrors `main_dpi.cpp`)

Reads an input PCAP, applies DPI + blocking rules, writes allowed packets to an output PCAP:

```java
// In your own code:
DPIEngine.Config cfg = new DPIEngine.Config();
cfg.numLoadBalancers = 2;
cfg.fpsPerLb = 2;

DPIEngine engine = new DPIEngine(cfg);
engine.initialize();

engine.blockApp(AppType.YOUTUBE);
engine.blockApp(AppType.TIKTOK);
engine.blockDomain("*.facebook.com");
engine.blockIP("1.2.3.4");
engine.blockPort(6881);  // BitTorrent

engine.processFile("input.pcap", "output.pcap");
```

Or call `Main.runDPIEngine(args)` with `--dpi input.pcap output.pcap [rules.txt]`.

