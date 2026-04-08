package com.packetanalyzer.rules;

import com.packetanalyzer.types.AppType;
import com.packetanalyzer.types.FiveTuple;

import java.io.*;
import java.util.*;
import java.util.concurrent.locks.*;

/**
 * Manages blocking/filtering rules for IP addresses, applications,
 * domains, and ports. All operations are thread-safe.
 *
 * Mirrors the C++ {@code DPI::RuleManager} class.
 */
public class RuleManager {

    // ── Storage ───────────────────────────────────────────────────────────────
    private final ReadWriteLock ipLock     = new ReentrantReadWriteLock();
    private final Set<Long>     blockedIps = new HashSet<>();

    private final ReadWriteLock  appLock     = new ReentrantReadWriteLock();
    private final Set<AppType>   blockedApps = new HashSet<>();

    private final ReadWriteLock  domainLock     = new ReentrantReadWriteLock();
    private final Set<String>    blockedDomains = new HashSet<>();
    private final List<String>   domainPatterns = new ArrayList<>();

    private final ReadWriteLock  portLock     = new ReentrantReadWriteLock();
    private final Set<Integer>   blockedPorts = new HashSet<>();

    // ── IP blocking ───────────────────────────────────────────────────────────

    public void blockIP(long ip) {
        ipLock.writeLock().lock();
        try { blockedIps.add(ip); }
        finally { ipLock.writeLock().unlock(); }
        System.out.println("[RuleManager] Blocked IP: " + FiveTuple.ipToString(ip));
    }

    public void blockIP(String ip) { blockIP(parseIP(ip)); }

    public void unblockIP(long ip) {
        ipLock.writeLock().lock();
        try { blockedIps.remove(ip); }
        finally { ipLock.writeLock().unlock(); }
        System.out.println("[RuleManager] Unblocked IP: " + FiveTuple.ipToString(ip));
    }

    public void unblockIP(String ip) { unblockIP(parseIP(ip)); }

    public boolean isIPBlocked(long ip) {
        ipLock.readLock().lock();
        try { return blockedIps.contains(ip); }
        finally { ipLock.readLock().unlock(); }
    }

    public List<String> getBlockedIPs() {
        ipLock.readLock().lock();
        try {
            List<String> result = new ArrayList<>();
            for (long ip : blockedIps) result.add(FiveTuple.ipToString(ip));
            return result;
        } finally { ipLock.readLock().unlock(); }
    }

    // ── App blocking ──────────────────────────────────────────────────────────

    public void blockApp(AppType app) {
        appLock.writeLock().lock();
        try { blockedApps.add(app); }
        finally { appLock.writeLock().unlock(); }
        System.out.println("[RuleManager] Blocked app: " + AppType.toString(app));
    }

    public void unblockApp(AppType app) {
        appLock.writeLock().lock();
        try { blockedApps.remove(app); }
        finally { appLock.writeLock().unlock(); }
        System.out.println("[RuleManager] Unblocked app: " + AppType.toString(app));
    }

    public boolean isAppBlocked(AppType app) {
        appLock.readLock().lock();
        try { return blockedApps.contains(app); }
        finally { appLock.readLock().unlock(); }
    }

    public List<AppType> getBlockedApps() {
        appLock.readLock().lock();
        try { return new ArrayList<>(blockedApps); }
        finally { appLock.readLock().unlock(); }
    }

    // ── Domain blocking ───────────────────────────────────────────────────────

    public void blockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) domainPatterns.add(domain);
            else                       blockedDomains.add(domain);
        } finally { domainLock.writeLock().unlock(); }
        System.out.println("[RuleManager] Blocked domain: " + domain);
    }

    public void unblockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) domainPatterns.remove(domain);
            else                       blockedDomains.remove(domain);
        } finally { domainLock.writeLock().unlock(); }
        System.out.println("[RuleManager] Unblocked domain: " + domain);
    }

    public boolean isDomainBlocked(String domain) {
        domainLock.readLock().lock();
        try {
            if (blockedDomains.contains(domain)) return true;
            String lower = domain.toLowerCase();
            for (String pattern : domainPatterns) {
                if (domainMatchesPattern(lower, pattern.toLowerCase())) return true;
            }
            return false;
        } finally { domainLock.readLock().unlock(); }
    }

    public List<String> getBlockedDomains() {
        domainLock.readLock().lock();
        try {
            List<String> result = new ArrayList<>(blockedDomains);
            result.addAll(domainPatterns);
            return result;
        } finally { domainLock.readLock().unlock(); }
    }

    // ── Port blocking ─────────────────────────────────────────────────────────

    public void blockPort(int port) {
        portLock.writeLock().lock();
        try { blockedPorts.add(port); }
        finally { portLock.writeLock().unlock(); }
        System.out.println("[RuleManager] Blocked port: " + port);
    }

    public void unblockPort(int port) {
        portLock.writeLock().lock();
        try { blockedPorts.remove(port); }
        finally { portLock.writeLock().unlock(); }
    }

    public boolean isPortBlocked(int port) {
        portLock.readLock().lock();
        try { return blockedPorts.contains(port); }
        finally { portLock.readLock().unlock(); }
    }

    // ── Combined check ────────────────────────────────────────────────────────

    public enum BlockType { IP, APP, DOMAIN, PORT }

    public static class BlockReason {
        public final BlockType type;
        public final String    detail;
        BlockReason(BlockType type, String detail) {
            this.type   = type;
            this.detail = detail;
        }
    }

    /**
     * Returns a {@link BlockReason} if the packet should be blocked,
     * or {@code null} if it should be forwarded.
     */
    public BlockReason shouldBlock(long srcIp, int dstPort, AppType app, String domain) {
        if (isIPBlocked(srcIp))
            return new BlockReason(BlockType.IP,     FiveTuple.ipToString(srcIp));
        if (isPortBlocked(dstPort))
            return new BlockReason(BlockType.PORT,   String.valueOf(dstPort));
        if (isAppBlocked(app))
            return new BlockReason(BlockType.APP,    AppType.toString(app));
        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain))
            return new BlockReason(BlockType.DOMAIN, domain);
        return null;
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    public boolean saveRules(String filename) {
        try (PrintWriter w = new PrintWriter(new FileWriter(filename))) {
            w.println("[BLOCKED_IPS]");
            for (String ip : getBlockedIPs()) w.println(ip);

            w.println("\n[BLOCKED_APPS]");
            for (AppType app : getBlockedApps()) w.println(AppType.toString(app));

            w.println("\n[BLOCKED_DOMAINS]");
            for (String d : getBlockedDomains()) w.println(d);

            w.println("\n[BLOCKED_PORTS]");
            portLock.readLock().lock();
            try { for (int p : blockedPorts) w.println(p); }
            finally { portLock.readLock().unlock(); }

            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Error saving rules: " + e.getMessage());
            return false;
        }
    }

    public boolean loadRules(String filename) {
        try (BufferedReader r = new BufferedReader(new FileReader(filename))) {
            String line;
            String section = "";
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                if (line.startsWith("[")) { section = line; continue; }

                switch (section) {
                    case "[BLOCKED_IPS]":     blockIP(line);     break;
                    case "[BLOCKED_APPS]":
                        AppType app = AppType.fromString(line);
                        if (app != AppType.UNKNOWN) blockApp(app);
                        break;
                    case "[BLOCKED_DOMAINS]": blockDomain(line); break;
                    case "[BLOCKED_PORTS]":
                        try { blockPort(Integer.parseInt(line)); } catch (NumberFormatException ignored) {}
                        break;
                }
            }
            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Error loading rules: " + e.getMessage());
            return false;
        }
    }

    public void clearAll() {
        ipLock.writeLock().lock();     try { blockedIps.clear();     } finally { ipLock.writeLock().unlock(); }
        appLock.writeLock().lock();    try { blockedApps.clear();    } finally { appLock.writeLock().unlock(); }
        domainLock.writeLock().lock(); try { blockedDomains.clear(); domainPatterns.clear(); } finally { domainLock.writeLock().unlock(); }
        portLock.writeLock().lock();   try { blockedPorts.clear();   } finally { portLock.writeLock().unlock(); }
        System.out.println("[RuleManager] All rules cleared");
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    public static class RuleStats {
        public final int blockedIps;
        public final int blockedApps;
        public final int blockedDomains;
        public final int blockedPorts;
        RuleStats(int ips, int apps, int domains, int ports) {
            blockedIps     = ips;
            blockedApps    = apps;
            blockedDomains = domains;
            blockedPorts   = ports;
        }
    }

    public RuleStats getStats() {
        int ips, apps, domains, ports;
        ipLock.readLock().lock();     try { ips     = blockedIps.size();    } finally { ipLock.readLock().unlock(); }
        appLock.readLock().lock();    try { apps    = blockedApps.size();   } finally { appLock.readLock().unlock(); }
        domainLock.readLock().lock(); try { domains = blockedDomains.size() + domainPatterns.size(); } finally { domainLock.readLock().unlock(); }
        portLock.readLock().lock();   try { ports   = blockedPorts.size();  } finally { portLock.readLock().unlock(); }
        return new RuleStats(ips, apps, domains, ports);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Parse a dotted-decimal IP string into a little-endian long (matches C++ representation). */
    public static long parseIP(String ip) {
        String[] parts = ip.trim().split("\\.");
        if (parts.length != 4) return 0;
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result |= (Long.parseLong(parts[i]) << (i * 8));
        }
        return result;
    }

    private static boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.length() >= 2 && pattern.startsWith("*.")) {
            String suffix = pattern.substring(1); // .example.com
            if (domain.endsWith(suffix)) return true;
            // Also match bare domain
            if (domain.equals(pattern.substring(2))) return true;
        }
        return false;
    }
}
