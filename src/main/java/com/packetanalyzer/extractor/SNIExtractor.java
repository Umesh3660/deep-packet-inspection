package com.packetanalyzer.extractor;

import java.util.Optional;

/**
 * Extracts the Server Name Indication from a TLS Client Hello payload.
 * Mirrors the C++ {@code DPI::SNIExtractor} class.
 */
public class SNIExtractor {

    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI          = 0x0000;
    private static final int SNI_TYPE_HOSTNAME      = 0x00;

    public static boolean isTLSClientHello(byte[] payload, int length) {
        if (length < 9) return false;
        if ((payload[0] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;
        int version = readUint16BE(payload, 1);
        if (version < 0x0300 || version > 0x0304) return false;
        int recordLen = readUint16BE(payload, 3);
        if (recordLen > length - 5) return false;
        return (payload[5] & 0xFF) == HANDSHAKE_CLIENT_HELLO;
    }

    public static Optional<String> extract(byte[] payload, int length) {
        if (!isTLSClientHello(payload, length)) return Optional.empty();

        int offset = 5; // skip TLS record header

        // Skip handshake header (4 bytes: type + 3-byte length)
        offset += 4;

        // Skip client version (2) + random (32)
        offset += 34;
        if (offset >= length) return Optional.empty();

        // Session ID
        int sessionIdLen = payload[offset] & 0xFF;
        offset += 1 + sessionIdLen;

        // Cipher suites
        if (offset + 2 > length) return Optional.empty();
        int cipherSuitesLen = readUint16BE(payload, offset);
        offset += 2 + cipherSuitesLen;

        // Compression methods
        if (offset >= length) return Optional.empty();
        int compressionLen = payload[offset] & 0xFF;
        offset += 1 + compressionLen;

        // Extensions
        if (offset + 2 > length) return Optional.empty();
        int extensionsLen = readUint16BE(payload, offset);
        offset += 2;
        int extensionsEnd = Math.min(offset + extensionsLen, length);

        while (offset + 4 <= extensionsEnd) {
            int extType   = readUint16BE(payload, offset);
            int extLength = readUint16BE(payload, offset + 2);
            offset += 4;

            if (offset + extLength > extensionsEnd) break;

            if (extType == EXTENSION_SNI) {
                if (extLength < 5) break;
                // sniListLength (2) + sniType (1) + sniLength (2) + value
                int sniType   = payload[offset + 2] & 0xFF;
                int sniLength = readUint16BE(payload, offset + 3);
                if (sniType != SNI_TYPE_HOSTNAME) break;
                if (sniLength > extLength - 5) break;
                return Optional.of(new String(payload, offset + 5, sniLength));
            }

            offset += extLength;
        }
        return Optional.empty();
    }

    static int readUint16BE(byte[] data, int off) {
        return ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF);
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Extracts the Host header from an unencrypted HTTP request.
 * Mirrors the C++ {@code DPI::HTTPHostExtractor} class.
 */
class HTTPHostExtractor {

    public static boolean isHTTPRequest(byte[] payload, int length) {
        if (length < 4) return false;
        String[] methods = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
        String prefix = new String(payload, 0, 4);
        for (String m : methods) {
            if (prefix.equals(m)) return true;
        }
        return false;
    }

    public static Optional<String> extract(byte[] payload, int length) {
        if (!isHTTPRequest(payload, length)) return Optional.empty();

        for (int i = 0; i + 5 < length; i++) {
            if ((payload[i]   == 'H' || payload[i]   == 'h') &&
                (payload[i+1] == 'o' || payload[i+1] == 'O') &&
                (payload[i+2] == 's' || payload[i+2] == 'S') &&
                (payload[i+3] == 't' || payload[i+3] == 'T') &&
                 payload[i+4] == ':') {

                int start = i + 5;
                while (start < length && (payload[start] == ' ' || payload[start] == '\t')) start++;
                int end = start;
                while (end < length && payload[end] != '\r' && payload[end] != '\n') end++;

                if (end > start) {
                    String host = new String(payload, start, end - start);
                    int colonPos = host.indexOf(':');
                    if (colonPos >= 0) host = host.substring(0, colonPos);
                    return Optional.of(host);
                }
            }
        }
        return Optional.empty();
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Extracts the queried domain from a DNS query packet.
 * Mirrors the C++ {@code DPI::DNSExtractor} class.
 */
class DNSExtractor {

    public static boolean isDNSQuery(byte[] payload, int length) {
        if (length < 12) return false;
        if ((payload[2] & 0x80) != 0) return false;  // QR bit set → response
        int qdcount = SNIExtractor.readUint16BE(payload, 4);
        return qdcount > 0;
    }

    public static Optional<String> extractQuery(byte[] payload, int length) {
        if (!isDNSQuery(payload, length)) return Optional.empty();

        int offset = 12;
        StringBuilder domain = new StringBuilder();

        while (offset < length) {
            int labelLen = payload[offset] & 0xFF;
            if (labelLen == 0) break;
            if (labelLen > 63) break;

            offset++;
            if (offset + labelLen > length) break;
            if (domain.length() > 0) domain.append('.');
            domain.append(new String(payload, offset, labelLen));
            offset += labelLen;
        }

        return domain.length() == 0 ? Optional.empty() : Optional.of(domain.toString());
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Simplified QUIC SNI extractor (searches for embedded TLS Client Hello).
 * Mirrors the C++ {@code DPI::QUICSNIExtractor} class.
 */
class QUICSNIExtractor {

    public static boolean isQUICInitial(byte[] payload, int length) {
        if (length < 5) return false;
        return (payload[0] & 0x80) != 0;
    }

    public static Optional<String> extract(byte[] payload, int length) {
        if (!isQUICInitial(payload, length)) return Optional.empty();

        for (int i = 0; i + 50 < length; i++) {
            if ((payload[i] & 0xFF) == 0x01) {
                int subOff = Math.max(0, i - 5);
                int subLen = length - subOff;
                byte[] sub = new byte[subLen];
                System.arraycopy(payload, subOff, sub, 0, subLen);
                Optional<String> sni = SNIExtractor.extract(sub, subLen);
                if (sni.isPresent()) return sni;
            }
        }
        return Optional.empty();
    }
}
