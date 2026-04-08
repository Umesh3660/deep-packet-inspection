package com.packetanalyzer.extractor;

import java.util.Optional;

/**
 * Public facade for the DNS query extractor.
 */
public class DNSExtractorPublic {

    public static boolean isDNSQuery(byte[] payload, int length) {
        if (length < 12) return false;
        if ((payload[2] & 0x80) != 0) return false; // QR bit → response
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
