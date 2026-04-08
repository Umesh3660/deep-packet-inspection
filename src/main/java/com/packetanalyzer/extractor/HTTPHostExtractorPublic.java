package com.packetanalyzer.extractor;

import java.util.Optional;

/**
 * Public facade for the HTTP host-header extractor.
 */
public class HTTPHostExtractorPublic {

    public static boolean isHTTPRequest(byte[] payload, int length) {
        if (length < 4) return false;
        String prefix = new String(payload, 0, 4);
        return prefix.equals("GET ") || prefix.equals("POST") || prefix.equals("PUT ")
            || prefix.equals("HEAD") || prefix.equals("DELE") || prefix.equals("PATC")
            || prefix.equals("OPTI");
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
                    int colon = host.indexOf(':');
                    if (colon >= 0) host = host.substring(0, colon);
                    return Optional.of(host);
                }
            }
        }
        return Optional.empty();
    }
}
