package com.packetanalyzer.dpi;

import java.util.Optional;

/**
 * Package-visible helper that delegates to the extractor package classes
 * (which are package-private) so that FastPathProcessor can call them
 * from a different package without circular dependencies.
 */
class HTTPHostExtractor {
    static Optional<String> extract(byte[] payload, int length) {
        return com.packetanalyzer.extractor.HTTPHostExtractorPublic.extract(payload, length);
    }
}

class DNSExtractor {
    static Optional<String> extractQuery(byte[] payload, int length) {
        return com.packetanalyzer.extractor.DNSExtractorPublic.extractQuery(payload, length);
    }
}
