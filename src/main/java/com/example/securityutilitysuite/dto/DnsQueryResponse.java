package com.example.securityutilitysuite.dto;

import java.util.List;
import java.util.Map;

/**
 * DNS sorgu ve spoofing analizi sonucu.
 */
public record DnsQueryResponse(
        String domain,
        boolean resolved,
        String error,
        Map<String, List<String>> records,
        List<ResolverAnswer> resolvers,
        boolean consistent,
        List<ReverseLookup> reverseLookups,
        List<Finding> findings
) {

    public record ResolverAnswer(
            String name,
            String address,
            List<String> aRecords,
            long responseMs,
            String error
    ) {}

    public record ReverseLookup(
            String ip,
            String ptr,
            boolean forwardConfirmed
    ) {}

    public static DnsQueryResponse failed(String domain, String error) {
        return new DnsQueryResponse(
                domain,
                false,
                error,
                Map.of(),
                List.of(),
                true,
                List.of(),
                List.of(new Finding("CRITICAL", "Alan adı çözümlenemedi: " + error))
        );
    }
}