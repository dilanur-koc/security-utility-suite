package com.example.securityutilitysuite.dto;

import java.time.LocalDateTime;

/**
 * Izleme hedefinin arayuz gosterimi.
 */
public record MonitorTargetItem(
        Long id,
        String target,
        String type,
        boolean active,
        LocalDateTime lastCheckedAt,
        String lastSummary,
        String lastSeverity,
        int failureCount,
        LocalDateTime createdAt
) {
}
