package com.example.securityutilitysuite.dto;

import java.time.LocalDateTime;

/**
 * Tek bir kontrol kaydinin gecmis gosterimi.
 */
public record MonitorCheckItem(
        Long id,
        LocalDateTime checkedAt,
        String summary,
        String severity,
        int findingCount,
        boolean successful,
        boolean changed
) {
}
