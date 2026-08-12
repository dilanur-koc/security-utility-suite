package com.example.securityutilitysuite.dto;

import java.time.LocalDateTime;

/**
 * Arayuze donen bildirim gosterimi.
 *
 * JPA entity'si yerine DTO kullaniliyor: sahip bilgisi disariya sizmasin
 * ve entity alanlari degistiginde API sozlesmesi sessizce kaymasin.
 */
public record NotificationItem(
        Long id,
        String title,
        String message,
        String severity,
        Long targetId,
        boolean read,
        LocalDateTime createdAt
) {
}
