package com.example.securityutilitysuite.enums;

/**
 * Bildirim onem dereceleri.
 *
 * Modul bulgularindaki {@code Finding.severity} degerleriyle ayni dili
 * konusur; boylece bulgu -> bildirim donusumunde esleme tablosu gerekmez.
 */
public enum NotificationSeverity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO
}
