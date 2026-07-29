package com.example.securityutilitysuite.enums;

/**
 * Tespit edilen tehdit turlerini temsil eder.
 * Bu deger, log analiz motoru tarafindan tespit edilen saldiri paternine gore atanir.
 */
public enum ThreatType {
    SQL_INJECTION,
    XSS,
    BRUTE_FORCE,
    SUSPICIOUS_ACTIVITY
}