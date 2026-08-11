package com.example.securityutilitysuite.dto;

/**
 * Tek bir sorgu parametresi icin tarama sonucu.
 *
 * @param parameter          parametre adi
 * @param xssSuspected        Reflected XSS supheli mi
 * @param sqlErrorSuspected   hata-tabanli SQL enjeksiyonu supheli mi
 * @param sqlBooleanSuspected boolean-tabanli SQL enjeksiyonu supheli mi
 */
public record WebVulnParamResult(
        String parameter,
        boolean xssSuspected,
        boolean sqlErrorSuspected,
        boolean sqlBooleanSuspected
) {
}
