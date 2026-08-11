package com.example.securityutilitysuite.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * POST /api/v1/webvuln/scan istek govdesi.
 *
 * @param url                   sorgu parametreleri ICEREN tam hedef URL
 *                              (orn. https://example.com/search?q=test)
 * @param legalAcknowledgement  kullanicinin "yalnizca yetkili oldugum
 *                              sistemlerde kullaniyorum" onayi. Bu SADECE
 *                              arayuzde degil, sunucu tarafinda da zorunludur
 *                              — biri /api/v1/webvuln/scan'i dogrudan
 *                              cagirirsa da bu onay olmadan tarama BASLAMAZ.
 */
public record WebVulnScanRequest(
        @NotBlank(message = "URL boş olamaz")
        @Size(max = 2048, message = "URL 2048 karakteri aşamaz")
        String url,

        boolean legalAcknowledgement
) {
}
