package com.example.securityutilitysuite.dto;

/**
 * Tespit edilen tek bir sizinti.
 *
 * @param type        sizinti turu (orn. "GitHub Personal Access Token")
 * @param severity    "CRITICAL" | "HIGH" | "MEDIUM"
 * @param line        1-tabanli satir numarasi (bulunamadiysa 0)
 * @param maskedValue kismen maskelenmis deger — ham secret hicbir zaman
 *                    tam olarak donmez (orn. "ghp_...ab12")
 */
public record SecretLeak(String type, String severity, int line, String maskedValue) {
}
