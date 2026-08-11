package com.example.securityutilitysuite.dto;

/**
 * Tespit edilen tek bir IOC (Indicator of Compromise).
 *
 * @param type  "IPV4" | "IPV6" | "DOMAIN" | "URL" | "MD5" | "SHA1" | "SHA256" | "EMAIL"
 * @param value normallestirilmis (defang'i acilmis) deger
 * @param note  siniflandirma notu (orn. "özel/dahili adres", "genel adres")
 */
public record IocItem(String type, String value, String note) {
}
