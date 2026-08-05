package com.example.securityutilitysuite.dto;

/**
 * Tum guvenlik modullerinin ortak bulgu tipi.
 *
 * Onceden her yanit DTO'su kendi ic {@code Finding} record'unu tasiyordu —
 * dordu de birebir ayniydi. Tek tip kullanmak hem tekrari kaldirir hem de
 * yeni bir modul eklendiginde onem derecesi degerlerinin kaymasini onler.
 *
 * @param severity CRITICAL / HIGH / MEDIUM / LOW
 * @param message  kullaniciya gosterilecek aciklama
 */
public record Finding(String severity, String message) {

    public static Finding critical(String message) {
        return new Finding("CRITICAL", message);
    }

    public static Finding high(String message) {
        return new Finding("HIGH", message);
    }

    public static Finding medium(String message) {
        return new Finding("MEDIUM", message);
    }

    public static Finding low(String message) {
        return new Finding("LOW", message);
    }
}
