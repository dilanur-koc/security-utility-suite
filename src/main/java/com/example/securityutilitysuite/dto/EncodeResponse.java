package com.example.securityutilitysuite.dto;

import java.util.List;

/**
 * Kodlama/cozme sonucu.
 *
 * Sonucun yaninda TUM gosterimler birden dondurulur. Guvenlik incelemesinde
 * ayni veriyi Base64, Base64URL ve hex olarak yan yana gormek siktir
 * (orn. bir imzayi hex'e cevirip karsilastirmak); kullanicinin ayni metni
 * uc kez gonderip beklemesi gereksiz.
 *
 * @param output       istenen islemin sonucu
 * @param format       kullanilan bicim
 * @param operation    yapilan islem
 * @param inputLength  girdi uzunlugu (karakter)
 * @param outputLength cikti uzunlugu (karakter)
 * @param byteLength   ham veri uzunlugu (bayt)
 * @param asText       ham verinin UTF-8 metin karsiligi (okunabilirse)
 * @param asBase64     ayni verinin standart Base64 gosterimi
 * @param asBase64Url  ayni verinin URL-safe Base64 gosterimi
 * @param asHex        ayni verinin hex gosterimi
 * @param findings     dikkat edilmesi gereken noktalar
 */
public record EncodeResponse(
        String output,
        String format,
        String operation,
        int inputLength,
        int outputLength,
        int byteLength,
        String asText,
        String asBase64,
        String asBase64Url,
        String asHex,
        List<Finding> findings
) {
}
