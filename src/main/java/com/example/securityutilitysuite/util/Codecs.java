package com.example.securityutilitysuite.util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Kodlama/cozme islemleri icin ortak yardimci.
 *
 * NEDEN ORTAK:
 * Veri &amp; Kriptografi kategorisindeki modullerin hepsi ayni islemleri
 * yapiyor — Base64 Converter standart Base64, JWT Analyzer URL-safe Base64,
 * Hash Verifier hex cikti, AES Encryptor yine Base64. Her modulun kendi
 * kopyasini tasimasi, birinde yapilan duzeltmenin digerlerine gecmemesi
 * demek olurdu (bunu projede daha once {@code kisaHata} ile yasadik).
 *
 * TASARIM NOTU — dolgu (padding) toleransi:
 * JWT gibi bicimlerde URL-safe Base64 dolgusuz ("=" olmadan) yazilir.
 * Java'nin {@code Base64.getUrlDecoder()} dolgusuz girdiyi kabul eder,
 * ancak kismi bloklarda hata verir. Bu yuzden cozme metotlari eksik
 * dolguyu kendisi tamamlar.
 */
public final class Codecs {

    private Codecs() {
        // yardimci sinif
    }

    // ------------------------------------------------------------------
    // Base64 (standart)
    // ------------------------------------------------------------------

    public static String base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static String base64Encode(String text) {
        return base64Encode(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * @throws IllegalArgumentException girdi gecerli Base64 degilse
     */
    public static byte[] base64Decode(String encoded) {
        try {
            return Base64.getDecoder().decode(temizle(encoded));
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Geçerli bir Base64 değeri değil: " + kisaOrnek(encoded));
        }
    }

    // ------------------------------------------------------------------
    // Base64 URL-safe (JWT, imzalar)
    // ------------------------------------------------------------------

    public static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Dolgusuz URL-safe Base64'u cozer. JWT parcalari dolgusuz gelir; eksik
     * "=" karakterleri burada tamamlanir.
     *
     * @throws IllegalArgumentException girdi cozulemezse
     */
    public static byte[] base64UrlDecode(String encoded) {
        String temiz = temizle(encoded);
        int eksik = (4 - temiz.length() % 4) % 4;
        if (eksik == 3) {
            // 4n+1 uzunluk hicbir zaman gecerli Base64 olamaz
            throw new IllegalArgumentException("Geçersiz Base64URL uzunluğu: " + kisaOrnek(encoded));
        }
        try {
            return Base64.getUrlDecoder().decode(temiz + "=".repeat(eksik));
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Geçerli bir Base64URL değeri değil: " + kisaOrnek(encoded));
        }
    }

    /** Base64URL cozup UTF-8 metne cevirir. */
    public static String base64UrlDecodeToString(String encoded) {
        return new String(base64UrlDecode(encoded), StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------
    // Hex
    // ------------------------------------------------------------------

    public static String hexEncode(byte[] data) {
        return HexFormat.of().formatHex(data);
    }

    public static String hexEncode(String text) {
        return hexEncode(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Ayraclara toleransli hex cozucu: "48 65 6c", "48:65:6c", "0x4865" ve
     * "4865" bicimlerinin hepsini kabul eder. Elle kopyalanan ciktilar
     * genelde bu bicimlerden birinde olur.
     *
     * @throws IllegalArgumentException girdi gecerli hex degilse
     */
    public static byte[] hexDecode(String hex) {
        String temiz = hex.replaceAll("(?i)0x", "")
                          .replaceAll("[\\s:,-]", "");
        if (temiz.isEmpty()) {
            throw new IllegalArgumentException("Hex değeri boş olamaz");
        }
        if (temiz.length() % 2 != 0) {
            throw new IllegalArgumentException(
                    "Hex uzunluğu çift olmalı (" + temiz.length() + " karakter girildi)");
        }
        if (!temiz.matches("[0-9a-fA-F]+")) {
            throw new IllegalArgumentException("Hex dışı karakter içeriyor: " + kisaOrnek(hex));
        }
        return HexFormat.of().parseHex(temiz);
    }

    // ------------------------------------------------------------------
    // Yardimcilar
    // ------------------------------------------------------------------

    /** Kopyala-yapistir sirasinda araya giren bosluk ve satir sonlarini atar. */
    private static String temizle(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Değer boş olamaz");
        }
        return value.replaceAll("\\s", "");
    }

    /** Hata mesajlarinda tum girdiyi basmamak icin kisa ornek. */
    private static String kisaOrnek(String value) {
        if (value == null) return "(boş)";
        String tek = value.replaceAll("\\s+", " ").trim();
        return tek.length() > 40 ? tek.substring(0, 40) + "…" : tek;
    }
}
