package com.example.securityutilitysuite.dto;

import java.util.List;
import java.util.Map;

/**
 * HTTP guvenlik basliklari denetim sonucu.
 *
 * @param url          denetlenen adres
 * @param finalUrl     yonlendirmelerden sonra ulasilan adres
 * @param reachable    istek tamamlanabildi mi
 * @param error        tamamlanamadiysa sebebi
 * @param statusCode   HTTP durum kodu
 * @param httpVersion  kullanilan HTTP surumu
 * @param responseMs   yanit suresi
 * @param score        100 uzerinden puan
 * @param grade        A-F harf notu
 * @param checks       her baslik icin denetim sonucu
 * @param rawHeaders   sunucunun dondurdugu tum basliklar
 * @param findings     riskler ve oneriler
 */
public record HeaderAuditResponse(
        String url,
        String finalUrl,
        boolean reachable,
        String error,
        int statusCode,
        String httpVersion,
        long responseMs,
        int score,
        String grade,
        List<HeaderCheck> checks,
        Map<String, String> rawHeaders,
        List<Finding> findings
) {

    /**
     * Tek bir guvenlik basliginin denetimi.
     *
     * @param name        baslik adi
     * @param present     var mi
     * @param value       degeri (yoksa null)
     * @param status      OK / WARN / MISSING
     * @param weight      puanlamadaki agirligi
     * @param description baslik ne ise yarar
     * @param note        yapilandirmayla ilgili ek uyari
     */
    public record HeaderCheck(String name, boolean present, String value,
                              String status, int weight, String description, String note) {
    }

    public static HeaderAuditResponse unreachable(String url, String error) {
        return new HeaderAuditResponse(
                url, null, false, error, 0, null, 0, 0, "—",
                List.of(), Map.of(),
                List.of(new Finding("CRITICAL", "Adrese ulaşılamadı: " + error))
        );
    }
}
