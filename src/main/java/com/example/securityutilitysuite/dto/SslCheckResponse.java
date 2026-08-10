package com.example.securityutilitysuite.dto;

import java.time.LocalDateTime;
import java.util.List;

/**
 * SSL/TLS denetim sonucu. Veritabanina kaydedilen ozet
 * ({@code SslCheckResult}) disinda, tek seferlik denetim bulgularini da tasir.
 *
 * @param domain      denetlenen host
 * @param port        denetlenen port
 * @param reachable   TLS el sikismasi kurulabildi mi
 * @param error       kurulamadiysa sebebi
 * @param subject     sertifika sahibi (CN)
 * @param issuer      sertifikayi imzalayan otorite
 * @param validFrom   gecerlilik baslangici
 * @param validTo     gecerlilik bitisi
 * @param daysRemaining bitise kalan gun (negatifse suresi dolmus)
 * @param expired     suresi dolmus mu
 * @param notYetValid henuz gecerli degil mi
 * @param trusted     zincir sistemdeki koklerle dogrulanabildi mi
 * @param hostnameMatch sertifika istenen host adiyla eslesiyor mu
 * @param selfSigned  kendinden imzali mi
 * @param signatureAlgorithm imza algoritmasi (orn. SHA256withRSA)
 * @param keyAlgorithm anahtar algoritmasi (RSA / EC)
 * @param keySizeBits anahtar uzunlugu
 * @param serialNumber sertifika seri numarasi
 * @param protocol    anlasilan TLS surumu
 * @param cipherSuite anlasilan sifre takimi
 * @param chainLength sunucunun gonderdigi zincir uzunlugu
 * @param subjectAlternativeNames sertifikanin kapsadigi diger adlar
 * @param findings    tespit edilen riskler (bos ise sorun yok)
 */
public record SslCheckResponse(
        String domain,
        int port,
        boolean reachable,
        String error,
        String subject,
        String issuer,
        LocalDateTime validFrom,
        LocalDateTime validTo,
        long daysRemaining,
        boolean expired,
        boolean notYetValid,
        boolean trusted,
        boolean hostnameMatch,
        boolean selfSigned,
        String signatureAlgorithm,
        String keyAlgorithm,
        int keySizeBits,
        String serialNumber,
        String protocol,
        String cipherSuite,
        int chainLength,
        List<String> subjectAlternativeNames,
        List<Finding> findings
) {

    /** Baglanti kurulamadiginda donen kisa yanit. */
    public static SslCheckResponse unreachable(String domain, int port, String error) {
        return new SslCheckResponse(
                domain, port, false, error,
                null, null, null, null, 0, false, false, false, false, false,
                null, null, 0, null, null, null, 0,
                List.of(),
                List.of(new Finding("CRITICAL", "TLS bağlantısı kurulamadı: " + error))
        );
    }
}
