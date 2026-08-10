package com.example.securityutilitysuite.dto;

import java.util.List;

/**
 * Bir kaynak IP icin ozet.
 *
 * @param ip                  kaynak IP adresi
 * @param failedAttempts      basarisiz (Failed password / Invalid user) deneme sayisi
 * @param succeededAfterFailures bu IP, basarisiz denemelerden SONRA basarili giris yapti mi
 *                            (olası ele gecirilmis hesap / basarili brute-force isareti)
 * @param usernamesTried      denenen benzersiz kullanici adlari (en fazla 10 tanesi)
 * @param firstSeen           bu IP'den ilk log satirinin zaman damgasi (log'da bulunuyorsa)
 * @param lastSeen            bu IP'den son log satirinin zaman damgasi
 * @param recommendBlock      failedAttempts >= threshold mi
 * @param suggestedRule       recommendBlock true ise onerilen ufw komutu, degilse null
 */
public record SshIpSummary(
        String ip,
        int failedAttempts,
        boolean succeededAfterFailures,
        List<String> usernamesTried,
        String firstSeen,
        String lastSeen,
        boolean recommendBlock,
        String suggestedRule
) {
}
