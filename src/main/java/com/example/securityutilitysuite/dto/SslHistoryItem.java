package com.example.securityutilitysuite.dto;

import java.time.LocalDateTime;

/**
 * Gecmis SSL denetimlerinin sade gosterimi.
 *
 * JPA entity'sini ({@code SslCheckResult}) dogrudan REST'ten dondurmek yerine
 * bu tip kullanilir: entity'ye yeni bir alan eklendiginde API sozlesmesi
 * istemeden degismez, id gibi ic detaylar disariya sizmaz.
 *
 * @param domain        denetlenen alan adi
 * @param issuer        sertifikayi imzalayan otorite
 * @param validTo       gecerlilik bitisi
 * @param daysRemaining bitise kalan gun
 * @param expired       suresi dolmus mu
 * @param checkedAt     denetimin yapildigi an
 */
public record SslHistoryItem(
        String domain,
        String issuer,
        LocalDateTime validTo,
        long daysRemaining,
        boolean expired,
        LocalDateTime checkedAt
) {
}
