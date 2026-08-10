package com.example.securityutilitysuite.dto;

/**
 * Tek bir JWT claim'i (payload icindeki bir alan).
 *
 * @param name  claim adi (orn. "sub", "exp", "role")
 * @param value okunabilir deger — tarih claim'leri (exp/iat/nbf) hem ham
 *              epoch hem de cozulmus tarih olarak metne cevrilmis halde gelir
 */
public record JwtClaim(String name, String value) {
}
