package com.example.securityutilitysuite.dto;

import java.time.LocalDateTime;
import java.util.List;

/**
 * POST /api/v1/jwt/analyze yanit govdesi.
 *
 * @param valid            token yapisal olarak coz ulebildi mi (3 parcali,
 *                         gecerli Base64URL, gecerli JSON). false ise diger
 *                         alanlarin cogu null/bos olur.
 * @param error            valid=false ise kisa hata aciklamasi
 * @param headerJson       header segmentinin bicimlendirilmis JSON metni
 * @param payloadJson      payload segmentinin bicimlendirilmis JSON metni
 * @param algorithm        header'daki "alg" degeri (orn. "HS256", "none")
 * @param type             header'daki "typ" degeri (genelde "JWT")
 * @param claims           payload'daki tum claim'ler, oldugu gibi
 * @param issuedAt         "iat" claim'i coz ulmus haliyle (yoksa null)
 * @param expiresAt        "exp" claim'i coz ulmus haliyle (yoksa null)
 * @param notBefore        "nbf" claim'i coz ulmus haliyle (yoksa null)
 * @param expired          exp gecmiste mi
 * @param signatureProvided istekte imza segmenti var miydi (bos degil)
 * @param signatureChecked secret ile dogrulama denendi mi
 * @param signatureValid   secret ile dogrulama sonucu (denenmedi ise null)
 * @param findings         guvenlik bulgulari
 */
public record JwtAnalyzeResponse(
        boolean valid,
        String error,
        String headerJson,
        String payloadJson,
        String algorithm,
        String type,
        List<JwtClaim> claims,
        LocalDateTime issuedAt,
        LocalDateTime expiresAt,
        LocalDateTime notBefore,
        boolean expired,
        boolean signatureProvided,
        boolean signatureChecked,
        Boolean signatureValid,
        List<Finding> findings
) {
    public static JwtAnalyzeResponse invalid(String error) {
        return new JwtAnalyzeResponse(false, error, null, null, null, null,
                List.of(), null, null, null, false, false, false, null, List.of());
    }
}
