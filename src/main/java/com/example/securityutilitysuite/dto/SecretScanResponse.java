package com.example.securityutilitysuite.dto;

import java.util.List;

/**
 * POST /api/v1/secrets/scan yanit govdesi.
 *
 * @param totalLines  girdideki toplam satir sayisi
 * @param leakCount   bulunan toplam sizinti sayisi
 * @param leaks       her sizinti orneginin ayrintisi
 * @param findings    turlere gore gruplanmis ozet bulgular
 */
public record SecretScanResponse(int totalLines, int leakCount, List<SecretLeak> leaks, List<Finding> findings) {
}
