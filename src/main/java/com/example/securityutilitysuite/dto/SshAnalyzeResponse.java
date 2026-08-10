package com.example.securityutilitysuite.dto;

import java.util.List;

/**
 * POST /api/v1/ssh/analyze yanit govdesi.
 *
 * @param totalLines      log'daki toplam satir sayisi
 * @param matchedLines     taninan bir SSH olay kalibiyla eslesen satir sayisi
 * @param threshold        bu analizde kullanilan esik degeri
 * @param ipSummaries      IP basina ozet, basarisiz deneme sayisina gore azalan sirali
 * @param findings         genel bulgular
 */
public record SshAnalyzeResponse(
        int totalLines,
        int matchedLines,
        int threshold,
        List<SshIpSummary> ipSummaries,
        List<Finding> findings
) {
}
