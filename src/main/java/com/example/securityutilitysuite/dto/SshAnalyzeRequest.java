package com.example.securityutilitysuite.dto;

/**
 * POST /api/v1/ssh/analyze istek govdesi.
 *
 * @param logContent analiz edilecek SSH auth log metni (orn. /var/log/auth.log)
 * @param threshold  bir IP'nin "engellenmeli" sayilmasi icin gereken minimum
 *                   basarisiz deneme sayisi. Verilmezse (null) varsayilan 5
 *                   kullanilir.
 */
public record SshAnalyzeRequest(String logContent, Integer threshold) {
}
