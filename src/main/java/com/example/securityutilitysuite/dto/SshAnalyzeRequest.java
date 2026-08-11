package com.example.securityutilitysuite.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * POST /api/v1/ssh/analyze istek govdesi.
 *
 * @param logContent analiz edilecek SSH auth log metni (orn. /var/log/auth.log)
 * @param threshold  bir IP'nin "engellenmeli" sayilmasi icin gereken minimum
 *                   basarisiz deneme sayisi. Verilmezse (null) varsayilan 5
 *                   kullanilir.
 */
public record SshAnalyzeRequest(
        @NotBlank(message = "Log içeriği boş olamaz")
        @Size(max = 500_000, message = "Log içeriği 500.000 karakteri aşamaz")
        String logContent,

        Integer threshold
) {
}
