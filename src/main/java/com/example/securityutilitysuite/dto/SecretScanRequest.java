package com.example.securityutilitysuite.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * POST /api/v1/secrets/scan istek govdesi.
 *
 * @param content taranacak metin (kod, .env dosyasi, git diff, log vb.)
 */
public record SecretScanRequest(
        @NotBlank(message = "İçerik boş olamaz")
        @Size(max = 500_000, message = "İçerik 500.000 karakteri aşamaz")
        String content
) {
}
