package com.example.securityutilitysuite.dto;

/**
 * POST /api/v1/secrets/scan istek govdesi.
 *
 * @param content taranacak metin (kod, .env dosyasi, git diff, log vb.)
 */
public record SecretScanRequest(String content) {
}
