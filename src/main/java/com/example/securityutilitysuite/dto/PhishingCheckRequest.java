package com.example.securityutilitysuite.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * POST /api/v1/phishing/check istek govdesi.
 *
 * @param url incelenecek URL. Bu modul TAMAMEN PASIFTIR — URL'ye hicbir
 *            aglayici istek gonderilmez, yalnizca metin/yapisi analiz edilir.
 */
public record PhishingCheckRequest(
        @NotBlank(message = "URL boş olamaz")
        @Size(max = 2048, message = "URL 2048 karakteri aşamaz")
        String url
) {
}
