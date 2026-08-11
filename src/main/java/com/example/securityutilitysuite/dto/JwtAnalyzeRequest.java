package com.example.securityutilitysuite.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * POST /api/v1/jwt/analyze istek govdesi.
 *
 * @param token  analiz edilecek JWT (ham, "eyJ..." ile baslayan tam metin)
 * @param secret isteğe bağlı. Verilirse ve algoritma HMAC ailesindense
 *               (HS256/HS384/HS512) imza bu anahtarla doğrulanır. RS/ES gibi
 *               asimetrik algoritmalar icin ortak anahtar (public key) girisi
 *               v1 kapsaminda desteklenmiyor.
 */
public record JwtAnalyzeRequest(
        @NotBlank(message = "Token boş olamaz")
        @Size(max = 8_000, message = "Token 8.000 karakteri aşamaz")
        String token,

        @Size(max = 512, message = "Anahtar 512 karakteri aşamaz")
        String secret
) {
}
