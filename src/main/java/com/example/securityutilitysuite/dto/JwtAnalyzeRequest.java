package com.example.securityutilitysuite.dto;

/**
 * POST /api/v1/jwt/analyze istek govdesi.
 *
 * @param token  analiz edilecek JWT (ham, "eyJ..." ile baslayan tam metin)
 * @param secret isteğe bağlı. Verilirse ve algoritma HMAC ailesindense
 *               (HS256/HS384/HS512) imza bu anahtarla doğrulanır. RS/ES gibi
 *               asimetrik algoritmalar icin ortak anahtar (public key) girisi
 *               v1 kapsaminda desteklenmiyor.
 */
public record JwtAnalyzeRequest(String token, String secret) {
}
