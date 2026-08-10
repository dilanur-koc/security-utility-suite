package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.CryptoRequest;
import com.example.securityutilitysuite.dto.CryptoResponse;
import com.example.securityutilitysuite.service.CryptoService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * AES-256 / Sezar sifreleme REST ucu.
 *
 * Not: parola istek govdesinde geliyor ve HICBIR YERE KAYDEDILMIYOR —
 * ne veritabanina, ne loga. Anahtar her istekte paroladan yeniden turetilir.
 */
@RestController
@RequestMapping("/api/v1/crypto")
public class CryptoController {

    private final CryptoService cryptoService;

    public CryptoController(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @PostMapping
    public ResponseEntity<CryptoResponse> process(@Valid @RequestBody CryptoRequest request) {
        return ResponseEntity.ok(cryptoService.process(request));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadInput(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(Map.of("message", ex.getMessage()));
    }
}
