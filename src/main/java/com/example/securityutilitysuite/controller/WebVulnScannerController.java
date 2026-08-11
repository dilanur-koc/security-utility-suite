package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.WebVulnScanRequest;
import com.example.securityutilitysuite.dto.WebVulnScanResponse;
import com.example.securityutilitysuite.service.WebVulnScannerService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Web Zafiyet Tarayıcı icin REST ucu.
 * DIKKAT: bu, projedeki tek AKTIF tarama modulu — hedefe gercek istek
 * gonderir. Guvenlik onlemleri (SSRF filtresi, GET-only, hiz siniri, yasal
 * onay zorunlulugu) WebVulnScannerService icinde uygulanir.
 */
@RestController
@RequestMapping("/api/v1/webvuln")
public class WebVulnScannerController {

    private final WebVulnScannerService service;

    public WebVulnScannerController(WebVulnScannerService service) {
        this.service = service;
    }

    @PostMapping("/scan")
    public ResponseEntity<WebVulnScanResponse> scan(@Valid @RequestBody WebVulnScanRequest request) {
        return ResponseEntity.ok(service.scan(request));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (FieldError fe : ex.getBindingResult().getFieldErrors()) {
            fields.put(fe.getField(), fe.getDefaultMessage());
        }
        return ResponseEntity.badRequest().body(Map.of("fields", fields));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadInput(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(Map.of("message", ex.getMessage()));
    }
}
