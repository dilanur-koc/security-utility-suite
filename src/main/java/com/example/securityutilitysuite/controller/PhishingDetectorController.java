package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.PhishingCheckRequest;
import com.example.securityutilitysuite.dto.PhishingCheckResponse;
import com.example.securityutilitysuite.service.PhishingDetectorService;
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
 * Phishing URL Detector icin REST ucu.
 * TAMAMEN PASIF — hedef URL'ye hicbir aglayici istek gonderilmez.
 */
@RestController
@RequestMapping("/api/v1/phishing")
public class PhishingDetectorController {

    private final PhishingDetectorService service;

    public PhishingDetectorController(PhishingDetectorService service) {
        this.service = service;
    }

    @PostMapping("/check")
    public ResponseEntity<PhishingCheckResponse> check(@Valid @RequestBody PhishingCheckRequest request) {
        return ResponseEntity.ok(service.analyze(request));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (FieldError fe : ex.getBindingResult().getFieldErrors()) {
            fields.put(fe.getField(), fe.getDefaultMessage());
        }
        return ResponseEntity.badRequest().body(Map.of("fields", fields));
    }
}
