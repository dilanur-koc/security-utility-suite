package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.HashRequest;
import com.example.securityutilitysuite.dto.HashResponse;
import com.example.securityutilitysuite.service.HashService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Hash Verifier &amp; Dictionary Cracker REST ucu.
 * Durum tutmaz; islem tamamen bellekte yapilir.
 */
@RestController
@RequestMapping("/api/v1/hash")
public class HashController {

    private final HashService hashService;

    public HashController(HashService hashService) {
        this.hashService = hashService;
    }

    @PostMapping
    public ResponseEntity<HashResponse> process(@Valid @RequestBody HashRequest request) {
        return ResponseEntity.ok(hashService.process(request));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadInput(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(Map.of("message", ex.getMessage()));
    }
}
