package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.SshAnalyzeRequest;
import com.example.securityutilitysuite.dto.SshAnalyzeResponse;
import com.example.securityutilitysuite.service.SshBruteForceService;
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

/** SSH Brute-Force Blocker icin REST ucu. */
@RestController
@RequestMapping("/api/v1/ssh")
public class SshBruteForceController {

    private final SshBruteForceService service;

    public SshBruteForceController(SshBruteForceService service) {
        this.service = service;
    }

    @PostMapping("/analyze")
    public ResponseEntity<SshAnalyzeResponse> analyze(@Valid @RequestBody SshAnalyzeRequest request) {
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
