package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.JwtAnalyzeRequest;
import com.example.securityutilitysuite.dto.JwtAnalyzeResponse;
import com.example.securityutilitysuite.service.JwtService;
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
 * JWT Token Analyzer icin REST ucu.
 * Token hicbir yerde saklanmaz/loglanmaz; istek govdesinde gelir, analiz
 * edilir, cevapla birlikte unutulur.
 */
@RestController
@RequestMapping("/api/v1/jwt")
public class JwtController {

    private final JwtService jwtService;

    public JwtController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<JwtAnalyzeResponse> analyze(@Valid @RequestBody JwtAnalyzeRequest request) {
        return ResponseEntity.ok(jwtService.analyze(request));
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
