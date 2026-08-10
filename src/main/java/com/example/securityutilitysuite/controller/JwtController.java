package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.JwtAnalyzeRequest;
import com.example.securityutilitysuite.dto.JwtAnalyzeResponse;
import com.example.securityutilitysuite.service.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
    public ResponseEntity<JwtAnalyzeResponse> analyze(@RequestBody JwtAnalyzeRequest request) {
        return ResponseEntity.ok(jwtService.analyze(request));
    }
}
