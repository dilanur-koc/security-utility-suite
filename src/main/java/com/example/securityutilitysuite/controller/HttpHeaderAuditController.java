package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.HeaderAuditRequest;
import com.example.securityutilitysuite.dto.HeaderAuditResponse;
import com.example.securityutilitysuite.service.HttpHeaderAuditService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * HTTP Security Headers Audit modulunun REST ucu.
 * Durum tutmaz; sonuclar veritabanina yazilmaz.
 */
@RestController
@RequestMapping("/api/v1/headers")
public class HttpHeaderAuditController {

    private final HttpHeaderAuditService headerAuditService;

    public HttpHeaderAuditController(HttpHeaderAuditService headerAuditService) {
        this.headerAuditService = headerAuditService;
    }

    @PostMapping("/audit")
    public ResponseEntity<HeaderAuditResponse> audit(@Valid @RequestBody HeaderAuditRequest request) {
        return ResponseEntity.ok(headerAuditService.audit(request));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadInput(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(Map.of("message", ex.getMessage()));
    }
}
