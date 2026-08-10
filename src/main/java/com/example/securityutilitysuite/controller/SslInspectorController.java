package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.SslCheckRequest;
import com.example.securityutilitysuite.dto.SslCheckResponse;
import com.example.securityutilitysuite.dto.SslHistoryItem;
import com.example.securityutilitysuite.service.SslInspectorService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * SSL/TLS Sertifika Inspector modulunun REST uclari.
 */
@RestController
@RequestMapping("/api/v1/ssl")
public class SslInspectorController {

    private final SslInspectorService sslInspectorService;

    public SslInspectorController(SslInspectorService sslInspectorService) {
        this.sslInspectorService = sslInspectorService;
    }

    /**
     * Verilen host icin TLS el sikismasi yapar, sertifikayi cozer ve
     * bulgulari dondurur. Baglanti kurulamasa bile 200 doner; sonucun
     * {@code reachable} alani duruma isaret eder.
     */
    @PostMapping("/check")
    public ResponseEntity<SslCheckResponse> check(@Valid @RequestBody SslCheckRequest request) {
        return ResponseEntity.ok(sslInspectorService.inspect(request));
    }

    @GetMapping("/history")
    public ResponseEntity<List<SslHistoryItem>> history(
            @RequestParam(required = false) String domain
    ) {
        return ResponseEntity.ok(sslInspectorService.history(domain));
    }
}
