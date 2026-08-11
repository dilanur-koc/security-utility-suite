package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.SecretScanRequest;
import com.example.securityutilitysuite.dto.SecretScanResponse;
import com.example.securityutilitysuite.service.SecretLeakService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Git & Secret Leak Finder icin REST ucu. */
@RestController
@RequestMapping("/api/v1/secrets")
public class SecretLeakController {

    private final SecretLeakService service;

    public SecretLeakController(SecretLeakService service) {
        this.service = service;
    }

    @PostMapping("/scan")
    public ResponseEntity<SecretScanResponse> scan(@RequestBody SecretScanRequest request) {
        return ResponseEntity.ok(service.scan(request));
    }
}
