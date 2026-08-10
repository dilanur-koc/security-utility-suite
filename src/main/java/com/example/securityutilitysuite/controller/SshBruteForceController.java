package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.SshAnalyzeRequest;
import com.example.securityutilitysuite.dto.SshAnalyzeResponse;
import com.example.securityutilitysuite.service.SshBruteForceService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** SSH Brute-Force Blocker icin REST ucu. */
@RestController
@RequestMapping("/api/v1/ssh")
public class SshBruteForceController {

    private final SshBruteForceService service;

    public SshBruteForceController(SshBruteForceService service) {
        this.service = service;
    }

    @PostMapping("/analyze")
    public ResponseEntity<SshAnalyzeResponse> analyze(@RequestBody SshAnalyzeRequest request) {
        return ResponseEntity.ok(service.analyze(request));
    }
}
