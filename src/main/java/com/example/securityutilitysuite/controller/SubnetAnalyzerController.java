package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.SubnetAnalyzeRequest;
import com.example.securityutilitysuite.dto.SubnetAnalyzeResponse;
import com.example.securityutilitysuite.service.SubnetAnalyzerService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Subnet & MAC OUI Analyzer modulunun REST ucu.
 * Durum tutmaz; hesaplama tamamen bellekte yapilir.
 */
@RestController
@RequestMapping("/api/v1/subnet")
public class SubnetAnalyzerController {

    private final SubnetAnalyzerService subnetAnalyzerService;

    public SubnetAnalyzerController(SubnetAnalyzerService subnetAnalyzerService) {
        this.subnetAnalyzerService = subnetAnalyzerService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<SubnetAnalyzeResponse> analyze(
            @Valid @RequestBody SubnetAnalyzeRequest request) {
        return ResponseEntity.ok(subnetAnalyzerService.analyze(request));
    }

    /**
     * Bicim hatalarini kullaniciya anlasilir sekilde dondurur; aksi halde
     * arayuzde yalnizca "500" gorunurdu.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadInput(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(Map.of("message", ex.getMessage()));
    }
}
