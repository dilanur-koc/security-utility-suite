package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.LogAnalysisRequest;
import com.example.securityutilitysuite.model.SecurityLogAlert;
import com.example.securityutilitysuite.service.LogAnalyzerService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * REST endpoints for the Log Analyzer module.
 */
@RestController
@RequestMapping("/api/v1/logs")
public class LogAnalyzerController {

    private final LogAnalyzerService logAnalyzerService;

    public LogAnalyzerController(LogAnalyzerService logAnalyzerService) {
        this.logAnalyzerService = logAnalyzerService;
    }

    /** Analyzes pasted/uploaded log text and returns the newly detected alerts. */
    @PostMapping("/analyze")
    public ResponseEntity<List<SecurityLogAlert>> analyze(@Valid @RequestBody LogAnalysisRequest request) {
        List<SecurityLogAlert> alerts = logAnalyzerService.analyze(request.getLogContent(), request.getLogSource());
        return ResponseEntity.ok(alerts);
    }

    /** Returns the full alert history, most recent first. */
    @GetMapping("/alerts")
    public ResponseEntity<Page<SecurityLogAlert>> getAlerts(
            @PageableDefault(size = 50, sort = "detectedAt", direction = Sort.Direction.DESC) Pageable pageable
    ) {
        return ResponseEntity.ok(logAnalyzerService.getAlerts(pageable));
    }
}
