package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.ScanRequest;
import com.example.securityutilitysuite.model.ScanResult;
import com.example.securityutilitysuite.service.PortScannerService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST endpoints for the Port Scanner module.
 *
 * Stateless by design: no session or in-memory job registry, so any
 * instance behind a load balancer can serve any request.
 */
@RestController
@RequestMapping("/api/v1/scan")
class PortScannerController {

    private final PortScannerService portScannerService;

    public PortScannerController(PortScannerService portScannerService) {
        this.portScannerService = portScannerService;
    }

    /**
     * Starts a scan and returns once it has completed. The internal probe
     * fan-out is fully concurrent (virtual threads); for very large ranges
     * consider a 202 Accepted + polling variant instead.
     */
    @PostMapping
    public ResponseEntity<ScanResult> startScan(@Valid @RequestBody ScanRequest request) {
        ScanResult result = portScannerService.scan(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    @GetMapping("/history")
    public ResponseEntity<Page<ScanResult>> getHistory(
            @PageableDefault(size = 20) Pageable pageable
    ) {
        return ResponseEntity.ok(portScannerService.getHistory(pageable));
    }
}
