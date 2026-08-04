package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.DnsQueryRequest;
import com.example.securityutilitysuite.dto.DnsQueryResponse;
import com.example.securityutilitysuite.service.DnsResolverService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * DNS Query Resolver & Spoofing modulunun REST ucu.
 * Durum tutmaz; sonuclar veritabanina yazilmaz.
 */
@RestController
@RequestMapping("/api/v1/dns")
public class DnsResolverController {

    private final DnsResolverService dnsResolverService;

    public DnsResolverController(DnsResolverService dnsResolverService) {
        this.dnsResolverService = dnsResolverService;
    }

    @PostMapping("/query")
    public ResponseEntity<DnsQueryResponse> query(@Valid @RequestBody DnsQueryRequest request) {
        return ResponseEntity.ok(dnsResolverService.query(request));
    }
}
