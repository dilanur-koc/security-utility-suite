package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.IocExtractRequest;
import com.example.securityutilitysuite.dto.IocExtractResponse;
import com.example.securityutilitysuite.service.IocService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Threat Intel (IOC) Extractor icin REST ucu. */
@RestController
@RequestMapping("/api/v1/ioc")
public class IocController {

    private final IocService service;

    public IocController(IocService service) {
        this.service = service;
    }

    @PostMapping("/extract")
    public ResponseEntity<IocExtractResponse> extract(@RequestBody IocExtractRequest request) {
        return ResponseEntity.ok(service.extract(request));
    }
}
