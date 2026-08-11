package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.IocExtractRequest;
import com.example.securityutilitysuite.dto.IocExtractResponse;
import com.example.securityutilitysuite.service.IocService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/** Threat Intel (IOC) Extractor icin REST ucu. */
@RestController
@RequestMapping("/api/v1/ioc")
public class IocController {

    private final IocService service;

    public IocController(IocService service) {
        this.service = service;
    }

    @PostMapping("/extract")
    public ResponseEntity<IocExtractResponse> extract(@Valid @RequestBody IocExtractRequest request) {
        return ResponseEntity.ok(service.extract(request));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (FieldError fe : ex.getBindingResult().getFieldErrors()) {
            fields.put(fe.getField(), fe.getDefaultMessage());
        }
        return ResponseEntity.badRequest().body(Map.of("fields", fields));
    }
}
