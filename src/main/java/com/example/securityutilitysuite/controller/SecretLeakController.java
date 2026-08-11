package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.SecretScanRequest;
import com.example.securityutilitysuite.dto.SecretScanResponse;
import com.example.securityutilitysuite.service.SecretLeakService;
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

/** Git & Secret Leak Finder icin REST ucu. */
@RestController
@RequestMapping("/api/v1/secrets")
public class SecretLeakController {

    private final SecretLeakService service;

    public SecretLeakController(SecretLeakService service) {
        this.service = service;
    }

    @PostMapping("/scan")
    public ResponseEntity<SecretScanResponse> scan(@Valid @RequestBody SecretScanRequest request) {
        return ResponseEntity.ok(service.scan(request));
    }

    /**
     * @Valid tetiklendiginde Spring bu exception'i firlatir. Yakalanmazsa
     * kullaniciya bicimlendirilmemis, genel bir 400 doner. Diger modullerin
     * (EncoderController vb.) zaten kullandigi "fields" haritasi bicimiyle
     * tutarli tutuluyor — frontend JS zaten body.fields'i bekliyor.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (FieldError fe : ex.getBindingResult().getFieldErrors()) {
            fields.put(fe.getField(), fe.getDefaultMessage());
        }
        return ResponseEntity.badRequest().body(Map.of("fields", fields));
    }
}
