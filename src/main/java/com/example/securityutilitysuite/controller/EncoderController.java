package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.EncodeRequest;
import com.example.securityutilitysuite.dto.EncodeResponse;
import com.example.securityutilitysuite.service.EncoderService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Base64 / Base64URL / Hex donusturucunun REST ucu.
 * Durum tutmaz; islem tamamen bellekte yapilir.
 */
@RestController
@RequestMapping("/api/v1/encode")
public class EncoderController {

    private final EncoderService encoderService;

    public EncoderController(EncoderService encoderService) {
        this.encoderService = encoderService;
    }

    @PostMapping
    public ResponseEntity<EncodeResponse> convert(@Valid @RequestBody EncodeRequest request) {
        return ResponseEntity.ok(encoderService.convert(request));
    }

    /**
     * Bozuk Base64/hex girdileri kullaniciya anlasilir sekilde bildirilir;
     * aksi halde arayuzde yalnizca "500" gorunurdu.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadInput(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(Map.of("message", ex.getMessage()));
    }
}
