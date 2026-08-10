package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.MetadataReadResponse;
import com.example.securityutilitysuite.service.MetadataService;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

/**
 * Metadata (EXIF) Cleaner icin REST ucu.
 * v1: JPEG / PNG / WEBP. Yuklenen dosya diske yazilmaz, bellekte islenir.
 */
@RestController
@RequestMapping("/api/v1/metadata")
public class MetadataController {

    /** Kaza ile devasa dosya yuklenmesini onlemek icin ust sinir. */
    private static final long MAX_SIZE_BYTES = 25L * 1024 * 1024; // 25 MB

    private final MetadataService metadataService;

    public MetadataController(MetadataService metadataService) {
        this.metadataService = metadataService;
    }

    @PostMapping("/read")
    public ResponseEntity<MetadataReadResponse> read(@RequestParam("file") MultipartFile file) throws IOException {
        validate(file);
        return ResponseEntity.ok(metadataService.read(file));
    }

    @PostMapping("/clean")
    public ResponseEntity<byte[]> clean(@RequestParam("file") MultipartFile file) throws IOException {
        validate(file);
        MetadataService.CleanedFile result = metadataService.clean(file);

        String originalName = file.getOriginalFilename() != null ? file.getOriginalFilename() : "dosya";
        String cleanedName = "cleaned_" + originalName;
        MediaType contentType = switch (result.format()) {
            case JPEG -> MediaType.IMAGE_JPEG;
            case PNG -> MediaType.IMAGE_PNG;
            case WEBP -> MediaType.parseMediaType("image/webp");
        };

        return ResponseEntity.ok()
                .contentType(contentType)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(cleanedName).build().toString())
                .header("X-Detected-Format", result.format().name())
                .body(result.data());
    }

    private void validate(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Dosya bos olamaz");
        }
        if (file.getSize() > MAX_SIZE_BYTES) {
            throw new IllegalArgumentException("Dosya cok buyuk (ust sinir 25 MB)");
        }
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadInput(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(Map.of("message", ex.getMessage()));
    }
}
