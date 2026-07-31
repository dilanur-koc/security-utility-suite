package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.FileIntegrityRequest;
import com.example.securityutilitysuite.model.FileIntegrityRecord;
import com.example.securityutilitysuite.service.FileIntegrityService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.NoSuchElementException;

/**
 * REST endpoints for the File Integrity Verifier module.
 */
@RestController
@RequestMapping("/api/v1/integrity")
public class FileIntegrityController {

    private final FileIntegrityService fileIntegrityService;

    public FileIntegrityController(FileIntegrityService fileIntegrityService) {
        this.fileIntegrityService = fileIntegrityService;
    }

    /** Captures (or resets) the SHA-256 baseline for a file path. */
    @PostMapping("/baseline")
    public ResponseEntity<FileIntegrityRecord> createBaseline(@Valid @RequestBody FileIntegrityRequest request) {
        FileIntegrityRecord record = fileIntegrityService.createBaseline(request.getFilePath());
        return ResponseEntity.status(HttpStatus.CREATED).body(record);
    }

    /** Re-checks a single tracked file against its stored baseline. */
    @PostMapping("/check/{id}")
    public ResponseEntity<FileIntegrityRecord> checkFile(@PathVariable Long id) {
        return ResponseEntity.ok(fileIntegrityService.checkFile(id));
    }

    /** Re-checks every tracked file. */
    @PostMapping("/check-all")
    public ResponseEntity<List<FileIntegrityRecord>> checkAll() {
        return ResponseEntity.ok(fileIntegrityService.checkAll());
    }

    /** Lists all tracked files with their latest known status. */
    @GetMapping("/files")
    public ResponseEntity<List<FileIntegrityRecord>> listFiles() {
        return ResponseEntity.ok(fileIntegrityService.listAll());
    }

    /** Stops tracking a file. */
    @DeleteMapping("/files/{id}")
    public ResponseEntity<Void> deleteFile(@PathVariable Long id) {
        fileIntegrityService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @org.springframework.web.bind.annotation.ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<java.util.Map<String, String>> handleNotFound(NoSuchElementException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(java.util.Map.of("error", ex.getMessage()));
    }
}
