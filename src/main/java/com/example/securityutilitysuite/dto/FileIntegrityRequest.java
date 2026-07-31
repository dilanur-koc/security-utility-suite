package com.example.securityutilitysuite.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request payload for POST /api/v1/integrity/baseline.
 */
public class FileIntegrityRequest {

    @NotBlank(message = "filePath boş olamaz")
    @Size(max = 1024, message = "filePath çok uzun")
    private String filePath;

    public FileIntegrityRequest() {
    }

    public FileIntegrityRequest(String filePath) {
        this.filePath = filePath;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }
}
