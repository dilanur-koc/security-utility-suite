package com.example.securityutilitysuite.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Request payload for POST /api/v1/logs/analyze.
 */
public class LogAnalysisRequest {

    @NotBlank(message = "logContent boş olamaz")
    private String logContent;

    /** Optional free-text label for where this log came from (filename, source name, etc.). */
    private String logSource;

    public LogAnalysisRequest() {
    }

    public LogAnalysisRequest(String logContent, String logSource) {
        this.logContent = logContent;
        this.logSource = logSource;
    }

    public String getLogContent() {
        return logContent;
    }

    public void setLogContent(String logContent) {
        this.logContent = logContent;
    }

    public String getLogSource() {
        return logSource;
    }

    public void setLogSource(String logSource) {
        this.logSource = logSource;
    }
}
