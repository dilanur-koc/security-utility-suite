package com.example.securityutilitysuite.model;


import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Request payload for POST /api/v1/scan.
 */
public class ScanResult {

    @NotBlank(message = "targetHost boş olamaz")
    @Pattern(
            regexp = "^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?$",
            message = "targetHost geçerli bir host adı veya IP olmalı"
    )
    private String targetHost;

    @Min(value = 1, message = "startPort 1 ile 65535 arasında olmalı")
    @Max(value = 65535, message = "startPort 1 ile 65535 arasında olmalı")
    private int startPort;

    @Min(value = 1, message = "endPort 1 ile 65535 arasında olmalı")
    @Max(value = 65535, message = "endPort 1 ile 65535 arasında olmalı")
    private int endPort;

    public ScanResult() {
    }

    public ScanResult(String targetHost, int startPort, int endPort) {
        this.targetHost = targetHost;
        this.startPort = startPort;
        this.endPort = endPort;
    }

    @AssertTrue(message = "startPort, endPort değerinden büyük olamaz")
    public boolean isRangeValid() {
        return startPort <= endPort;
    }

    @AssertTrue(message = "Tek seferde en fazla 10.000 port taranabilir")
    public boolean isRangeWithinLimit() {
        return (endPort - startPort) <= 10_000;
    }

    public String getTargetHost() {
        return targetHost;
    }

    public void setTargetHost(String targetHost) {
        this.targetHost = targetHost;
    }

    public int getStartPort() {
        return startPort;
    }

    public void setStartPort(int startPort) {
        this.startPort = startPort;
    }

    public int getEndPort() {
        return endPort;
    }

    public void setEndPort(int endPort) {
        this.endPort = endPort;
    }
}