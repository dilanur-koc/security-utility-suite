package com.example.securityutilitysuite.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * POST /api/v1/ssl/check istek govdesi.
 */
public class SslCheckRequest {

    @NotBlank(message = "domain boş olamaz")
    @Pattern(
            regexp = "^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?$",
            message = "domain geçerli bir host adı olmalı (protokol veya yol içermemeli)"
    )
    private String domain;

    @Min(value = 1, message = "port 1 ile 65535 arasında olmalı")
    @Max(value = 65535, message = "port 1 ile 65535 arasında olmalı")
    private int port = 443;

    public SslCheckRequest() {
    }

    public SslCheckRequest(String domain, int port) {
        this.domain = domain;
        this.port = port;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }
}
