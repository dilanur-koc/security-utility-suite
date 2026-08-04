package com.example.securityutilitysuite.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * POST /api/v1/dns/query istek govdesi.
 */
public class DnsQueryRequest {

    @NotBlank(message = "domain boş olamaz")
    @Pattern(
            regexp = "^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?$",
            message = "domain geçerli bir alan adı olmalı (protokol veya yol içermemeli)"
    )
    private String domain;

    /** true ise birden fazla genel cozumleyiciye sorulup yanitlar karsilastirilir. */
    private boolean spoofCheck = true;

    public DnsQueryRequest() {
    }

    public DnsQueryRequest(String domain, boolean spoofCheck) {
        this.domain = domain;
        this.spoofCheck = spoofCheck;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public boolean isSpoofCheck() {
        return spoofCheck;
    }

    public void setSpoofCheck(boolean spoofCheck) {
        this.spoofCheck = spoofCheck;
    }
}
