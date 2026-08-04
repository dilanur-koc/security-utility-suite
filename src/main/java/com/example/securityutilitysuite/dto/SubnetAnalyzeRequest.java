package com.example.securityutilitysuite.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * POST /api/v1/subnet/analyze istek govdesi.
 *
 * En az birinin dolu olmasi beklenir; ikisi birden verilebilir.
 */
public class SubnetAnalyzeRequest {

    /** CIDR gosterimi, orn. 192.168.1.0/24 */
    @NotBlank(message = "cidr boş olamaz")
    private String cidr;

    /** Istege bagli MAC adresi, orn. 00:1A:2B:3C:4D:5E */
    private String mac;

    public SubnetAnalyzeRequest() {
    }

    public SubnetAnalyzeRequest(String cidr, String mac) {
        this.cidr = cidr;
        this.mac = mac;
    }

    public String getCidr() {
        return cidr;
    }

    public void setCidr(String cidr) {
        this.cidr = cidr;
    }

    public String getMac() {
        return mac;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }
}
