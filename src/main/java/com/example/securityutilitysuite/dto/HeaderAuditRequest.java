package com.example.securityutilitysuite.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * POST /api/v1/headers/audit istek govdesi.
 */
public class HeaderAuditRequest {

    @NotBlank(message = "url boş olamaz")
    @Pattern(
            regexp = "^https?://[^\\s/$.?#].[^\\s]*$",
            message = "url http:// veya https:// ile başlamalı"
    )
    private String url;

    /** Yonlendirmeler takip edilsin mi (varsayilan: evet). */
    private boolean followRedirects = true;

    public HeaderAuditRequest() {
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public boolean isFollowRedirects() {
        return followRedirects;
    }

    public void setFollowRedirects(boolean followRedirects) {
        this.followRedirects = followRedirects;
    }
}
