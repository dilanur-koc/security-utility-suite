package com.example.securityutilitysuite.dto;

import java.util.List;

/**
 * POST /api/v1/webvuln/scan yanit govdesi.
 *
 * @param url                girilen hedef URL
 * @param parametersTested   test edilen parametre sayisi
 * @param requestsSent       hedefe gonderilen toplam GET istegi sayisi
 * @param results            parametre basina sonuclar
 * @param findings           genel bulgular
 */
public record WebVulnScanResponse(
        String url,
        int parametersTested,
        int requestsSent,
        List<WebVulnParamResult> results,
        List<Finding> findings
) {
}
