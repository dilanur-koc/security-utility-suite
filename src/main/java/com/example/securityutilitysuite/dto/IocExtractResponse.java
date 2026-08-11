package com.example.securityutilitysuite.dto;

import java.util.List;

/**
 * POST /api/v1/ioc/extract yanit govdesi.
 *
 * @param defangedCount girdide normallestirilen (defanged) gosterge sayisi
 * @param items         benzersiz IOC'lerin turune gore siniflandirilmis listesi
 * @param findings      genel bulgular
 */
public record IocExtractResponse(int defangedCount, List<IocItem> items, List<Finding> findings) {
}
