package com.example.securityutilitysuite.dto;

import java.util.List;

/**
 * GET /api/v1/metadata/read yanit govdesi.
 *
 * @param fileName        yuklenen dosyanin adi
 * @param detectedFormat  magic-byte ile tespit edilen gercek format (JPEG/PNG/WEBP)
 * @param sizeBytes       dosya boyutu
 * @param tagCount        toplam metadata etiketi sayisi
 * @param hasGps          GPS konum bilgisi bulundu mu
 * @param gpsLatitude     bulunduysa enlem, yoksa null
 * @param gpsLongitude    bulunduysa boylam, yoksa null
 * @param tags            tum etiketler
 * @param findings        dikkat edilmesi gereken noktalar
 */
public record MetadataReadResponse(
        String fileName,
        String detectedFormat,
        long sizeBytes,
        int tagCount,
        boolean hasGps,
        Double gpsLatitude,
        Double gpsLongitude,
        List<MetadataTag> tags,
        List<Finding> findings
) {
}
