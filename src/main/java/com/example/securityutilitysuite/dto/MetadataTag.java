package com.example.securityutilitysuite.dto;

/**
 * Tek bir metadata etiketi (orn. "Exif IFD0" / "Model" / "iPhone 14 Pro").
 *
 * @param directory   etiketin ait oldugu grup (Exif IFD0, GPS, PNG-tEXt, vb.)
 * @param tagName     etiket adi
 * @param description okunabilir deger
 */
public record MetadataTag(String directory, String tagName, String description) {
}
