package com.example.securityutilitysuite.enums;

/**
 * Izlenebilen kontrol turleri.
 *
 * Yalnizca ZAMANLA DEGISEN seyler burada: sertifika suresi dolar, guvenlik
 * basliklari degisir, DNS kayitlari guncellenir, bir sitede yeni zafiyet
 * cikabilir. Hash hesaplama veya Base64 cevirme gibi tek seferlik islemler
 * izlemeye alinmaz — ayni girdi hep ayni sonucu verir, gecmis tutmanin
 * bilgi degeri yoktur.
 */
public enum MonitorType {

    /** Sertifika suresi, zincir gecerliligi, zayif algoritma. */
    SSL,

    /** HSTS, CSP, X-Frame-Options gibi basliklarin varligi ve degeri. */
    HTTP_HEADERS,

    /** A/MX/TXT kayitlarinda degisiklik, spoofing belirtisi. */
    DNS,

    /** Oltalama gostergeleri (typosquatting, supheli TLD). */
    PHISHING
}
