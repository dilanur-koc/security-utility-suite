package com.example.securityutilitysuite.security;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Istegi yapanin gercek IP adresini belirler.
 *
 * NEDEN BU SINIF VAR:
 * Onceki kod {@code X-Forwarded-For} basligini sorgusuz kabul ediyordu.
 * Uygulama guvenilir bir vekil arkasinda degilse bu baslik TAMAMEN
 * SALDIRGAN KONTROLUNDEDIR: her istekte farkli bir deger gondererek
 * kaba kuvvet sayacini sonsuza kadar sifirlamak mumkundu, yani hiz
 * sinirlamasi etkisizdi.
 *
 * Yeni kural: {@code X-Forwarded-For} YALNIZCA istek gercekten guvenilir
 * bir vekilden geliyorsa dikkate alinir. Guvenilir vekil listesi
 * {@code app.security.trusted-proxies} ayarindan gelir ve varsayilan
 * olarak BOSTUR — yani hicbir baslik guvenilmez, dogrudan soket adresi
 * kullanilir. Ters vekil (nginx, ngrok, bulut yuk dengeleyici) arkasina
 * alindiginda vekilin IP'si bu listeye eklenmelidir.
 */
@Component
public class ClientIpResolver {

    private static final Logger log = LoggerFactory.getLogger(ClientIpResolver.class);

    private final Set<String> trustedProxies;

    public ClientIpResolver(
            @Value("${app.security.trusted-proxies:}") String trustedProxiesCsv) {
        this.trustedProxies = new LinkedHashSet<>();
        if (trustedProxiesCsv != null && !trustedProxiesCsv.isBlank()) {
            Arrays.stream(trustedProxiesCsv.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .forEach(trustedProxies::add);
            log.info("Güvenilen vekiller: {}", trustedProxies);
        }
    }

    /**
     * @return istegi yapanin IP adresi; hicbir zaman null donmez
     */
    public String resolve(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (remoteAddr == null || remoteAddr.isBlank()) {
            return "bilinmiyor";
        }

        // Istek guvenilir bir vekilden gelmiyorsa basliklara BAKILMAZ.
        if (!trustedProxies.contains(remoteAddr)) {
            return remoteAddr;
        }

        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded == null || forwarded.isBlank()) {
            return remoteAddr;
        }

        // Zincirdeki ilk deger asil istemcidir: "istemci, vekil1, vekil2"
        String ilk = forwarded.split(",")[0].trim();
        return ilk.isEmpty() ? remoteAddr : ilk;
    }
}
