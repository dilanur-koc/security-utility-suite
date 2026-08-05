package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.SslCheckRequest;
import com.example.securityutilitysuite.dto.SslCheckResponse;
import com.example.securityutilitysuite.model.SslCheckResult;
import com.example.securityutilitysuite.repository.SslCheckResultRepository;
import com.example.securityutilitysuite.security.NetworkGuard;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.InetSocketAddress;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;

/**
 * Bir host'un TLS sertifikasini denetler.
 *
 * Tasarim notlari:
 * - Denetim iki asamalidir. Once sistemin varsayilan guven deposuyla (normal
 *   dogrulama acik) el sikismasi denenir. Basarisiz olursa — ki suresi dolmus,
 *   kendinden imzali veya host adi uyusmayan sertifikalarda tam olarak bu olur —
 *   sertifikayi yine de OKUYABILMEK icin dogrulamasiz ikinci bir el sikismasi
 *   yapilir ve sonuc "guvenilir degil" olarak isaretlenir. Bir denetim araci,
 *   bozuk sertifikayi gizlemek yerine gostermek zorundadir.
 * - Dogrulamasiz baglanti YALNIZCA sertifika okumak icindir; bu soket uzerinden
 *   hicbir veri gonderilmez ve baglanti hemen kapatilir.
 * - Sonucun ozeti veritabanina yazilir, zengin bulgular yaniti ile doner.
 */
@Service
public class SslInspectorService {

    private static final Logger log = LoggerFactory.getLogger(SslInspectorService.class);

    private static final int TIMEOUT_MS = 5000;
    private static final int EXPIRY_WARN_DAYS = 30;
    private static final int RSA_MIN_BITS = 2048;
    private static final int EC_MIN_BITS = 256;

    private final SslCheckResultRepository repository;
    private final NetworkGuard networkGuard;

    public SslInspectorService(SslCheckResultRepository repository, NetworkGuard networkGuard) {
        this.repository = repository;
        this.networkGuard = networkGuard;
    }

    @Transactional
    public SslCheckResponse inspect(SslCheckRequest request) {
        String host = request.getDomain();
        int port = request.getPort();

        // SSRF/ic ag taramasi korumasi. Bu modulde port alani da bulundugu
        // icin kontrol ozellikle onemli: aksi halde arac, uygulamanin ag
        // konumundan ic ag port tarayicisina donusurdu (baglanabilen porttan
        // TLS hatasi, baglanamayandan zaman asimi doner; ikisi ayirt edilebilir).
        networkGuard.verifyPublicTarget(host);

        Handshake hs;
        try {
            hs = handshake(host, port, true);
        } catch (Exception strictFailure) {
            // Dogrulama basarisiz — sertifikayi yine de okumaya calis.
            try {
                hs = handshake(host, port, false);
                hs = new Handshake(hs.chain(), hs.protocol(), hs.cipherSuite(), false,
                        strictFailure.getMessage());
            } catch (Exception ex) {
                log.warn("TLS el sikismasi basarisiz host={} port={}: {}", host, port, ex.getMessage());
                return SslCheckResponse.unreachable(host, port, kisaHata(ex));
            }
        }

        X509Certificate cert = (X509Certificate) hs.chain()[0];
        return degerlendir(host, port, cert, hs);
    }

    @Transactional(readOnly = true)
    public List<SslCheckResult> history(String domain) {
        return (domain == null || domain.isBlank())
                ? repository.findAll()
                : repository.findByDomain(domain);
    }

    // ------------------------------------------------------------------
    // El sikismasi
    // ------------------------------------------------------------------

    private record Handshake(Certificate[] chain, String protocol, String cipherSuite,
                             boolean trusted, String trustError) {
    }

    private Handshake handshake(String host, int port, boolean validate) throws Exception {
        SSLSocketFactory factory = validate
                ? (SSLSocketFactory) SSLSocketFactory.getDefault()
                : inspectionOnlyFactory();

        try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
            socket.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);

            SSLParameters params = socket.getSSLParameters();
            // SNI: ayni IP uzerinde birden fazla site barinabilir, dogru
            // sertifikanin gelmesi icin host adini bildirmemiz gerekiyor.
            params.setServerNames(List.<SNIServerName>of(new SNIHostName(host)));
            if (validate) {
                params.setEndpointIdentificationAlgorithm("HTTPS");
            }
            socket.setSSLParameters(params);

            socket.startHandshake();
            SSLSession session = socket.getSession();
            return new Handshake(session.getPeerCertificates(),
                    session.getProtocol(), session.getCipherSuite(), validate, null);
        }
    }

    /**
     * Yalnizca sertifika OKUMAK icin, dogrulama yapmayan bir fabrika uretir.
     * Bu soket uzerinden veri alisverisi yapilmaz; amac reddedilen bir
     * sertifikanin icerigini kullaniciya gosterebilmektir.
     */
    private SSLSocketFactory inspectionOnlyFactory() throws Exception {
        TrustManager[] inspectOnly = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                        // Denetim modu: dogrulama bilerek yapilmaz.
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                        // Denetim modu: dogrulama bilerek yapilmaz.
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, inspectOnly, new java.security.SecureRandom());
        return ctx.getSocketFactory();
    }

    // ------------------------------------------------------------------
    // Degerlendirme
    // ------------------------------------------------------------------

    private SslCheckResponse degerlendir(String host, int port, X509Certificate cert, Handshake hs) {
        LocalDateTime validFrom = toLocal(cert.getNotBefore().toInstant());
        LocalDateTime validTo = toLocal(cert.getNotAfter().toInstant());
        long daysRemaining = Duration.between(Instant.now(), cert.getNotAfter().toInstant()).toDays();

        boolean expired = false;
        boolean notYetValid = false;
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException e) {
            expired = true;
        } catch (CertificateNotYetValidException e) {
            notYetValid = true;
        }

        String subject = cert.getSubjectX500Principal().getName();
        String issuer = cert.getIssuerX500Principal().getName();
        boolean selfSigned = subject.equals(issuer);

        List<String> sans = sanListesi(cert);
        boolean hostnameMatch = hostEslesiyorMu(host, cert, sans);

        String keyAlgorithm = cert.getPublicKey().getAlgorithm();
        int keyBits = anahtarUzunlugu(cert);

        List<SslCheckResponse.Finding> findings = new ArrayList<>();

        if (expired) {
            findings.add(f("CRITICAL", "Sertifikanın süresi dolmuş (" + Math.abs(daysRemaining) + " gün önce)."));
        } else if (notYetValid) {
            findings.add(f("CRITICAL", "Sertifika henüz geçerli değil."));
        } else if (daysRemaining <= EXPIRY_WARN_DAYS) {
            findings.add(f("HIGH", "Sertifikanın bitimine " + daysRemaining + " gün kaldı."));
        }

        if (!hs.trusted()) {
            findings.add(f("HIGH", "Sertifika zinciri sistemdeki kök otoritelerle doğrulanamadı."));
        }
        if (!hostnameMatch) {
            findings.add(f("HIGH", "Sertifika '" + host + "' host adını kapsamıyor."));
        }
        if (selfSigned) {
            findings.add(f("MEDIUM", "Sertifika kendinden imzalı; genel kullanıma uygun değil."));
        }

        String sigAlg = cert.getSigAlgName();
        if (sigAlg != null && (sigAlg.toUpperCase().contains("SHA1") || sigAlg.toUpperCase().contains("MD5"))) {
            findings.add(f("HIGH", "Zayıf imza algoritması: " + sigAlg));
        }

        if ("RSA".equalsIgnoreCase(keyAlgorithm) && keyBits > 0 && keyBits < RSA_MIN_BITS) {
            findings.add(f("HIGH", "RSA anahtarı çok kısa: " + keyBits + " bit (en az " + RSA_MIN_BITS + " olmalı)."));
        }
        if ("EC".equalsIgnoreCase(keyAlgorithm) && keyBits > 0 && keyBits < EC_MIN_BITS) {
            findings.add(f("HIGH", "EC anahtarı çok kısa: " + keyBits + " bit."));
        }

        // Zincirdeki ARA sertifikalar da denetlenir. Yalnizca yaprak sertifikaya
        // bakmak, suresi dolmus bir ara sertifikayi gozden kacirir; tarayici
        // ise zincirin tamamini dogruladigi icin siteyi yine de reddeder.
        for (int i = 1; i < hs.chain().length; i++) {
            if (!(hs.chain()[i] instanceof X509Certificate ara)) continue;
            try {
                ara.checkValidity();
            } catch (CertificateExpiredException e) {
                findings.add(f("HIGH", "Zincirdeki ara sertifikanın süresi dolmuş: "
                        + kisaAd(ara.getSubjectX500Principal().getName())));
            } catch (CertificateNotYetValidException e) {
                findings.add(f("HIGH", "Zincirdeki ara sertifika henüz geçerli değil: "
                        + kisaAd(ara.getSubjectX500Principal().getName())));
            }
            String araAlg = ara.getSigAlgName();
            if (araAlg != null && (araAlg.toUpperCase().contains("SHA1")
                    || araAlg.toUpperCase().contains("MD5"))) {
                findings.add(f("HIGH", "Ara sertifikada zayıf imza algoritması: " + araAlg));
            }
        }

        String protocol = hs.protocol();
        if (protocol != null && (protocol.contains("1.0") || protocol.contains("1.1") || protocol.startsWith("SSL"))) {
            findings.add(f("HIGH", "Eski protokol sürümü kullanılıyor: " + protocol));
        }

        String cipher = hs.cipherSuite();
        if (cipher != null && (cipher.contains("_RC4_") || cipher.contains("_3DES_")
                || cipher.contains("_NULL_") || cipher.contains("_MD5"))) {
            findings.add(f("HIGH", "Zayıf şifre takımı: " + cipher));
        }

        kaydet(host, issuer, validFrom, validTo, daysRemaining, expired);

        return new SslCheckResponse(
                host, port, true, null,
                subject, issuer, validFrom, validTo, daysRemaining,
                expired, notYetValid, hs.trusted(), hostnameMatch, selfSigned,
                sigAlg, keyAlgorithm, keyBits,
                cert.getSerialNumber().toString(16),
                protocol, cipher, hs.chain().length,
                sans, findings
        );
    }

    /**
     * Ayni alan adi icin YENI satir acmak yerine mevcut kaydi gunceller.
     * Onceki halinde her denetim bir satir ekliyordu; ayni domain birkac kez
     * kontrol edilince tablo gereksiz sisiyordu.
     */
    private void kaydet(String domain, String issuer, LocalDateTime from, LocalDateTime to,
                        long daysRemaining, boolean expired) {
        String kisaIssuer = (issuer != null && issuer.length() > 500)
                ? issuer.substring(0, 500) : issuer;

        var mevcut = repository.findByDomain(domain);
        if (!mevcut.isEmpty()) {
            SslCheckResult kayit = mevcut.get(0);
            kayit.setIssuer(kisaIssuer);
            kayit.setValidFrom(from);
            kayit.setValidTo(to);
            kayit.setDaysRemaining(daysRemaining);
            kayit.setExpired(expired);
            kayit.setCheckedAt(LocalDateTime.now());
            repository.save(kayit);

            // Gecmiste birikmis fazla satirlar varsa temizle
            if (mevcut.size() > 1) {
                repository.deleteAll(mevcut.subList(1, mevcut.size()));
            }
            return;
        }

        repository.save(SslCheckResult.builder()
                .domain(domain)
                .issuer(kisaIssuer)
                .validFrom(from)
                .validTo(to)
                .daysRemaining(daysRemaining)
                .isExpired(expired)
                .build());
    }

    // ------------------------------------------------------------------
    // Yardimcilar
    // ------------------------------------------------------------------

    private static SslCheckResponse.Finding f(String severity, String message) {
        return new SslCheckResponse.Finding(severity, message);
    }

    private static LocalDateTime toLocal(Instant instant) {
        return LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
    }

    private List<String> sanListesi(X509Certificate cert) {
        List<String> result = new ArrayList<>();
        try {
            var entries = cert.getSubjectAlternativeNames();
            if (entries == null) return result;
            for (List<?> entry : entries) {
                // entry: [type, value]; 2 = dNSName, 7 = iPAddress
                if (entry.size() >= 2 && entry.get(1) instanceof String value) {
                    result.add(value);
                }
            }
        } catch (Exception ex) {
            log.debug("SAN okunamadi: {}", ex.getMessage());
        }
        return result;
    }

    /** Basit joker destegi: *.ornek.com, alt alan adlarinin tek seviyesini kapsar. */
    private boolean hostEslesiyorMu(String host, X509Certificate cert, List<String> sans) {
        String h = host.toLowerCase();

        for (String san : sans) {
            if (adEslesiyorMu(h, san.toLowerCase())) return true;
        }
        // SAN yoksa CN'e bak (eski sertifikalar)
        if (sans.isEmpty()) {
            String dn = cert.getSubjectX500Principal().getName();
            for (String part : dn.split(",")) {
                String p = part.trim();
                if (p.regionMatches(true, 0, "CN=", 0, 3)
                        && adEslesiyorMu(h, p.substring(3).toLowerCase())) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean adEslesiyorMu(String host, String pattern) {
        if (pattern.equals(host)) return true;
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1);           // ".ornek.com"
            int firstDot = host.indexOf('.');
            return firstDot > 0 && host.substring(firstDot).equals(suffix);
        }
        return false;
    }

    private int anahtarUzunlugu(X509Certificate cert) {
        var key = cert.getPublicKey();
        if (key instanceof RSAPublicKey rsa) {
            return rsa.getModulus().bitLength();
        }
        if (key instanceof ECPublicKey ec) {
            return ec.getParams().getCurve().getField().getFieldSize();
        }
        return 0;
    }

    /** DN icinden yalnizca CN kismini cikarir; tam DN cok uzun ve okunmaz. */
    private String kisaAd(String dn) {
        if (dn == null) return "bilinmiyor";
        for (String part : dn.split(",")) {
            String p = part.trim();
            if (p.regionMatches(true, 0, "CN=", 0, 3)) {
                return p.substring(3);
            }
        }
        return dn.length() > 60 ? dn.substring(0, 60) + "…" : dn;
    }

    private String kisaHata(Exception ex) {
        String msg = ex.getMessage();
        if (msg == null || msg.isBlank()) {
            return ex.getClass().getSimpleName();
        }
        return msg.length() > 200 ? msg.substring(0, 200) + "…" : msg;
    }
}
