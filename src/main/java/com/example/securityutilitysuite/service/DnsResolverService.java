package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.DnsQueryRequest;
import com.example.securityutilitysuite.dto.DnsQueryResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * DNS kayitlarini sorgular ve olasi spoofing/onbellek zehirlenmesi
 * belirtilerini analiz eder.
 *
 * Tasarim notlari:
 * - Sorgular JDK'nin kendi DNS saglayicisi (JNDI) uzerinden yapilir; harici
 *   bir kutuphane gerekmez.
 * - Spoofing tespiti dogrudan olcelemez. Bunun yerine ayni soru birden fazla
 *   BAGIMSIZ genel cozumleyiciye sorulur ve yanitlar karsilastirilir. Yanitlar
 *   ayrisiyorsa bu bir uyaridir — ancak CDN ve cografi yonlendirme de ayni
 *   etkiyi yarattigi icin bulgu KESIN degil, "incelenmeli" seviyesindedir.
 * - Modul durum tutmaz, veritabanina yazmaz: her sorgu bagimsizdir.
 */
@Service
public class DnsResolverService {

    private static final Logger log = LoggerFactory.getLogger(DnsResolverService.class);

    private static final String[] RECORD_TYPES = {"A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"};

    /** Bagimsiz isletmeciler — ayni sirketin sunucularini secmek karsilastirmayi anlamsiz kilardi. */
    private static final Map<String, String> PUBLIC_RESOLVERS = Map.of(
            "Google", "8.8.8.8",
            "Cloudflare", "1.1.1.1",
            "Quad9", "9.9.9.9"
    );

    private static final String TIMEOUT_MS = "3000";
    private static final String RETRIES = "1";

    private static final int REVERSE_LOOKUP_LIMIT = 5;
    private static final int REVERSE_TIMEOUT_SECONDS = 3;

    public DnsQueryResponse query(DnsQueryRequest request) {
        String domain = request.getDomain().toLowerCase();

        Map<String, List<String>> records;
        try {
            records = lookup(domain, null);
        } catch (Exception ex) {
            log.warn("DNS cozumleme basarisiz domain={}: {}", domain, ex.getMessage());
            return DnsQueryResponse.failed(domain, kisaHata(ex));
        }

        if (records.values().stream().allMatch(List::isEmpty)) {
            return DnsQueryResponse.failed(domain, "Hiçbir DNS kaydı bulunamadı");
        }

        List<DnsQueryResponse.ResolverAnswer> resolvers = new ArrayList<>();
        boolean consistent = true;

        if (request.isSpoofCheck()) {
            resolvers = cozumleyicileriKarsilastir(domain);
            consistent = tutarliMi(resolvers);
        }

        List<DnsQueryResponse.ReverseLookup> reverse = tersDns(records.getOrDefault("A", List.of()));
        List<DnsQueryResponse.Finding> findings =
                bulgulariCikar(domain, records, resolvers, consistent, reverse);

        return new DnsQueryResponse(domain, true, null, records, resolvers, consistent, reverse, findings);
    }

    // ------------------------------------------------------------------
    // Sorgulama
    // ------------------------------------------------------------------

    /**
     * @param resolverIp null ise sistemin varsayilan cozumleyicisi kullanilir.
     *
     * Her kayit turu AYRI sorgulanir. Tum turleri tek cagrida istemek bazi
     * cozumleyicilerde (orn. systemd-resolved) "NOTIMP / response code 4"
     * hatasina yol acar ve hicbir kayit donmez. Ayri sorgularda bir tur
     * desteklenmese bile digerleri calismaya devam eder.
     */
    private Map<String, List<String>> lookup(String domain, String resolverIp) throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        env.put("com.sun.jndi.dns.timeout.initial", TIMEOUT_MS);
        env.put("com.sun.jndi.dns.timeout.retries", RETRIES);
        if (resolverIp != null) {
            env.put(Context.PROVIDER_URL, "dns://" + resolverIp);
        }

        DirContext ctx = new InitialDirContext(env);
        try {
            Map<String, List<String>> result = new LinkedHashMap<>();
            Exception ilkHata = null;

            for (String type : RECORD_TYPES) {
                try {
                    Attributes attrs = ctx.getAttributes(domain, new String[]{type});
                    result.put(type, degerleriOku(attrs.get(type)));
                } catch (Exception ex) {
                    // Bu tur desteklenmiyor veya kayit yok — digerlerine devam.
                    log.debug("{} kaydi alinamadi ({}): {}", type, domain, ex.getMessage());
                    result.put(type, new ArrayList<>());
                    if (ilkHata == null) ilkHata = ex;
                }
            }

            // Hicbir tur donmediyse gercek bir cozumleme hatasi var demektir.
            if (result.values().stream().allMatch(List::isEmpty) && ilkHata != null) {
                throw ilkHata;
            }
            return result;
        } finally {
            try {
                ctx.close();
            } catch (Exception ignored) {
                // kapanis hatasi sonucu etkilemez
            }
        }
    }

    /** Tek bir kayit turunu sorgular; karsilastirma icin tum turleri cekmeye gerek yok. */
    private List<String> lookupSingle(String domain, String resolverIp, String type) throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        env.put("com.sun.jndi.dns.timeout.initial", TIMEOUT_MS);
        env.put("com.sun.jndi.dns.timeout.retries", RETRIES);
        if (resolverIp != null) {
            env.put(Context.PROVIDER_URL, "dns://" + resolverIp);
        }

        DirContext ctx = new InitialDirContext(env);
        try {
            Attributes attrs = ctx.getAttributes(domain, new String[]{type});
            return degerleriOku(attrs.get(type));
        } finally {
            try {
                ctx.close();
            } catch (Exception ignored) {
                // kapanis hatasi sonucu etkilemez
            }
        }
    }

    private List<String> degerleriOku(Attribute attr) {
        List<String> values = new ArrayList<>();
        if (attr == null) return values;
        try {
            NamingEnumeration<?> all = attr.getAll();
            while (all.hasMore()) {
                String v = String.valueOf(all.next()).trim();
                // TXT kayitlari tirnakli gelebilir
                if (v.length() > 1 && v.startsWith("\"") && v.endsWith("\"")) {
                    v = v.substring(1, v.length() - 1);
                }
                if (!v.isEmpty()) values.add(v);
            }
        } catch (Exception ex) {
            log.debug("Kayit okunamadi: {}", ex.getMessage());
        }
        return values;
    }

    // ------------------------------------------------------------------
    // Spoofing karsilastirmasi
    // ------------------------------------------------------------------

    private List<DnsQueryResponse.ResolverAnswer> cozumleyicileriKarsilastir(String domain) {
        List<DnsQueryResponse.ResolverAnswer> answers = new ArrayList<>();

        PUBLIC_RESOLVERS.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> {
                    long start = System.currentTimeMillis();
                    try {
                        // Karsilastirma icin YALNIZCA A kaydi gerekiyor.
                        // Onceki halinde her cozumleyiciye 7 tur soruluyordu:
                        // 3 x 7 = 21 sorgunun 18'i bosa gidiyordu.
                        List<String> a = lookupSingle(domain, entry.getValue(), "A");
                        answers.add(new DnsQueryResponse.ResolverAnswer(
                                entry.getKey(), entry.getValue(), a,
                                System.currentTimeMillis() - start, null));
                    } catch (Exception ex) {
                        answers.add(new DnsQueryResponse.ResolverAnswer(
                                entry.getKey(), entry.getValue(), List.of(),
                                System.currentTimeMillis() - start, kisaHata(ex)));
                    }
                });

        return answers;
    }

    private boolean tutarliMi(List<DnsQueryResponse.ResolverAnswer> answers) {
        Set<String> reference = null;
        for (DnsQueryResponse.ResolverAnswer a : answers) {
            if (a.error() != null || a.aRecords().isEmpty()) continue;
            Set<String> current = new LinkedHashSet<>(a.aRecords());
            if (reference == null) {
                reference = current;
            } else if (!reference.equals(current)) {
                return false;
            }
        }
        return true;
    }

    // ------------------------------------------------------------------
    // Ters DNS
    // ------------------------------------------------------------------

    /**
     * Ters DNS sorgulari ayri bir is parcaciginda ve zaman asimiyla calisir.
     * {@link InetAddress#getCanonicalHostName()} zaman asimi parametresi kabul
     * etmiyor; yanit vermeyen bir PTR sunucusu istegi uzun sure askida
     * birakabiliyordu. Sure asilirsa o IP "cozumlenemedi" olarak isaretlenir.
     */
    private List<DnsQueryResponse.ReverseLookup> tersDns(List<String> aRecords) {
        List<String> hedefler = aRecords.stream().limit(REVERSE_LOOKUP_LIMIT).toList();
        if (hedefler.isEmpty()) {
            return List.of();
        }

        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<DnsQueryResponse.ReverseLookup>> futures = hedefler.stream()
                    .map(ip -> pool.submit(() -> tekTersDns(ip)))
                    .toList();

            List<DnsQueryResponse.ReverseLookup> result = new ArrayList<>();
            for (int i = 0; i < futures.size(); i++) {
                try {
                    result.add(futures.get(i).get(REVERSE_TIMEOUT_SECONDS, TimeUnit.SECONDS));
                } catch (Exception ex) {
                    futures.get(i).cancel(true);
                    result.add(new DnsQueryResponse.ReverseLookup(hedefler.get(i), null, false));
                }
            }
            return result;
        }
    }

    private DnsQueryResponse.ReverseLookup tekTersDns(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            String ptr = addr.getCanonicalHostName();

            boolean confirmed = false;
            if (!ptr.equals(ip)) {
                // Ileri dogrulama: PTR adi tekrar cozumlendiginde ayni IP'ye donuyor mu?
                try {
                    for (InetAddress back : InetAddress.getAllByName(ptr)) {
                        if (back.getHostAddress().equals(ip)) {
                            confirmed = true;
                            break;
                        }
                    }
                } catch (Exception ignored) {
                    // cozumlenemiyorsa dogrulanmamis sayilir
                }
            }
            return new DnsQueryResponse.ReverseLookup(ip, ptr.equals(ip) ? null : ptr, confirmed);
        } catch (Exception ex) {
            return new DnsQueryResponse.ReverseLookup(ip, null, false);
        }
    }

    // ------------------------------------------------------------------
    // Bulgular
    // ------------------------------------------------------------------

    private List<DnsQueryResponse.Finding> bulgulariCikar(
            String domain,
            Map<String, List<String>> records,
            List<DnsQueryResponse.ResolverAnswer> resolvers,
            boolean consistent,
            List<DnsQueryResponse.ReverseLookup> reverse) {

        List<DnsQueryResponse.Finding> f = new ArrayList<>();

        // --- Spoofing belirtisi ---
        if (!resolvers.isEmpty() && !consistent) {
            f.add(new DnsQueryResponse.Finding("HIGH",
                    "Farklı çözümleyiciler farklı A kayıtları döndürdü. "
                    + "Bu bir DNS spoofing belirtisi olabilir; ancak CDN ve coğrafi "
                    + "yönlendirme de aynı sonucu verir, doğrulanmalı."));
        }

        // --- Yerel çözümleyici ile genel çözümleyiciler ayrışıyor mu ---
        Set<String> local = new LinkedHashSet<>(records.getOrDefault("A", List.of()));
        for (DnsQueryResponse.ResolverAnswer a : resolvers) {
            if (a.error() == null && !a.aRecords().isEmpty()
                    && !local.isEmpty() && !local.equals(new LinkedHashSet<>(a.aRecords()))) {
                f.add(new DnsQueryResponse.Finding("MEDIUM",
                        "Yerel çözümleyicinin yanıtı " + a.name() + " ile eşleşmiyor. "
                        + "Yerel DNS önbelleği zehirlenmiş veya kurumsal bir yönlendirme olabilir."));
                break;
            }
        }

        // --- Özel IP aralığı ---
        for (String ip : records.getOrDefault("A", List.of())) {
            if (ozelAdresMi(ip)) {
                f.add(new DnsQueryResponse.Finding("MEDIUM",
                        "A kaydı özel/yerel bir adrese işaret ediyor: " + ip
                        + " — DNS rebinding veya yanlış yapılandırma göstergesi olabilir."));
                break;
            }
        }

        // --- E-posta kimlik doğrulama kayıtları ---
        List<String> txt = records.getOrDefault("TXT", List.of());
        boolean hasSpf = txt.stream().anyMatch(t -> t.toLowerCase().startsWith("v=spf1"));
        boolean hasMx = !records.getOrDefault("MX", List.of()).isEmpty();

        if (!hasSpf) {
            f.add(new DnsQueryResponse.Finding(hasMx ? "HIGH" : "MEDIUM",
                    "SPF kaydı yok. Alan adı adına sahte e-posta gönderimi kolaylaşır."));
        }
        if (hasMx && txt.stream().noneMatch(t -> t.toLowerCase().contains("dkim"))) {
            f.add(new DnsQueryResponse.Finding("LOW",
                    "Kök alan adında DKIM işareti görülmedi (seçici alt alanda olabilir)."));
        }

        // --- Ad sunucusu sayisi ---
        int ns = records.getOrDefault("NS", List.of()).size();
        if (ns == 1) {
            f.add(new DnsQueryResponse.Finding("MEDIUM",
                    "Tek ad sunucusu tanımlı. Tek nokta arızası riski var."));
        }

        // --- Ters DNS dogrulamasi ---
        long unconfirmed = reverse.stream().filter(r -> !r.forwardConfirmed()).count();
        if (!reverse.isEmpty() && unconfirmed == reverse.size()) {
            f.add(new DnsQueryResponse.Finding("LOW",
                    "Hiçbir A kaydı ileri doğrulamalı ters DNS ile eşleşmedi. "
                    + "Barındırma sağlayıcılarında bu normal olabilir."));
        }

        return f;
    }

    private boolean ozelAdresMi(String ip) {
        try {
            InetAddress a = InetAddress.getByName(ip);
            return a.isSiteLocalAddress() || a.isLoopbackAddress()
                    || a.isLinkLocalAddress() || a.isAnyLocalAddress();
        } catch (Exception ex) {
            return false;
        }
    }

    private String kisaHata(Exception ex) {
        String msg = ex.getMessage();
        if (msg == null || msg.isBlank()) return ex.getClass().getSimpleName();
        return msg.length() > 200 ? msg.substring(0, 200) + "…" : msg;
    }
}
