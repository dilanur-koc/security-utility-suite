package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.DnsQueryRequest;
import com.example.securityutilitysuite.dto.DnsQueryResponse;
import com.example.securityutilitysuite.dto.Finding;
import com.example.securityutilitysuite.util.Errors;
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
import java.util.*;
import java.util.concurrent.*;

@Service
public class DnsResolverService {

    private static final Logger log = LoggerFactory.getLogger(DnsResolverService.class);

    private static final String[] RECORD_TYPES = {"A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"};

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
        if (request == null || request.getDomain() == null || request.getDomain().isBlank()) {
            return DnsQueryResponse.failed("", "Geçersiz alan adı");
        }

        String domain = request.getDomain().trim().toLowerCase();

        Map<String, List<String>> records;
        try {
            records = lookup(domain, null);
        } catch (Exception ex) {
            log.warn("DNS cozumleme basarisiz domain={}: {}", domain, ex.getMessage());
            return DnsQueryResponse.failed(domain, Errors.kisa(ex));
        }

        if (records.values().stream().allMatch(list -> list == null || list.isEmpty())) {
            return DnsQueryResponse.failed(domain, "Hiçbir DNS kaydı bulunamadı");
        }

        List<DnsQueryResponse.ResolverAnswer> resolvers = new ArrayList<>();
        Karsilastirma karsilastirma = new Karsilastirma(true, 0);

        if (request.isSpoofCheck()) {
            resolvers = cozumleyicileriKarsilastirParalel(domain);
            karsilastirma = tutarliMi(resolvers);
        }

        List<String> aRecords = safeGetList(records, "A");
        List<DnsQueryResponse.ReverseLookup> reverse = tersDns(aRecords);
        boolean consistent = karsilastirma.tutarli();
        List<Finding> findings = bulgulariCikar(domain, records, resolvers, karsilastirma, reverse);

        return new DnsQueryResponse(domain, true, null, records, resolvers, consistent, reverse, findings);
    }

    // ------------------------------------------------------------------
    // Sorgulama
    // ------------------------------------------------------------------

    private Map<String, List<String>> lookup(String domain, String resolverIp) throws Exception {
        Hashtable<String, String> env = createJndiEnv(resolverIp);

        DirContext ctx = new InitialDirContext(env);
        try {
            Map<String, List<String>> result = new LinkedHashMap<>();
            Exception ilkHata = null;

            for (String type : RECORD_TYPES) {
                try {
                    Attributes attrs = ctx.getAttributes(domain, new String[]{type});
                    result.put(type, degerleriOku(attrs.get(type)));
                } catch (Exception ex) {
                    log.debug("{} kaydi alinamadi ({}): {}", type, domain, ex.getMessage());
                    result.put(type, Collections.emptyList());
                    if (ilkHata == null) ilkHata = ex;
                }
            }

            if (result.values().stream().allMatch(List::isEmpty) && ilkHata != null) {
                throw ilkHata;
            }
            return result;
        } finally {
            closeContextQuietly(ctx);
        }
    }

    private List<String> lookupSingle(String domain, String resolverIp, String type) throws Exception {
        Hashtable<String, String> env = createJndiEnv(resolverIp);

        DirContext ctx = new InitialDirContext(env);
        try {
            Attributes attrs = ctx.getAttributes(domain, new String[]{type});
            return degerleriOku(attrs.get(type));
        } finally {
            closeContextQuietly(ctx);
        }
    }

    private Hashtable<String, String> createJndiEnv(String resolverIp) {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        env.put("com.sun.jndi.dns.timeout.initial", TIMEOUT_MS);
        env.put("com.sun.jndi.dns.timeout.retries", RETRIES);
        if (resolverIp != null) {
            env.put(Context.PROVIDER_URL, "dns://" + resolverIp);
        }
        return env;
    }

    private List<String> degerleriOku(Attribute attr) {
        List<String> values = new ArrayList<>();
        if (attr == null) return values;

        NamingEnumeration<?> all = null;
        try {
            all = attr.getAll();
            while (all.hasMore()) {
                Object obj = all.next();
                if (obj == null) continue;

                String v = String.valueOf(obj).trim();
                if (v.length() > 1 && v.startsWith("\"") && v.endsWith("\"")) {
                    v = v.substring(1, v.length() - 1);
                }
                if (!v.isEmpty()) values.add(v);
            }
        } catch (Exception ex) {
            log.debug("Kayit okunamadi: {}", ex.getMessage());
        } finally {
            if (all != null) {
                try { all.close(); } catch (Exception ignored) {}
            }
        }
        return values;
    }

    // ------------------------------------------------------------------
    // Spoofing Karsilastirmasi
    // ------------------------------------------------------------------

    private List<DnsQueryResponse.ResolverAnswer> cozumleyicileriKarsilastirParalel(String domain) {
        ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
        try {
            List<Future<DnsQueryResponse.ResolverAnswer>> futures = PUBLIC_RESOLVERS.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .map(entry -> pool.submit(() -> tekResolverSorgula(domain, entry.getKey(), entry.getValue())))
                    .toList();

            List<DnsQueryResponse.ResolverAnswer> answers = new ArrayList<>();
            for (Future<DnsQueryResponse.ResolverAnswer> future : futures) {
                try {
                    answers.add(future.get(3500, TimeUnit.MILLISECONDS));
                } catch (Exception ex) {
                    future.cancel(true);
                }
            }
            return answers;
        } finally {
            // ExecutorService.close() takilmasini önlemek için shutdownNow
            pool.shutdownNow();
        }
    }

    private DnsQueryResponse.ResolverAnswer tekResolverSorgula(String domain, String name, String ip) {
        long start = System.currentTimeMillis();
        try {
            List<String> a = lookupSingle(domain, ip, "A");
            return new DnsQueryResponse.ResolverAnswer(name, ip, a, System.currentTimeMillis() - start, null);
        } catch (Exception ex) {
            return new DnsQueryResponse.ResolverAnswer(name, ip, List.of(), System.currentTimeMillis() - start, Errors.kisa(ex));
        }
    }

    /**
     * Karsilastirma sonucu. Onceki halinde yalnizca bir boolean donuyordu ve
     * HICBIR cozumleyici yanit vermediginde de "tutarli" deniyordu — arayuz
     * yesil rozet gosteriyor, oysa karsilastirilan hicbir sey yok. Bir
     * guvenlik aracinda "veri yok" ile "sorun yok" ayni gorunmemeli.
     */
    private record Karsilastirma(boolean tutarli, int karsilastirilabilir) {
        boolean anlamli() {
            return karsilastirilabilir >= 2;
        }
    }

    private Karsilastirma tutarliMi(List<DnsQueryResponse.ResolverAnswer> answers) {
        Set<String> reference = null;
        int veriDonduren = 0;
        boolean tutarli = true;

        for (DnsQueryResponse.ResolverAnswer a : answers) {
            if (a == null || a.error() != null || a.aRecords() == null || a.aRecords().isEmpty()) continue;
            veriDonduren++;
            Set<String> current = new LinkedHashSet<>(a.aRecords());
            if (reference == null) {
                reference = current;
            } else if (!reference.equals(current)) {
                tutarli = false;
            }
        }
        return new Karsilastirma(tutarli, veriDonduren);
    }

    // ------------------------------------------------------------------
    // Ters DNS
    // ------------------------------------------------------------------

    private List<DnsQueryResponse.ReverseLookup> tersDns(List<String> aRecords) {
        if (aRecords == null || aRecords.isEmpty()) {
            return Collections.emptyList();
        }

        List<String> hedefler = aRecords.stream()
                .filter(Objects::nonNull)
                .limit(REVERSE_LOOKUP_LIMIT)
                .toList();

        ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
        try {
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
        } finally {
            pool.shutdownNow();
        }
    }

    private DnsQueryResponse.ReverseLookup tekTersDns(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            String ptr = addr.getCanonicalHostName();

            boolean confirmed = false;
            if (ptr != null && !ptr.equals(ip)) {
                try {
                    for (InetAddress back : InetAddress.getAllByName(ptr)) {
                        if (back.getHostAddress().equals(ip)) {
                            confirmed = true;
                            break;
                        }
                    }
                } catch (Exception ignored) {}
            }
            return new DnsQueryResponse.ReverseLookup(ip, Objects.equals(ptr, ip) ? null : ptr, confirmed);
        } catch (Exception ex) {
            return new DnsQueryResponse.ReverseLookup(ip, null, false);
        }
    }

    // ------------------------------------------------------------------
    // Bulgular
    // ------------------------------------------------------------------

    private List<Finding> bulgulariCikar(
            String domain,
            Map<String, List<String>> records,
            List<DnsQueryResponse.ResolverAnswer> resolvers,
            Karsilastirma karsilastirma,
            List<DnsQueryResponse.ReverseLookup> reverse) {

        List<Finding> f = new ArrayList<>();

        // Spoofing kontrolü
        if (resolvers != null && !resolvers.isEmpty() && !karsilastirma.anlamli()) {
            f.add(Finding.medium(
                    "Spoofing karşılaştırması yapılamadı: genel çözümleyicilerin "
                    + karsilastirma.karsilastirilabilir() + " tanesi yanıt verdi "
                    + "(en az 2 gerekiyor). Ağ, 53 numaralı porta giden dış "
                    + "sorguları engelliyor olabilir."));
        }

        if (resolvers != null && karsilastirma.anlamli() && !karsilastirma.tutarli()) {
            f.add(new Finding("HIGH",
                    "Farklı çözümleyiciler farklı A kayıtları döndürdü. Bu bir DNS spoofing belirtisi olabilir; "
                            + "ancak CDN ve coğrafi yönlendirme de aynı sonucu verir, doğrulanmalı."));
        }

        // Yerel DNS Ayrışması
        List<String> localA = safeGetList(records, "A");
        Set<String> localSet = new LinkedHashSet<>(localA);
        if (resolvers != null) {
            for (DnsQueryResponse.ResolverAnswer a : resolvers) {
                if (a != null && a.error() == null && a.aRecords() != null && !a.aRecords().isEmpty()
                        && !localSet.isEmpty() && !localSet.equals(new LinkedHashSet<>(a.aRecords()))) {
                    f.add(new Finding("MEDIUM",
                            "Yerel çözümleyicinin yanıtı " + a.name() + " ile eşleşmiyor. "
                                    + "Yerel DNS önbelleği zehirlenmiş veya kurumsal bir yönlendirme olabilir."));
                    break;
                }
            }
        }

        // Özel IP (Private / Loopback) Kontrolü
        for (String ip : localA) {
            if (ozelAdresMi(ip)) {
                f.add(new Finding("MEDIUM",
                        "A kaydı özel/yerel bir adrese işaret ediyor: " + ip
                                + " — DNS rebinding veya yanlış yapılandırma göstergesi olabilir."));
                break;
            }
        }

        // E-Posta Güvenlik Kayıtları (SPF / DMARC / MX)
        List<String> txtRecords = safeGetList(records, "TXT");
        boolean hasMx = !safeGetList(records, "MX").isEmpty();
        boolean hasSpf = txtRecords.stream().anyMatch(t -> t != null && t.toLowerCase().startsWith("v=spf1"));

        if (!hasSpf) {
            f.add(new Finding(hasMx ? "HIGH" : "MEDIUM",
                    "SPF kaydı bulunamadı. Alan adı adına sahte e-posta gönderimi riski var."));
        }

        // Ad Sunucusu (NS) Kontrolü
        int nsCount = safeGetList(records, "NS").size();
        if (nsCount == 1) {
            f.add(new Finding("MEDIUM",
                    "Tek ad sunucusu (NS) tanımlı. Tek nokta arızası (SPOF) riski var."));
        }

        // Ters DNS Doğrulaması
        if (reverse != null && !reverse.isEmpty()) {
            long unconfirmed = reverse.stream().filter(r -> r != null && !r.forwardConfirmed()).count();
            if (unconfirmed == reverse.size()) {
                f.add(new Finding("LOW",
                        "Hiçbir A kaydı ileri doğrulamalı ters DNS ile eşleşmedi."));
            }
        }

        return f;
    }

    // ------------------------------------------------------------------
    // Yardımcı Metodlar
    // ------------------------------------------------------------------

    private List<String> safeGetList(Map<String, List<String>> map, String key) {
        if (map == null) return Collections.emptyList();
        List<String> list = map.get(key);
        return list != null ? list : Collections.emptyList();
    }

    private boolean ozelAdresMi(String ip) {
        if (ip == null || ip.isBlank()) return false;
        try {
            InetAddress a = InetAddress.getByName(ip);
            return a.isSiteLocalAddress() || a.isLoopbackAddress()
                    || a.isLinkLocalAddress() || a.isAnyLocalAddress();
        } catch (Exception ex) {
            return false;
        }
    }

    private void closeContextQuietly(DirContext ctx) {
        if (ctx != null) {
            try {
                ctx.close();
            } catch (Exception ignored) {}
        }
    }

}