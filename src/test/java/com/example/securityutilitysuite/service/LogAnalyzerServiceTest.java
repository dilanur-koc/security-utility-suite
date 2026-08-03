package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.enums.Severity;
import com.example.securityutilitysuite.enums.ThreatType;
import com.example.securityutilitysuite.model.SecurityLogAlert;
import com.example.securityutilitysuite.repository.SecurityLogAlertRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;

/**
 * {@link LogAnalyzerService} icin birim testleri.
 *
 * Odak noktasi ZAFIYET TESPIT DOGRULUGU: her kuralin dogru esikte
 * tetiklenmesi, dogru tehdit turu/onem derecesi atamasi ve — en az onun
 * kadar onemlisi — temiz loglarda yanlis pozitif uretmemesi.
 *
 * Repository mock'lanir; kalicilik burada test edilmez (o katman ayrica
 * @DataJpaTest ile dogrulanacak). saveAll(...) kendisine verilen listeyi
 * geri dondurur, boylece analyze()'in urettigi alert'ler uzerinde
 * dogrudan assertion yapabiliyoruz.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("LogAnalyzerService — tehdit tespiti")
class LogAnalyzerServiceTest {

    @Mock
    private SecurityLogAlertRepository repository;

    private LogAnalyzerService service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        service = new LogAnalyzerService(repository);
        lenient().when(repository.saveAll(any()))
                .thenAnswer(invocation -> new ArrayList<>(
                        (List<SecurityLogAlert>) invocation.getArgument(0)));
    }

    // ------------------------------------------------------------------
    // Yardimcilar
    // ------------------------------------------------------------------

    /** Combined log formatinda tek satir uretir. */
    private static String line(String ip, String path, int status) {
        return String.format(
                "%s - - [29/Jul/2026:10:12:03 +0300] \"GET %s HTTP/1.1\" %d 512",
                ip, path, status);
    }

    /** Ayni IP'den, ayni path/status ile n adet satir uretir. */
    private static String repeat(String ip, String path, int status, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            sb.append(line(ip, path, status)).append("\n");
        }
        return sb.toString();
    }

    // ==================================================================
    // Brute-force (401, esik = 3)
    // ==================================================================

    @Nested
    @DisplayName("Brute-force tespiti")
    class BruteForce {

        @Test
        @DisplayName("Ayni IP'den 3 basarisiz giris HIGH seviyesinde alert uretir")
        void ucBasarisizGiris_alertUretir() {
            List<SecurityLogAlert> alerts =
                    service.analyze(repeat("192.168.1.10", "/login", 401, 3), "test.log");

            assertThat(alerts).hasSize(1);
            SecurityLogAlert alert = alerts.get(0);
            assertThat(alert.getThreatType()).isEqualTo(ThreatType.BRUTE_FORCE);
            assertThat(alert.getSeverity()).isEqualTo(Severity.HIGH);
            assertThat(alert.getIpAddress()).isEqualTo("192.168.1.10");
            assertThat(alert.getLogSource()).isEqualTo("test.log");
        }

        @Test
        @DisplayName("Esigin altinda (2 deneme) alert uretilmez")
        void ikiBasarisizGiris_alertUretmez() {
            List<SecurityLogAlert> alerts =
                    service.analyze(repeat("192.168.1.10", "/login", 401, 2), "test.log");

            assertThat(alerts).isEmpty();
        }

        @Test
        @DisplayName("8 ve uzeri deneme CRITICAL seviyesine yukselir")
        void sekizBasarisizGiris_criticalOlur() {
            List<SecurityLogAlert> alerts =
                    service.analyze(repeat("192.168.1.10", "/login", 401, 8), "test.log");

            assertThat(alerts).hasSize(1);
            assertThat(alerts.get(0).getSeverity()).isEqualTo(Severity.CRITICAL);
        }

        @Test
        @DisplayName("Denemeler farkli IP'lere dagilmissa esik asilmaz")
        void farkliIpler_esigiAsmaz() {
            String log = line("10.0.0.1", "/login", 401) + "\n"
                       + line("10.0.0.2", "/login", 401) + "\n"
                       + line("10.0.0.3", "/login", 401);

            assertThat(service.analyze(log, "test.log")).isEmpty();
        }
    }

    // ==================================================================
    // Hata yigilmasi (404/500, esik = 3) ve yetkisiz erisim (403, esik = 2)
    // ==================================================================

    @Nested
    @DisplayName("Supheli aktivite tespiti")
    class SuspiciousActivity {

        @Test
        @DisplayName("3 adet 404/500 MEDIUM seviyesinde alert uretir")
        void hataYigilmasi_alertUretir() {
            String log = line("10.0.0.5", "/admin", 404) + "\n"
                       + line("10.0.0.5", "/backup", 404) + "\n"
                       + line("10.0.0.5", "/api/x", 500);

            List<SecurityLogAlert> alerts = service.analyze(log, "test.log");

            assertThat(alerts).hasSize(1);
            assertThat(alerts.get(0).getThreatType()).isEqualTo(ThreatType.SUSPICIOUS_ACTIVITY);
            assertThat(alerts.get(0).getSeverity()).isEqualTo(Severity.MEDIUM);
        }

        @Test
        @DisplayName("2 adet 403 HIGH seviyesinde alert uretir")
        void yetkisizErisim_alertUretir() {
            List<SecurityLogAlert> alerts =
                    service.analyze(repeat("10.0.0.7", "/admin", 403, 2), "test.log");

            assertThat(alerts).hasSize(1);
            assertThat(alerts.get(0).getThreatType()).isEqualTo(ThreatType.SUSPICIOUS_ACTIVITY);
            assertThat(alerts.get(0).getSeverity()).isEqualTo(Severity.HIGH);
        }

        @Test
        @DisplayName("Tek 403 esigi asmaz")
        void tek403_alertUretmez() {
            assertThat(service.analyze(line("10.0.0.7", "/admin", 403), "test.log")).isEmpty();
        }
    }

    // ==================================================================
    // SQL enjeksiyonu imzalari — URL-encoded payload'lar dahil
    // ==================================================================

    @Nested
    @DisplayName("SQL enjeksiyonu tespiti")
    class SqlInjection {

        @Test
        @DisplayName("%20 ile kodlanmis 'OR 1=1' yakalanir")
        void yuzde20IleKodlanmis_yakalanir() {
            List<SecurityLogAlert> alerts =
                    service.analyze(line("10.0.0.9", "/urun?id=1%20OR%201=1", 200), "test.log");

            assertThat(alerts).hasSize(1);
            assertThat(alerts.get(0).getThreatType()).isEqualTo(ThreatType.SQL_INJECTION);
            assertThat(alerts.get(0).getSeverity()).isEqualTo(Severity.CRITICAL);
        }

        @Test
        @DisplayName("+ ile kodlanmis \"' OR '1'='1\" yakalanir")
        void artiIleKodlanmis_yakalanir() {
            List<SecurityLogAlert> alerts =
                    service.analyze(line("10.0.0.9", "/urun?id=1'+OR+'1'='1", 200), "test.log");

            assertThat(alerts).hasSize(1);
            assertThat(alerts.get(0).getThreatType()).isEqualTo(ThreatType.SQL_INJECTION);
        }

        @Test
        @DisplayName("UNION SELECT yakalanir")
        void unionSelect_yakalanir() {
            List<SecurityLogAlert> alerts = service.analyze(
                    line("10.0.0.9", "/ara?q=union%20select%20*%20from%20users", 200), "test.log");

            assertThat(alerts).hasSize(1);
            assertThat(alerts.get(0).getThreatType()).isEqualTo(ThreatType.SQL_INJECTION);
        }

        @Test
        @DisplayName("Combined formata uymayan ham satirdaki payload da yakalanir")
        void parseEdilemeyenSatir_yakalanir() {
            // Regresyon testi: bu satir combined log formatina uymuyor, path ""
            // olarak geliyordu ve ham metin hic taranmiyordu.
            String log = "Jul 29 10:15:22 web01 app: query failed: "
                       + "SELECT * FROM users WHERE id=1 OR 1=1";

            List<SecurityLogAlert> alerts = service.analyze(log, "syslog");

            assertThat(alerts).hasSize(1);
            assertThat(alerts.get(0).getThreatType()).isEqualTo(ThreatType.SQL_INJECTION);
            assertThat(alerts.get(0).getIpAddress()).isEqualTo("unknown");
        }
    }

    // ==================================================================
    // XSS imzalari
    // ==================================================================

    @Nested
    @DisplayName("XSS tespiti")
    class Xss {

        @Test
        @DisplayName("<script> etiketi HIGH seviyesinde yakalanir")
        void scriptEtiketi_yakalanir() {
            List<SecurityLogAlert> alerts = service.analyze(
                    line("10.0.0.11", "/p?q=<script>alert(1)</script>", 200), "test.log");

            assertThat(alerts).hasSize(1);
            assertThat(alerts.get(0).getThreatType()).isEqualTo(ThreatType.XSS);
            assertThat(alerts.get(0).getSeverity()).isEqualTo(Severity.HIGH);
        }

        @Test
        @DisplayName("URL-encoded onerror= yakalanir")
        void kodlanmisOnerror_yakalanir() {
            List<SecurityLogAlert> alerts = service.analyze(
                    line("10.0.0.11", "/p?img=x%20onerror=alert(1)", 200), "test.log");

            assertThat(alerts).hasSize(1);
            assertThat(alerts.get(0).getThreatType()).isEqualTo(ThreatType.XSS);
        }
    }

    // ==================================================================
    // Yanlis pozitif kontrolu ve genel davranis
    // ==================================================================

    @Nested
    @DisplayName("Yanlis pozitif ve genel davranis")
    class GeneralBehaviour {

        @Test
        @DisplayName("Tamamen temiz log hic alert uretmez")
        void temizLog_alertUretmez() {
            String log = line("10.0.0.20", "/index.html", 200) + "\n"
                       + line("10.0.0.20", "/urunler/kategori-2/detay", 200) + "\n"
                       + line("10.0.0.20", "/api/v1/report?from=2026-01-01", 200) + "\n"
                       + line("10.0.0.21", "/hakkimizda", 304);

            assertThat(service.analyze(log, "test.log")).isEmpty();
        }

        @Test
        @DisplayName("Bos ve bosluklu satirlar atlanir")
        void bosSatirlar_atlanir() {
            assertThat(service.analyze("\n   \n\n", "test.log")).isEmpty();
        }

        @Test
        @DisplayName("Ayni satir hem SQLi hem XSS iceriyorsa iki ayri alert uretilir")
        void ikiImza_ikiAlertUretir() {
            List<SecurityLogAlert> alerts = service.analyze(
                    line("10.0.0.30", "/p?q=1%20OR%201=1&r=<script>alert(1)</script>", 200),
                    "test.log");

            assertThat(alerts).hasSize(2);
            assertThat(alerts).extracting(SecurityLogAlert::getThreatType)
                    .containsExactlyInAnyOrder(ThreatType.SQL_INJECTION, ThreatType.XSS);
        }

        @Test
        @DisplayName("logSource bos birakilirsa 'manual-paste' atanir")
        void bosLogSource_varsayilanaDuser() {
            List<SecurityLogAlert> alerts =
                    service.analyze(repeat("10.0.0.40", "/login", 401, 3), "   ");

            assertThat(alerts).hasSize(1);
            assertThat(alerts.get(0).getLogSource()).isEqualTo("manual-paste");
        }

        @Test
        @DisplayName("Bozuk yuzde dizisi (%zz) hata firlatmadan islenir")
        void bozukYuzdeDizisi_patlamaz() {
            List<SecurityLogAlert> alerts =
                    service.analyze(line("10.0.0.50", "/ara?q=%zz%", 200), "test.log");

            assertThat(alerts).isEmpty();
        }

        @Test
        @DisplayName("Farkli kurallar ayni IP icin ayri ayri tetiklenebilir")
        void birdenFazlaKural_ayriAlertUretir() {
            String log = repeat("10.0.0.60", "/login", 401, 3)
                       + repeat("10.0.0.60", "/admin", 403, 2);

            List<SecurityLogAlert> alerts = service.analyze(log, "test.log");

            assertThat(alerts).hasSize(2);
            assertThat(alerts).extracting(SecurityLogAlert::getThreatType)
                    .containsExactlyInAnyOrder(ThreatType.BRUTE_FORCE, ThreatType.SUSPICIOUS_ACTIVITY);
        }
    }
}
