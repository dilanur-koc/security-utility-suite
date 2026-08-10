package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.SshAnalyzeRequest;
import com.example.securityutilitysuite.dto.SshAnalyzeResponse;
import com.example.securityutilitysuite.dto.SshIpSummary;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SshBruteForceServiceTest {

    private final SshBruteForceService service = new SshBruteForceService();

    private static final String SAHTE_LOG = String.join("\n",
            // 203.0.113.5: 6 basarisiz deneme -> varsayilan esik (5) asilir
            "Aug 10 10:15:20 server sshd[100]: Failed password for root from 203.0.113.5 port 51001 ssh2",
            "Aug 10 10:15:22 server sshd[100]: Failed password for invalid user admin from 203.0.113.5 port 51002 ssh2",
            "Aug 10 10:15:24 server sshd[100]: Failed password for invalid user admin from 203.0.113.5 port 51003 ssh2",
            "Aug 10 10:15:26 server sshd[100]: Failed password for invalid user test from 203.0.113.5 port 51004 ssh2",
            "Aug 10 10:15:28 server sshd[100]: Failed password for invalid user test2 from 203.0.113.5 port 51005 ssh2",
            "Aug 10 10:15:30 server sshd[100]: Failed password for invalid user test3 from 203.0.113.5 port 51006 ssh2",
            // 198.51.100.10: 3 basarisiz sonra basarili giris -> CRITICAL
            "Aug 10 10:20:00 server sshd[200]: Failed password for dila from 198.51.100.10 port 52001 ssh2",
            "Aug 10 10:20:02 server sshd[200]: Failed password for dila from 198.51.100.10 port 52002 ssh2",
            "Aug 10 10:20:04 server sshd[200]: Failed password for dila from 198.51.100.10 port 52003 ssh2",
            "Aug 10 10:20:06 server sshd[200]: Accepted password for dila from 198.51.100.10 port 52004 ssh2",
            // 192.0.2.20: tek basarisiz deneme -> bulgu uretmemeli
            "Aug 10 10:25:00 server sshd[300]: Failed password for root from 192.0.2.20 port 53001 ssh2",
            // eslesmeyen satirlar
            "Aug 10 10:26:00 server sshd[400]: Connection closed by 192.0.2.99 port 54000",
            "bu satir hic sshd formatinda degil"
    );

    @Test
    void esikiAsanIpIcinYuksekBulguVeEngellemeOnerisiUretir() {
        SshAnalyzeResponse r = service.analyze(new SshAnalyzeRequest(SAHTE_LOG, null));

        assertThat(r.threshold()).isEqualTo(5);

        Optional<SshIpSummary> ip5 = r.ipSummaries().stream()
                .filter(s -> s.ip().equals("203.0.113.5")).findFirst();
        assertThat(ip5).isPresent();
        assertThat(ip5.get().failedAttempts()).isEqualTo(6);
        assertThat(ip5.get().recommendBlock()).isTrue();
        assertThat(ip5.get().suggestedRule()).contains("203.0.113.5").contains("ufw deny");

        assertThat(r.findings()).anyMatch(f ->
                f.severity().equals("HIGH") && f.message().contains("203.0.113.5"));
    }

    @Test
    void basarisizDenemeSonrasiBasariCriticalUretir() {
        SshAnalyzeResponse r = service.analyze(new SshAnalyzeRequest(SAHTE_LOG, null));

        Optional<SshIpSummary> ip10 = r.ipSummaries().stream()
                .filter(s -> s.ip().equals("198.51.100.10")).findFirst();
        assertThat(ip10).isPresent();
        assertThat(ip10.get().failedAttempts()).isEqualTo(3);
        assertThat(ip10.get().succeededAfterFailures()).isTrue();

        assertThat(r.findings()).anyMatch(f ->
                f.severity().equals("CRITICAL") && f.message().contains("198.51.100.10"));
    }

    @Test
    void esikAltindakiIpBulguUretmez() {
        SshAnalyzeResponse r = service.analyze(new SshAnalyzeRequest(SAHTE_LOG, null));

        Optional<SshIpSummary> ip20 = r.ipSummaries().stream()
                .filter(s -> s.ip().equals("192.0.2.20")).findFirst();
        assertThat(ip20).isPresent();
        assertThat(ip20.get().failedAttempts()).isEqualTo(1);
        assertThat(ip20.get().recommendBlock()).isFalse();
        assertThat(ip20.get().suggestedRule()).isNull();
    }

    @Test
    void ozelEsikDegeriKullanilir() {
        // Esik 2 olursa 192.0.2.20 (1 deneme) yine hesaba katilmaz ama
        // 198.51.100.10 (3 deneme) artik engelleme onerisi almali.
        SshAnalyzeResponse r = service.analyze(new SshAnalyzeRequest(SAHTE_LOG, 2));

        assertThat(r.threshold()).isEqualTo(2);
        SshIpSummary ip10 = r.ipSummaries().stream()
                .filter(s -> s.ip().equals("198.51.100.10")).findFirst().orElseThrow();
        assertThat(ip10.recommendBlock()).isTrue();
    }

    @Test
    void taninmayanFormatIcinDusukBulguVerir() {
        SshAnalyzeResponse r = service.analyze(new SshAnalyzeRequest("rastgele metin\nbaska bir satir", null));

        assertThat(r.matchedLines()).isZero();
        assertThat(r.findings()).anyMatch(f -> f.severity().equals("LOW"));
    }

    @Test
    void bosGirdiHataVermeden000Doner() {
        SshAnalyzeResponse r = service.analyze(new SshAnalyzeRequest("", null));

        assertThat(r.totalLines()).isZero();
        assertThat(r.ipSummaries()).isEmpty();
    }
}
