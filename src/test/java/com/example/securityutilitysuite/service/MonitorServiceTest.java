package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.DnsQueryResponse;
import com.example.securityutilitysuite.dto.Finding;
import com.example.securityutilitysuite.dto.MonitorTargetItem;
import com.example.securityutilitysuite.dto.MonitorTargetRequest;
import com.example.securityutilitysuite.enums.MonitorType;
import com.example.securityutilitysuite.enums.Role;
import com.example.securityutilitysuite.model.MonitorCheck;
import com.example.securityutilitysuite.model.MonitoredTarget;
import com.example.securityutilitysuite.model.User;
import com.example.securityutilitysuite.repository.MonitorCheckRepository;
import com.example.securityutilitysuite.repository.MonitoredTargetRepository;
import com.example.securityutilitysuite.security.CurrentUserProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * {@link MonitorService} icin birim testleri.
 *
 * ODAK: SAHIPLIK YALITIMI. Bu servisin en kritik ozelligi, bir kullanicinin
 * baskasinin kaydini gorememesi ve silememesi. Sahiplik kontrolu sessizce
 * gevserse dogrudan bir IDOR acigi olusur — bu yuzden her erisim yolu
 * ("baskasinin kaydini oku", "sil", "durumunu degistir", "gecmisini gor")
 * ayri ayri test edilir.
 *
 * Deterministik: ag cagrisi yok, alt servisler mock'lanir.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("MonitorService — izleme ve sahiplik yalıtımı")
class MonitorServiceTest {

    @Mock private MonitoredTargetRepository targetRepository;
    @Mock private MonitorCheckRepository checkRepository;
    @Mock private NotificationService notificationService;
    @Mock private CurrentUserProvider currentUser;
    @Mock private SslInspectorService sslService;
    @Mock private HttpHeaderAuditService headerService;
    @Mock private DnsResolverService dnsService;

    private MonitorService service;

    private User ayse;
    private User burak;

    @BeforeEach
    void setUp() {
        ayse = kullanici(1L, "ayse");
        burak = kullanici(2L, "burak");

        service = new MonitorService(targetRepository, checkRepository, notificationService,
                currentUser, sslService, headerService, dnsService);

        // Varsayilan olarak oturumda Ayse var.
        lenient().when(currentUser.current()).thenReturn(ayse);
        lenient().when(currentUser.currentId()).thenReturn(1L);
    }

    private static User kullanici(Long id, String ad) {
        User u = User.builder().username(ad).password("x").role(Role.USER).build();
        ReflectionTestUtils.setField(u, "id", id);
        return u;
    }

    private MonitoredTarget hedef(Long id, User sahip, String adres) {
        MonitoredTarget t = MonitoredTarget.builder()
                .target(adres).type(MonitorType.SSL).active(true).failureCount(0).build();
        ReflectionTestUtils.setField(t, "id", id);
        t.setOwner(sahip);
        return t;
    }

    // ==================================================================
    // SAHIPLIK YALITIMI — en kritik bolum
    // ==================================================================

    @Nested
    @DisplayName("Sahiplik yalıtımı")
    class SahiplikYalitimi {

        @Test
        @DisplayName("Başkasının hedefi silinemez")
        void baskasininHedefiSilinemez() {
            // Burak'in kaydi; Ayse oturumda. Sorgu sahip bazli oldugu icin
            // bos doner ve "bulunamadi" hatasi alinir.
            when(targetRepository.findByIdAndOwnerId(99L, 1L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.sil(99L))
                    .isInstanceOf(NoSuchElementException.class);

            verify(targetRepository, never()).delete(any());
        }

        @Test
        @DisplayName("Başkasının hedefi görünmez — liste yalnızca kendi kayıtlarını döner")
        void listeSadeceKendiKayitlari() {
            when(targetRepository.findByOwnerIdOrderByCreatedAtDesc(1L))
                    .thenReturn(List.of(hedef(1L, ayse, "ayse-site.com")));

            List<MonitorTargetItem> sonuc = service.listele();

            assertThat(sonuc).hasSize(1);
            assertThat(sonuc.get(0).target()).isEqualTo("ayse-site.com");
            // Burak'in kaydi sorguya hic girmedi
            verify(targetRepository).findByOwnerIdOrderByCreatedAtDesc(1L);
        }

        @Test
        @DisplayName("Başkasının hedefinin durumu değiştirilemez")
        void baskasininDurumuDegistirilemez() {
            when(targetRepository.findByIdAndOwnerId(99L, 1L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.durumDegistir(99L))
                    .isInstanceOf(NoSuchElementException.class);

            verify(targetRepository, never()).save(any());
        }

        @Test
        @DisplayName("Başkasının hedefi elle kontrol edilemez")
        void baskasininHedefiKontrolEdilemez() {
            when(targetRepository.findByIdAndOwnerId(99L, 1L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.simdiKontrolEt(99L))
                    .isInstanceOf(NoSuchElementException.class);
        }

        @Test
        @DisplayName("Var olmayan ve başkasına ait kayıt AYNI hatayı verir")
        void ayirtEdilemezHata() {
            // Guvenlik: 403 donmek "bu id var ama senin degil" bilgisini
            // sizdirirdi. Ikisi de ayni NoSuchElementException vermeli.
            when(targetRepository.findByIdAndOwnerId(anyLong(), anyLong()))
                    .thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.sil(99L))
                    .isInstanceOf(NoSuchElementException.class)
                    .hasMessageContaining("bulunamadı");
            assertThatThrownBy(() -> service.sil(12345L))
                    .isInstanceOf(NoSuchElementException.class)
                    .hasMessageContaining("bulunamadı");
        }
    }

    // ==================================================================
    // Hedef yonetimi
    // ==================================================================

    @Nested
    @DisplayName("Hedef ekleme")
    class Ekleme {

        @Test
        @DisplayName("Yeni hedef eklenir ve oturumdaki kullanıcıya bağlanır")
        void hedefEklenir() {
            when(targetRepository.countByOwnerId(1L)).thenReturn(0L);
            when(targetRepository.existsByOwnerIdAndTargetAndType(anyLong(), anyString(), any()))
                    .thenReturn(false);
            when(targetRepository.save(any(MonitoredTarget.class)))
                    .thenAnswer(inv -> {
                        MonitoredTarget t = inv.getArgument(0);
                        ReflectionTestUtils.setField(t, "id", 5L);
                        return t;
                    });

            MonitorTargetItem item = service.ekle(
                    new MonitorTargetRequest("example.com", MonitorType.SSL));

            assertThat(item.target()).isEqualTo("example.com");
            assertThat(item.active()).isTrue();
        }

        @Test
        @DisplayName("Aynı hedef aynı türde iki kez eklenemez")
        void mukerrerHedef() {
            when(targetRepository.countByOwnerId(1L)).thenReturn(1L);
            when(targetRepository.existsByOwnerIdAndTargetAndType(1L, "example.com", MonitorType.SSL))
                    .thenReturn(true);

            assertThatThrownBy(() -> service.ekle(
                    new MonitorTargetRequest("example.com", MonitorType.SSL)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("zaten");
        }

        @Test
        @DisplayName("Hedef sayısı sınırı aşılamaz")
        void hedefSiniri() {
            when(targetRepository.countByOwnerId(1L)).thenReturn(50L);

            assertThatThrownBy(() -> service.ekle(
                    new MonitorTargetRequest("yeni.com", MonitorType.SSL)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("En fazla");

            verify(targetRepository, never()).save(any());
        }
    }

    // ==================================================================
    // Silme
    // ==================================================================

    @Nested
    @DisplayName("Silme")
    class Silme {

        @Test
        @DisplayName("Kendi hedefi silinir ve geçmişi de temizlenir")
        void kendiHedefiSilinir() {
            MonitoredTarget t = hedef(5L, ayse, "example.com");
            when(targetRepository.findByIdAndOwnerId(5L, 1L)).thenReturn(Optional.of(t));

            service.sil(5L);

            // Yabanci anahtar kisiti nedeniyle once gecmis silinmeli
            verify(checkRepository).deleteByTargetId(5L);
            verify(targetRepository).delete(t);
        }
    }

    // ==================================================================
    // Bildirim kurallari
    // ==================================================================

    @Nested
    @DisplayName("Bildirim kuralları")
    class Bildirimler {

        @Test
        @DisplayName("Sorun yoksa ve değişiklik yoksa bildirim üretilmez")
        void sessizGecis() {
            // Alarm yorgunlugunu onlemek icin: her kontrolde bildirim uretmek
            // kullaniciyi kisa surede korlestirir.
            MonitoredTarget t = hedef(5L, ayse, "example.com");
            t.setLastSummary("A kayıtları: 1.2.3.4");

            when(dnsService.query(any())).thenReturn(dnsYaniti("1.2.3.4", List.of()));
            t.setType(MonitorType.DNS);

            service.kontrolEt(t);

            verify(notificationService, never()).olustur(any(), anyString(), anyString(), any(), any());
        }

        @Test
        @DisplayName("Sonuç değiştiğinde bildirim üretilir")
        void degisiklikteBildirim() {
            MonitoredTarget t = hedef(5L, ayse, "example.com");
            t.setType(MonitorType.DNS);
            t.setLastSummary("A kayıtları: 1.2.3.4");

            // IP degisti
            when(dnsService.query(any())).thenReturn(dnsYaniti("9.9.9.9", List.of()));

            service.kontrolEt(t);

            verify(notificationService).olustur(any(), anyString(), anyString(), any(), any());
        }

        @Test
        @DisplayName("İlk kontrolde (önceki özet yokken) bildirim üretilmez")
        void ilkKontrolSessiz() {
            MonitoredTarget t = hedef(5L, ayse, "example.com");
            t.setType(MonitorType.DNS);
            t.setLastSummary(null);   // ilk kez kontrol ediliyor

            when(dnsService.query(any())).thenReturn(dnsYaniti("1.2.3.4", List.of()));

            service.kontrolEt(t);

            verify(notificationService, never()).olustur(any(), anyString(), anyString(), any(), any());
        }
    }

    // ------------------------------------------------------------------

    private DnsQueryResponse dnsYaniti(String ip, List<Finding> bulgular) {
        return new DnsQueryResponse(
                "example.com", true, null,
                java.util.Map.of("A", List.of(ip)),
                new ArrayList<>(), true, List.of(), bulgular);
    }

}
