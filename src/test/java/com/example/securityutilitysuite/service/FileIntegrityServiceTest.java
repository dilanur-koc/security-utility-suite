package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.enums.IntegrityStatus;
import com.example.securityutilitysuite.model.FileIntegrityRecord;
import com.example.securityutilitysuite.repository.FileIntegrityRecordRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;

/**
 * {@link FileIntegrityService} icin birim testleri.
 *
 * Gercek dosya sistemi kullanilir ({@link TempDir}) — test edilen sey zaten
 * dosya okuma ve SHA-256 hesaplama. Dizin her testten sonra JUnit tarafindan
 * silinir, testler birbirini etkilemez.
 *
 * Repository, bellek ici bir harita ile taklit edilir. Boylece "ayni yol
 * yeniden baseline'landiginda mukerrer satir olusuyor mu" gibi depo
 * davranisina bagli durumlar gercekci sekilde sinanabiliyor.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("FileIntegrityService — dosya bütünlüğü")
class FileIntegrityServiceTest {

    @TempDir
    Path tempDir;

    @Mock
    private FileIntegrityRecordRepository repository;

    private FileIntegrityService service;

    /** id -> kayit. Kayit sirasini korumak icin LinkedHashMap. */
    private final Map<Long, FileIntegrityRecord> depo = new LinkedHashMap<>();
    private long sonId;

    @BeforeEach
    void setUp() {
        depo.clear();
        sonId = 0;
        service = new FileIntegrityService(repository);

        lenient().when(repository.save(any(FileIntegrityRecord.class))).thenAnswer(inv -> {
            FileIntegrityRecord r = inv.getArgument(0);
            if (r.getId() == null) {
                // Entity'de setId yok (JPA uretiyor); testte kimlik atamak icin
                // Spring'in test yardimcisi ile alani dogrudan yaziyoruz.
                ReflectionTestUtils.setField(r, "id", ++sonId);
            }
            depo.put(r.getId(), r);
            return r;
        });

        lenient().when(repository.findById(any())).thenAnswer(inv ->
                Optional.ofNullable(depo.get((Long) inv.getArgument(0))));

        lenient().when(repository.findByFilePath(anyString())).thenAnswer(inv -> {
            String yol = inv.getArgument(0);
            return depo.values().stream().filter(r -> yol.equals(r.getFilePath())).findFirst();
        });

        lenient().when(repository.findAll()).thenAnswer(inv -> new ArrayList<>(depo.values()));

        lenient().doAnswer(inv -> {
            depo.remove((Long) inv.getArgument(0));
            return null;
        }).when(repository).deleteById(any());
    }

    private Path dosyaOlustur(String ad, String icerik) throws Exception {
        Path p = tempDir.resolve(ad);
        Files.writeString(p, icerik);
        return p;
    }

    // ==================================================================
    // Baseline
    // ==================================================================

    @Nested
    @DisplayName("Baseline oluşturma")
    class Baseline {

        @Test
        @DisplayName("Var olan dosya için SHA-256 baseline üretilir")
        void baselineUretilir() throws Exception {
            Path f = dosyaOlustur("a.txt", "merhaba");

            FileIntegrityRecord r = service.createBaseline(f.toString());

            assertThat(r.getFilePath()).isEqualTo(f.toString());
            assertThat(r.getAlgorithm()).isEqualTo("SHA-256");
            assertThat(r.getBaselineHash()).hasSize(64);   // SHA-256 = 64 hex karakter
            assertThat(r.getStatus()).isEqualTo(IntegrityStatus.BASELINE_ONLY);
        }

        @Test
        @DisplayName("Aynı içerik aynı hash'i, farklı içerik farklı hash üretir")
        void hashTutarli() throws Exception {
            Path a = dosyaOlustur("a.txt", "ayni icerik");
            Path b = dosyaOlustur("b.txt", "ayni icerik");
            Path c = dosyaOlustur("c.txt", "farkli icerik");

            String ha = service.createBaseline(a.toString()).getBaselineHash();
            String hb = service.createBaseline(b.toString()).getBaselineHash();
            String hc = service.createBaseline(c.toString()).getBaselineHash();

            assertThat(ha).isEqualTo(hb);
            assertThat(ha).isNotEqualTo(hc);
        }

        @Test
        @DisplayName("Var olmayan dosya reddedilir")
        void olmayanDosya() {
            // Servis, okunamayan dosya icin NoSuchElementException firlatiyor
            // ("Dosya okunamadı veya bulunamadı"). Test bunu birebir yansitir.
            assertThatThrownBy(() -> service.createBaseline(tempDir.resolve("yok.txt").toString()))
                    .isInstanceOf(NoSuchElementException.class)
                    .hasMessageContaining("bulunamadı");
        }

        @Test
        @DisplayName("Aynı yol yeniden baseline'lanınca mükerrer kayıt oluşmaz")
        void mukerrerKayitOlusmaz() throws Exception {
            // Regresyon testi: onceki surumde her cagri YENI satir aciyordu.
            // Ayni dosya iki kez eklenince tabloda iki kayit olusuyor,
            // istatistik grafikleri de sisiyordu.
            Path f = dosyaOlustur("a.txt", "ilk");
            FileIntegrityRecord ilk = service.createBaseline(f.toString());
            Long ilkId = ilk.getId();
            String ilkHash = ilk.getBaselineHash();

            Files.writeString(f, "degisti");
            FileIntegrityRecord ikinci = service.createBaseline(f.toString());

            assertThat(depo).hasSize(1);
            assertThat(ikinci.getId()).isEqualTo(ilkId);
            assertThat(ikinci.getBaselineHash()).isNotEqualTo(ilkHash);
            assertThat(ikinci.getStatus()).isEqualTo(IntegrityStatus.BASELINE_ONLY);
        }
    }

    // ==================================================================
    // Kontrol
    // ==================================================================

    @Nested
    @DisplayName("Bütünlük kontrolü")
    class Kontrol {

        @Test
        @DisplayName("Değişmemiş dosya UNCHANGED döner")
        void degismemis() throws Exception {
            Path f = dosyaOlustur("a.txt", "sabit");
            FileIntegrityRecord r = service.createBaseline(f.toString());

            FileIntegrityRecord sonuc = service.checkFile(r.getId());

            assertThat(sonuc.getStatus()).isEqualTo(IntegrityStatus.UNCHANGED);
            assertThat(sonuc.getCurrentHash()).isEqualTo(sonuc.getBaselineHash());
            assertThat(sonuc.getLastCheckedAt()).isNotNull();
        }

        @Test
        @DisplayName("İçeriği değişen dosya MODIFIED döner")
        void degismis() throws Exception {
            Path f = dosyaOlustur("a.txt", "ilk");
            FileIntegrityRecord r = service.createBaseline(f.toString());

            Files.writeString(f, "sonradan degisti");
            FileIntegrityRecord sonuc = service.checkFile(r.getId());

            assertThat(sonuc.getStatus()).isEqualTo(IntegrityStatus.MODIFIED);
            assertThat(sonuc.getCurrentHash()).isNotEqualTo(sonuc.getBaselineHash());
        }

        @Test
        @DisplayName("Tek karakterlik değişiklik bile yakalanır")
        void tekKarakter() throws Exception {
            Path f = dosyaOlustur("a.txt", "abcdef");
            FileIntegrityRecord r = service.createBaseline(f.toString());

            Files.writeString(f, "abcdeF");

            assertThat(service.checkFile(r.getId()).getStatus())
                    .isEqualTo(IntegrityStatus.MODIFIED);
        }

        @Test
        @DisplayName("Silinen dosya MISSING döner ve currentHash temizlenir")
        void silinmis() throws Exception {
            Path f = dosyaOlustur("a.txt", "silinecek");
            FileIntegrityRecord r = service.createBaseline(f.toString());

            Files.delete(f);
            FileIntegrityRecord sonuc = service.checkFile(r.getId());

            assertThat(sonuc.getStatus()).isEqualTo(IntegrityStatus.MISSING);
            assertThat(sonuc.getCurrentHash()).isNull();
        }

        @Test
        @DisplayName("Olmayan kayıt id'si istisna fırlatır")
        void olmayanKayit() {
            assertThatThrownBy(() -> service.checkFile(9999L))
                    .isInstanceOf(NoSuchElementException.class);
        }

        @Test
        @DisplayName("checkAll her kaydı ayrı ayrı değerlendirir")
        void tumunuKontrolEt() throws Exception {
            Path sabit = dosyaOlustur("sabit.txt", "durur");
            Path degisen = dosyaOlustur("degisen.txt", "ilk");
            Path silinen = dosyaOlustur("silinen.txt", "gider");

            service.createBaseline(sabit.toString());
            service.createBaseline(degisen.toString());
            service.createBaseline(silinen.toString());

            Files.writeString(degisen, "ikinci");
            Files.delete(silinen);

            List<FileIntegrityRecord> sonuc = service.checkAll();

            assertThat(sonuc).hasSize(3);
            assertThat(sonuc).extracting(FileIntegrityRecord::getStatus)
                    .containsExactlyInAnyOrder(
                            IntegrityStatus.UNCHANGED,
                            IntegrityStatus.MODIFIED,
                            IntegrityStatus.MISSING);
        }
    }

    // ==================================================================
    // Listeleme ve silme
    // ==================================================================

    @Nested
    @DisplayName("Listeleme ve silme")
    class Yonetim {

        @Test
        @DisplayName("listAll eklenen kayıtları döner")
        void listele() throws Exception {
            service.createBaseline(dosyaOlustur("a.txt", "x").toString());
            service.createBaseline(dosyaOlustur("b.txt", "y").toString());

            assertThat(service.listAll()).hasSize(2);
        }

        @Test
        @DisplayName("delete kaydı kaldırır ama dosyaya dokunmaz")
        void sil() throws Exception {
            Path f = dosyaOlustur("a.txt", "kalsin");
            FileIntegrityRecord r = service.createBaseline(f.toString());

            service.delete(r.getId());

            assertThat(depo).isEmpty();
            assertThat(Files.exists(f)).isTrue();   // takipten cikti, silinmedi
        }
    }
}
