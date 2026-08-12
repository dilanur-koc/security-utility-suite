package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.model.MonitoredTarget;
import com.example.securityutilitysuite.repository.MonitoredTargetRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Aktif izleme hedeflerini periyodik olarak kontrol eder.
 *
 * TASARIM NOTLARI:
 *
 * - Hedefler SIRAYLA ve aralarinda gecikmeyle kontrol edilir. Hepsini ayni
 *   anda baslatmak, izlenen sitelere ani bir istek yigini gonderirdi;
 *   bu hem kaba bir davranis hem de hizmet engelleme gibi gorunur.
 *
 * - Bir hedefin hatasi digerlerini durdurmaz: her kontrol kendi try/catch
 *   blogunda calisir.
 *
 * - Varsayilan aralik 6 saat. Sertifika suresi ve guvenlik basliklari
 *   dakikalik degisen seyler degil; daha sik kontrol gereksiz yuk olur.
 *   {@code app.monitor.interval-ms} ile degistirilebilir.
 *
 * - Ozellik varsayilan olarak KAPALI ({@code app.monitor.enabled}).
 *   Gelistirme sirasinda uygulamanin kendiliginden dis isteklere baslamasi
 *   istenmeyen bir surpriz olurdu.
 */
@Component
public class MonitorScheduler {

    private static final Logger log = LoggerFactory.getLogger(MonitorScheduler.class);

    /** Hedefler arasi bekleme; izlenen sitelere yigin istek gitmesin. */
    private static final long TARGET_DELAY_MS = 2000;

    private final MonitoredTargetRepository targetRepository;
    private final MonitorService monitorService;
    private final boolean enabled;

    public MonitorScheduler(MonitoredTargetRepository targetRepository,
                            MonitorService monitorService,
                            @Value("${app.monitor.enabled:false}") boolean enabled) {
        this.targetRepository = targetRepository;
        this.monitorService = monitorService;
        this.enabled = enabled;
    }

    @Scheduled(
            initialDelayString = "${app.monitor.initial-delay-ms:60000}",
            fixedDelayString = "${app.monitor.interval-ms:21600000}")
    public void tumHedefleriKontrolEt() {
        if (!enabled) {
            return;
        }

        List<MonitoredTarget> hedefler = targetRepository.findByActiveTrue();
        if (hedefler.isEmpty()) {
            return;
        }

        log.info("Zamanlanmış izleme başladı: {} hedef", hedefler.size());
        int basarili = 0;

        for (MonitoredTarget t : hedefler) {
            try {
                monitorService.kontrolEt(t);
                targetRepository.save(t);
                basarili++;
            } catch (Exception ex) {
                // Bir hedefin hatasi digerlerini durdurmamali.
                log.warn("Hedef kontrol edilemedi id={} hedef={}: {}",
                        t.getId(), t.getTarget(), ex.getMessage());
            }

            try {
                Thread.sleep(TARGET_DELAY_MS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                log.info("Zamanlanmış izleme yarıda kesildi");
                return;
            }
        }

        log.info("Zamanlanmış izleme bitti: {}/{} başarılı", basarili, hedefler.size());
    }
}
