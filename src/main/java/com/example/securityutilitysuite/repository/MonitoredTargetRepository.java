package com.example.securityutilitysuite.repository;

import com.example.securityutilitysuite.enums.MonitorType;
import com.example.securityutilitysuite.model.MonitoredTarget;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * GUVENLIK NOTU — sorgu imzalari bilerek boyle:
 *
 * {@code findById(id)} yerine {@code findByIdAndOwnerId(id, ownerId)}
 * kullaniliyor. Aradaki fark kritik: ilkinde kayit once cekilir, sonra
 * kod tarafinda sahiplik kontrol edilir — kontrolu yazmayi unutmak
 * dogrudan IDOR acigi olur. Ikincisinde sahiplik SORGUNUN PARCASIDIR;
 * baskasinin kaydi hicbir zaman donmez, unutma ihtimali yoktur.
 *
 * Ayni sebeple sahipsiz {@code findAll()} imzasi bu arayuze eklenmemistir.
 */
@Repository
public interface MonitoredTargetRepository extends JpaRepository<MonitoredTarget, Long> {

    List<MonitoredTarget> findByOwnerIdOrderByCreatedAtDesc(Long ownerId);

    Optional<MonitoredTarget> findByIdAndOwnerId(Long id, Long ownerId);

    boolean existsByOwnerIdAndTargetAndType(Long ownerId, String target, MonitorType type);

    long countByOwnerId(Long ownerId);

    /** Zamanlanmis kontrol icin: TUM kullanicilarin aktif hedefleri. */
    List<MonitoredTarget> findByActiveTrue();
}
