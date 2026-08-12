package com.example.securityutilitysuite.repository;

import com.example.securityutilitysuite.model.MonitorCheck;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Kontrol gecmisi.
 *
 * Sahiplik hedef uzerinden dogrulanir: sorgular {@code target.owner.id}
 * uzerinden filtrelenir, boylece kullanici yalnizca kendi hedeflerinin
 * gecmisini gorebilir.
 */
@Repository
public interface MonitorCheckRepository extends JpaRepository<MonitorCheck, Long> {

    @Query("SELECT c FROM MonitorCheck c WHERE c.target.id = :targetId "
            + "AND c.target.owner.id = :ownerId ORDER BY c.checkedAt DESC")
    List<MonitorCheck> findHistory(@Param("targetId") Long targetId,
                                   @Param("ownerId") Long ownerId,
                                   Pageable pageable);

    @Query("SELECT c FROM MonitorCheck c WHERE c.target.owner.id = :ownerId "
            + "ORDER BY c.checkedAt DESC")
    List<MonitorCheck> findRecentForOwner(@Param("ownerId") Long ownerId, Pageable pageable);

    /** Hedef silinirken gecmisi de silinir. */
    @Modifying
    @Query("DELETE FROM MonitorCheck c WHERE c.target.id = :targetId")
    void deleteByTargetId(@Param("targetId") Long targetId);

    /**
     * Belirtilen tarihten eski kayitlari siler.
     *
     * Not: "son N kaydi tut" bicimindeki bir sorgu JPQL'de yazilamaz
     * (alt sorguda LIMIT desteklenmez). Bunun yerine servis katmani
     * saklanacak son kaydin tarihini bulup buraya verir.
     */
    @Modifying
    @Query("DELETE FROM MonitorCheck c WHERE c.target.id = :targetId "
            + "AND c.checkedAt < :before")
    int deleteOlderThan(@Param("targetId") Long targetId,
                        @Param("before") java.time.LocalDateTime before);
}
