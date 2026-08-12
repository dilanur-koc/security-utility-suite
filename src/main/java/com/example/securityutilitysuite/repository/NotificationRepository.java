package com.example.securityutilitysuite.repository;

import com.example.securityutilitysuite.model.Notification;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Bildirimler. Tum sorgular sahip bazlidir — bkz. MonitoredTargetRepository
 * icindeki guvenlik notu.
 */
@Repository
public interface NotificationRepository extends JpaRepository<Notification, Long> {

    List<Notification> findByOwnerIdOrderByCreatedAtDesc(Long ownerId, Pageable pageable);

    Optional<Notification> findByIdAndOwnerId(Long id, Long ownerId);

    long countByOwnerIdAndReadFalse(Long ownerId);

    @Modifying
    @Query("UPDATE Notification n SET n.read = true WHERE n.owner.id = :ownerId AND n.read = false")
    int markAllRead(@Param("ownerId") Long ownerId);

    @Modifying
    @Query("DELETE FROM Notification n WHERE n.owner.id = :ownerId")
    int deleteAllForOwner(@Param("ownerId") Long ownerId);
}
