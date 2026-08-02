package com.example.securityutilitysuite.repository;

import com.example.securityutilitysuite.model.FileIntegrityRecord;
import com.example.securityutilitysuite.enums.IntegrityStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for {@link FileIntegrityRecord}.
 */
public interface FileIntegrityRecordRepository extends JpaRepository<FileIntegrityRecord, Long> {

    Optional<FileIntegrityRecord> findByFilePath(String filePath);

    // --- Istatistik Tablosu icin eklenenler ---

    @Query("SELECT f.status, COUNT(f) FROM FileIntegrityRecord f GROUP BY f.status")
    List<Object[]> countGroupedByStatus();

    List<FileIntegrityRecord> findByStatusInOrderByLastCheckedAtDesc(List<IntegrityStatus> statuses);
}