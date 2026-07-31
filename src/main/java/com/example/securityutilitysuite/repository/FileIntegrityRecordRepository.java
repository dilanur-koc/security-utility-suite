package com.example.securityutilitysuite.repository;

import com.example.securityutilitysuite.model.FileIntegrityRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Spring Data JPA repository for {@link FileIntegrityRecord}.
 */
public interface FileIntegrityRecordRepository extends JpaRepository<FileIntegrityRecord, Long> {

    Optional<FileIntegrityRecord> findByFilePath(String filePath);
}
