package com.example.securityutilitysuite.repository;

import com.example.securityutilitysuite.model.ScanResult;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Spring Data JPA repository for {@link ScanResult}.
 *
 * Purely declarative — no custom implementation needed — which keeps the
 * data-access layer stateless and safe for multiple concurrent instances
 * talking to the same database.
 */
public interface ScanResultRepository extends JpaRepository<ScanResult, Long> {

    /**
     * Returns scan history ordered by most recent first, paginated so the
     * history endpoint stays cheap as the table grows.
     */
    Page<ScanResult> findAllByOrderByCreatedAtDesc(Pageable pageable);
}