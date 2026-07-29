package com.example.securityutilitysuite.repository;


import com.example.securityutilitysuite.model.SslCheckResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SslCheckResultRepository extends JpaRepository<SslCheckResult, Long> {

    // Belirli bir domain'e ait tum kontrol gecmisini getirir
    List<SslCheckResult> findByDomain(String domain);

    // Suresi dolmus sertifikalari listeler
    List<SslCheckResult> findByIsExpiredTrue();

    // Bir domain'in en son yapilan kontrol kaydini getirir
    SslCheckResult findFirstByDomainOrderByCheckedAtDesc(String domain);
}
