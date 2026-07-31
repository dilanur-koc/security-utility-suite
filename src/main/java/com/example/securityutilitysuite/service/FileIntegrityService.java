package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.enums.IntegrityStatus;
import com.example.securityutilitysuite.model.FileIntegrityRecord;
import com.example.securityutilitysuite.repository.FileIntegrityRecordRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * Computes SHA-256 baselines for files and re-verifies them on demand,
 * flagging modifications or missing files.
 *
 * Design notes:
 * - Streaming hash: files are hashed via {@link DigestInputStream} in fixed
 *   chunks, so large files don't need to be loaded into memory at once.
 * - Stateless verification: every check reads the file fresh from disk;
 *   no file content is cached between requests, only the resulting hash.
 * - A missing/unreadable file is not an application error — it's a valid
 *   integrity finding (status MISSING) and is persisted as such rather
 *   than thrown as an exception.
 */
@Service
public class FileIntegrityService {

    private static final Logger log = LoggerFactory.getLogger(FileIntegrityService.class);
    private static final String ALGORITHM = "SHA-256";
    private static final int BUFFER_SIZE = 8192;

    private final FileIntegrityRecordRepository repository;

    public FileIntegrityService(FileIntegrityRecordRepository repository) {
        this.repository = repository;
    }

    /**
     * Computes the current hash of the given path and stores it as the
     * baseline. If the path was already tracked, this resets its baseline
     * (useful after an intentional, legitimate file change).
     */
    @Transactional
    public FileIntegrityRecord createBaseline(String filePath) {
        String hash = hashFile(filePath)
                .orElseThrow(() -> new NoSuchElementException(
                        "Dosya okunamadı veya bulunamadı: " + filePath));

        FileIntegrityRecord record = repository.findByFilePath(filePath)
                .orElseGet(() -> new FileIntegrityRecord(filePath, ALGORITHM, hash));

        // If re-baselining an existing record, reset it to a fresh baseline.
        record = new FileIntegrityRecord(filePath, ALGORITHM, hash);
        return repository.save(record);
    }

    /**
     * Re-hashes the tracked file and updates its status by comparing
     * against the stored baseline.
     */
    @Transactional
    public FileIntegrityRecord checkFile(Long id) {
        FileIntegrityRecord record = repository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Kayıt bulunamadı: " + id));

        var currentHash = hashFile(record.getFilePath());

        if (currentHash.isEmpty()) {
            record.setStatus(IntegrityStatus.MISSING);
            record.setCurrentHash(null);
        } else if (currentHash.get().equals(record.getBaselineHash())) {
            record.setStatus(IntegrityStatus.UNCHANGED);
            record.setCurrentHash(currentHash.get());
        } else {
            record.setStatus(IntegrityStatus.MODIFIED);
            record.setCurrentHash(currentHash.get());
        }

        record.setLastCheckedAt(LocalDateTime.now());
        return repository.save(record);
    }

    /**
     * Re-checks every tracked file. Sequential is fine here — file
     * integrity lists are expected to be small (dozens, not thousands),
     * unlike the port scanner's fan-out use case.
     */
    @Transactional
    public List<FileIntegrityRecord> checkAll() {
        List<FileIntegrityRecord> all = repository.findAll();
        return all.stream().map(r -> checkFile(r.getId())).toList();
    }

    @Transactional(readOnly = true)
    public List<FileIntegrityRecord> listAll() {
        return repository.findAll();
    }

    @Transactional
    public void delete(Long id) {
        repository.deleteById(id);
    }

    /**
     * Returns the SHA-256 hex digest of the file at the given path, or
     * empty if the path doesn't exist, isn't a regular file, or can't be
     * read (permissions, I/O error, etc.).
     */
    private java.util.Optional<String> hashFile(String filePath) {
        Path path = Path.of(filePath);

        if (!Files.isRegularFile(path) || !Files.isReadable(path)) {
            return java.util.Optional.empty();
        }

        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            try (InputStream in = Files.newInputStream(path);
                 DigestInputStream digestStream = new DigestInputStream(in, digest)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                while (digestStream.read(buffer) != -1) {
                    // reading drives the digest update; no need to use the bytes
                }
            }
            return java.util.Optional.of(HexFormat.of().formatHex(digest.digest()));
        } catch (NoSuchAlgorithmException ex) {
            // Should never happen — SHA-256 is a mandatory JDK algorithm.
            log.error("SHA-256 algorithm unavailable", ex);
            return java.util.Optional.empty();
        } catch (IOException ex) {
            log.warn("Could not read file {}: {}", filePath, ex.getMessage());
            return java.util.Optional.empty();
        }
    }
}
