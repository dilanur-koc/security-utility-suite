package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.ScanRequest;
import com.example.securityutilitysuite.enums.ScanStatus;
import com.example.securityutilitysuite.model.ScanResult;
import com.example.securityutilitysuite.repository.ScanResultRepository;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Performs TCP-connect port scans against a caller-supplied host.
 *
 * Design notes:
 * - Stateless: every call receives its arguments, persists its own result
 *   row, and holds no scan state in memory between requests — safe to run
 *   behind a load balancer across multiple instances without sticky
 *   sessions.
 * - Java 21 virtual threads: each port check is submitted to a
 *   {@link Executors#newVirtualThreadPerTaskExecutor()} executor. Since a
 *   port probe is almost pure I/O wait (blocked on Socket#connect), virtual
 *   threads let us fan out thousands of concurrent probes without the
 *   memory/context-switch cost of platform threads, and without needing a
 *   hand-sized thread pool.
 * - Bounded per-request timeout: every connection attempt uses
 *   Socket#connect(SocketAddress, timeout) so one unresponsive port can't
 *   stall the whole scan.
 */
@Service
public class PortScannerService {

    private static final Logger log = LoggerFactory.getLogger(PortScannerService.class);
    private static final int CONNECT_TIMEOUT_MS = 200;

    private final ScanResultRepository scanResultRepository;
    private final ExecutorService virtualThreadExecutor = Executors.newVirtualThreadPerTaskExecutor();

    public PortScannerService(ScanResultRepository scanResultRepository) {
        this.scanResultRepository = scanResultRepository;
    }

    /**
     * Runs a scan: fans out one virtual-thread task per port, waits for
     * all of them, persists the outcome, and returns the saved entity.
     */
    /**
     * Not: bu metot bilerek {@code @Transactional} DEGILDIR. Tek bir
     * transaction icinde calissaydi (a) IN_PROGRESS satiri commit
     * edilmedigi icin tarama surerken hicbir sorguda gorunmezdi, (b) uzun
     * suren tarama boyunca bir veritabani baglantisi bosuna tutulur ve
     * birkac es zamanli tarama havuzu tuketebilirdi. Iki save() cagrisi
     * kendi kisa transaction'larinda calisir.
     */
    public ScanResult scan(ScanRequest request) {
        long start = System.currentTimeMillis();

        ScanResult scanResult = new ScanResult(request.getTargetHost(), ScanStatus.IN_PROGRESS);
        scanResult = scanResultRepository.save(scanResult);

        List<Integer> openPorts;
        ScanStatus finalStatus;

        try {
            // Host'u once cozumle: erisilemeyen bir adres icin her port
            // "kapali" donerdi ve sonuc "basarili tarama, 0 acik port" gibi
            // gorunurdu. Kullanici host'un ayakta olmadigini anlayamiyordu.
            InetAddress.getByName(request.getTargetHost());

            openPorts = scanPortRange(request.getTargetHost(), request.getStartPort(), request.getEndPort());
            finalStatus = ScanStatus.COMPLETED;
        } catch (UnknownHostException ex) {
            log.warn("Host cozumlenemedi: {}", request.getTargetHost());
            openPorts = Collections.emptyList();
            finalStatus = ScanStatus.FAILED;
        } catch (Exception ex) {
            log.warn("Scan failed for host={} range={}-{}: {}",
                    request.getTargetHost(), request.getStartPort(), request.getEndPort(), ex.getMessage());
            openPorts = Collections.emptyList();
            finalStatus = ScanStatus.FAILED;
        }

        long durationMs = System.currentTimeMillis() - start;

        scanResult.setStatus(finalStatus);
        scanResult.setScanDurationMs(durationMs);
        scanResult.setOpenPorts(openPorts.stream()
                .map(String::valueOf)
                .collect(Collectors.joining(",")));

        return scanResultRepository.save(scanResult);
    }

    /**
     * Probes every port in [startPort, endPort] concurrently (one virtual
     * thread per port) and returns the ones that accepted a TCP connection,
     * in ascending order.
     */
    private List<Integer> scanPortRange(String targetHost, int startPort, int endPort) {
        List<CompletableFuture<Integer>> futures = IntStream.rangeClosed(startPort, endPort)
                .mapToObj(port -> CompletableFuture.supplyAsync(
                        () -> isPortOpen(targetHost, port) ? port : null,
                        virtualThreadExecutor))
                .collect(Collectors.toList());

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        List<Integer> openPorts = new ArrayList<>();
        for (CompletableFuture<Integer> future : futures) {
            Integer port = future.join();
            if (port != null) {
                openPorts.add(port);
            }
        }
        Collections.sort(openPorts);
        return openPorts;
    }

    private boolean isPortOpen(String targetHost, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(targetHost, port), CONNECT_TIMEOUT_MS);
            return true;
        } catch (Exception ex) {
            // Timeout, refused, unreachable, etc. all mean "closed" here -
            // no need for per-port log noise.
            return false;
        }
    }

    @Transactional(readOnly = true)
    public org.springframework.data.domain.Page<ScanResult> getHistory(
            org.springframework.data.domain.Pageable pageable
    ) {
        return scanResultRepository.findAllByOrderByCreatedAtDesc(pageable);
    }

    @PreDestroy
    void shutdownExecutor() {
        virtualThreadExecutor.shutdown();
    }
}
