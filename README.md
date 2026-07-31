# security-utility-suite

A lightweight Spring Boot utility suite for network security operations — asynchronous port scanning, file integrity verification, and log-based threat detection — with a built-in dark-themed web control panel. Built with Java 21 Virtual Threads for fast, non-blocking concurrent scanning.

## Features

* **Port Scanner** — asynchronous TCP-connect scanning powered by Java 21 Virtual Threads (one virtual thread per port probe).
* **File Integrity Verifier** — computes SHA-256 baseline hashes for tracked files and detects unauthorized changes on demand.
* **Log Analyzer** — parses raw access/auth logs and flags Brute-Force, Suspicious Activity, SQL Injection, and XSS patterns via rule-based detection.
* Persistent history storage via Spring Data JPA (H2 by default — zero external setup required).
* RESTful API for every module (scan, integrity check, log analysis).
* Input validation via Jakarta Bean Validation (host format, port range, max range size, file path checks).
* Global exception handling for consistent, predictable JSON error responses across all modules.
* Integrated Bootstrap 5 + Vanilla JS dark-themed control panel with 3 fully functional module tabs.
* Clean, layered architecture: `Controller` → `Service` → `Repository` → `Entity`, repeated per module.
* Configurable connection timeout (tunable per environment — local vs. remote targets).

> **Status:** All 3 dashboard tabs — Ağ Tarayıcı (Port Scanner), Dosya Bütünlüğü (File Integrity), Log Analizi (Log Analyzer) — are fully functional end-to-end, front-to-back.
>
> **Roadmap:** An SSL/TLS Certificate Checker module is in progress (entity + repository already in place; service/controller/UI pending).

## Prerequisites

* Java Development Kit (JDK 21 or higher) — the project uses a Gradle toolchain, so Gradle will auto-provision JDK 21 if it's not already installed.
* No external database required for local development — the project ships with an embedded H2 database by default.
* (Optional) Docker, if you want to spin up extra test targets for scanning.

## Quickstart & Installation

Clone the repository:

```
git clone https://github.com/dilanur-koc/security-utility-suite.git
cd security-utility-suite
```

Build the project (uses the Gradle Wrapper — no local Gradle install needed):

```
./gradlew build        # Linux / macOS
gradlew.bat build       # Windows
```

Run the application:

```
./gradlew bootRun       # Linux / macOS
gradlew.bat bootRun      # Windows
```

Access the interactive dashboard in your browser:

```
http://127.0.0.1:8080
```

## API Reference

### Port Scanner

**Trigger a port scan**

```
POST /api/v1/scan
Content-Type: application/json
```

Request body:

```json
{
  "targetHost": "127.0.0.1",
  "startPort": 1,
  "endPort": 1024
}
```

Response `201 Created`:

```json
{
  "id": 42,
  "targetHost": "127.0.0.1",
  "openPorts": "22,80,8080",
  "scanDurationMs": 137,
  "status": "COMPLETED",
  "createdAt": "2026-07-30T15:47:49"
}
```

**Get scan history (paginated)**

```
GET /api/v1/scan/history?page=0&size=20
```

Returns a Spring `Page<ScanResult>` of past scan records, most recent first.

### File Integrity Verifier

**Compute a baseline hash for a file**

```
POST /api/v1/integrity/baseline
Content-Type: application/json
```

Request body:

```json
{
  "filePath": "/etc/nginx/nginx.conf",
  "algorithm": "SHA-256"
}
```

**Check all tracked files for changes**

```
GET /api/v1/integrity/check
```

Returns the current status (`Değişmedi` / `Değişti`) for every tracked file against its stored baseline.

### Log Analyzer

**Analyze log content for threats**

```
POST /api/v1/logs/analyze
Content-Type: application/json
```

Request body:

```json
{
  "logContent": "203.0.113.44 - - [30/Jul/2026:10:12:01 +0300] \"POST /login HTTP/1.1\" 401 512\n...",
  "logSource": "auth.log"
}
```

Detects and persists new findings across 4 categories:

* `BRUTE_FORCE` — ≥3 failed logins (401) from the same IP
* `SUSPICIOUS_ACTIVITY` — ≥3 scanning responses (404/500) or ≥2 unauthorized (403) from the same IP
* `SQL_INJECTION` — known injection signatures (`UNION SELECT`, `' OR '1'='1`, `; DROP TABLE`, etc.)
* `XSS` — known XSS signatures (`<script>`, `onerror=`, `javascript:`, etc.)

**Get alert history (paginated)**

```
GET /api/v1/logs/alerts?page=0&size=20
```

Returns all past findings, most recent first.

## Project Structure

```
src/main/java/com/example/securityutilitysuite/
├── enums/        → ScanStatus, Severity, ThreatType
├── dto/          → ScanRequest, LogAnalysisRequest (validated inbound payloads)
├── model/        → ScanResult, SecurityLogAlert, SslCheckResult (JPA entities)
├── repository/   → ScanResultRepository, SecurityLogAlertRepository, SslCheckResultRepository
├── service/      → PortScannerService, LogAnalyzerService (virtual-thread / rule-based logic)
└── controller/   → PortScannerController, LogAnalyzerController, GlobalExceptionHandler

src/main/resources/
└── static/index.html   → Bootstrap 5 + Vanilla JS dashboard (3 modules)
```

## Compatibility

Tested and verified on:

* Java 21 LTS (Virtual Threads)
* Spring Boot 4.1.0
* Gradle (via the included Gradle Wrapper)
* Linux (Pop!_OS / Ubuntu) and Windows
* Modern web browsers (Chrome, Firefox, Edge, Safari)

## Security Note

This tool performs live TCP-connect probes and reads file/log content on the hosts and paths you specify. Only scan hosts and networks you own or are explicitly authorized to test — unauthorized port scanning may be illegal in your jurisdiction. `scanme.nmap.org` is a good, legally safe target for casual testing.

## Contributing

* **Bug Reporting:** Open an issue describing the bug and steps to reproduce.
* **Feature Requests:** Submit an issue discussing your proposed enhancement.
* **Pull Requests:** Fork the repo, create your feature branch, and submit a PR!

## License

Distributed under the MIT License.
