Markdown

# security-utility-suite

A comprehensive Spring Boot utility suite for cyber security operations and threat management — network analysis, cryptographic tools, log analysis, threat intelligence, and vulnerability scanning — with a built-in dark-themed web control panel. Powered by Java 21 Virtual Threads and Spring Security for fast, concurrent, and secure execution.

## Features

* **Port Scanner** — asynchronous TCP-connect scanning powered by Java 21 Virtual Threads (one virtual thread per port probe).
* **DNS Query Resolver** — queries A, AAAA, MX, TXT, and NS records for domain name analysis.
* **SSL/TLS Inspector** — verifies target certificate validity, expiration countdown, and issuer details with internal `NetworkGuard` SSRF protection.
* **HTTP Security Headers Audit** — checks web targets for missing critical security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.).
* **Subnet & MAC Analyzer** — calculates CIDR IP ranges, usable hosts, subnet masks, and resolves MAC address OUIs.
* **Base64 / Hex Converter** — bidirectional encoder/decoder utility for binary-to-text data formats.
* **Hash Verifier & Cracker** — MD5, SHA-1, SHA-256 hash generation, verification, and dictionary-based hash cracking simulation.
* **AES-256 Encryptor** — secure symmetric text encryption and decryption using AES-256 GCM.
* **Metadata (EXIF) Cleaner** — parses and strips sensitive GPS, camera, author, and device metadata from images (JPEG, PNG) and documents (DLP).
* **JWT Token Analyzer** — decodes headers/payloads, evaluates algorithm strength, and verifies signature validity.
* **SSH Brute-Force Blocker** — parses auth/sshd logs to detect repeated login failures and generates actionable `ufw` ban rules.
* **Git & Secret Leak Finder** — scans code/text for hardcoded AWS Keys, GitHub Tokens, and DB credentials with sensitive value masking.
* **Threat Intel (IOC) Extractor** — extracts, categorizes, and defangs/normalizes IP, URL, and Domain indicators of compromise from raw text.
* **Phishing URL Detector** — scores URLs for phishing techniques using Levenshtein distance typosquatting checks and `@` userinfo bypass detection.
* **Web Vulnerability Scanner (XSS/SQLi)** — performs safe, non-destructive `GET` parameter reflection checks for SQL Injection and Reflected XSS with strict rate-limiting and DoS prevention.

> **Status:** All **14 modules** are fully implemented end-to-end (Controller, Service, Repository, DTO, Unit Tests, and UI) and deployed on the dashboard.

## Security & Architecture Principles

* **Defense-in-Depth:** Integrated `NetworkGuard` SSRF filter blocks probes against loopback (`127.0.0.1`, `localhost`), RFC 1918 private networks, and cloud metadata endpoints (`169.254.169.254`).
* **Role-Based Access Control (RBAC):** Spring Security with automatic initial `ADMIN` setup and restricted H2 Console access.
* **Data Leakage Protection (DLP):** High-threshold secret masking (12+ chars) and overlap deduplication to prevent accidental credential disclosure.
* **Rate Limiting & Safety:** Active scanners enforce strict `GET`-only HTTP methods and request delays to prevent DoS or state-changing side effects.

## Prerequisites

* Java Development Kit (JDK 21 or higher) — the project uses a Gradle toolchain, so Gradle will auto-provision JDK 21 if it's not already installed.
* No external database required for local development — ships with an embedded H2 database by default (SQL Server configuration available for production).
* Git for version control.

## Quickstart & Installation

Clone the repository:

```bash
git clone [https://github.com/dilanur-koc/security-utility-suite.git](https://github.com/dilanur-koc/security-utility-suite.git)
cd security-utility-suite

Build and run tests:
Bash

./gradlew test          # Linux / macOS
.\gradlew test          # Windows (PowerShell)

Run the application:
Bash

./gradlew bootRun       # Linux / macOS
.\gradlew bootRun       # Windows (PowerShell)

Access the interactive control panel in your browser:

[http://127.0.0.1:8080](http://127.0.0.1:8080)

API Reference
Port Scanner
HTTP

POST /api/v1/scan
Content-Type: application/json

{
  "targetHost": "127.0.0.1",
  "startPort": 1,
  "endPort": 1024
}

SSL/TLS Inspector
HTTP

POST /api/v1/ssl/check
Content-Type: application/json

{
  "domain": "example.com"
}

Log Analyzer
HTTP

POST /api/v1/logs/analyze
Content-Type: application/json

{
  "logContent": "203.0.113.44 - - [30/Jul/2026:10:12:01 +0300] \"POST /login HTTP/1.1\" 401 512\n...",
  "logSource": "auth.log"
}

Metadata (EXIF) Cleaner
HTTP

POST /api/v1/metadata/clean
Content-Type: multipart/form-data

Secret Leak Finder
HTTP

POST /api/v1/secrets/scan
Content-Type: application/json

{
  "content": "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP"
}

Phishing URL Detector
HTTP

POST /api/v1/phishing/analyze
Content-Type: application/json

{
  "url": "[http://gooogle.com/login](http://gooogle.com/login)"
}

Web Vulnerability Scanner
HTTP

POST /api/v1/vulnerability/scan
Content-Type: application/json

{
  "targetUrl": "[http://example.com/search?q=test](http://example.com/search?q=test)",
  "disclaimerAccepted": true
}

Project Structure

src/main/java/com/example/securityutilitysuite/
├── config/       → SecurityConfig (RBAC, Form Login, H2 FrameOptions)
├── controller/   → REST Controllers for all 14 security modules
├── dto/          → Inbound/Outbound request payloads with Jakarta @Valid constraints
├── enums/        → Role, ScanStatus, Severity, ThreatType, IntegrityStatus
├── model/        → JPA Entities (User, ScanResult, SecurityLogAlert, etc.)
├── repository/   → Spring Data JPA Repositories
├── security/     → NetworkGuard (SSRF protection), ClientIpResolver, AuthEvents
├── service/      → Core business, crypto, virtual-thread scanning, and analysis logic
└── util/         → Codecs and Error utilities

src/main/resources/
└── static/       → Responsive dark-themed Single Page Application (Dashboard UI)

Compatibility

Tested and verified on:

    Java 21 LTS (Virtual Threads)

    Spring Boot 3.3+ / 4.x

    Gradle (via the included Gradle Wrapper)

    Linux (Pop!_OS / Ubuntu) and Windows 11

    Modern web browsers (Chrome, Firefox, Edge, Safari)

Security Note & Legal Disclaimer

This tool performs active network probes, HTTP requests, and security testing operations. Only scan hosts, networks, and applications you own or are explicitly authorized to test. Unauthorized vulnerability scanning or port probing may be illegal in your jurisdiction. Users are solely responsible for compliance with applicable laws.
Contributing

    Bug Reporting: Open an issue describing the bug and steps to reproduce.

    Feature Requests: Submit an issue discussing your proposed enhancement.

    Pull Requests: Fork the repo, create your feature branch, and submit a PR!

License

Distributed under the MIT License.
