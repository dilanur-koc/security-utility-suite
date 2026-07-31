# security-utility-suite

A lightweight Spring Boot utility suite for asynchronous network port scanning, with a built-in dark-themed web control panel. Built with Java 21 Virtual Threads for fast, non-blocking concurrent scanning.

## Features

* Asynchronous port scanning powered by **Java 21 Virtual Threads** (one virtual thread per port probe).
* Persistent scan history storage via **Spring Data JPA** (H2 by default — zero external setup required).
* RESTful API for triggering scans and retrieving history.
* Input validation via **Jakarta Bean Validation** (host format, port range, max range size).
* Global exception handling for consistent, predictable JSON error responses.
* Integrated **Bootstrap 5 + Vanilla JS** dark-themed control panel with 3 module tabs.
* Clean, layered architecture: `Controller` → `Service` → `Repository` → `Entity`.
* Configurable connection timeout (tunable per environment — local vs. remote targets).

> **Note:** The dashboard has 3 tabs — **Ağ Tarayıcı (Port Scanner)** is fully functional end-to-end. **Dosya Bütünlüğü (File Integrity)** and **Log Analizi (Log Analyzer)** are UI-complete previews; their backends are planned for a future release.

## Prerequisites

* **Java Development Kit (JDK 21 or higher)** — the project uses a Gradle toolchain, so Gradle will auto-provision JDK 21 if it's not already installed.
* No external database required for local development — the project ships with an embedded **H2** database by default.
* (Optional) Docker, if you want to spin up extra test targets for scanning.

## Quickstart & Installation

Clone the repository:
```bash
git clone https://github.com/dilanur-koc/security-utility-suite.git
cd security-utility-suite
```

Build the project (uses the Gradle Wrapper — no local Gradle install needed):
```bash
./gradlew build        # Linux / macOS
gradlew.bat build       # Windows
```

Run the application:
```bash
./gradlew bootRun       # Linux / macOS
gradlew.bat bootRun      # Windows
```

Access the interactive dashboard in your browser:
```
http://127.0.0.1:8080
```

## API Reference

### Trigger a port scan
```
POST /api/v1/scan
Content-Type: application/json
```
**Request body:**
```json
{
  "targetHost": "127.0.0.1",
  "startPort": 1,
  "endPort": 1024
}
```
**Response `201 Created`:**
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

### Get scan history (paginated)
```
GET /api/v1/scan/history?page=0&size=20
```
Returns a Spring `Page<ScanResult>` of past scan records, most recent first.

## Project Structure

```
src/main/java/com/example/securityutilitysuite/
├── enums/        → ScanStatus (IN_PROGRESS, COMPLETED, FAILED)
├── dto/          → ScanRequest (validated inbound payload)
├── model/        → ScanResult (JPA entity)
├── repository/   → ScanResultRepository (Spring Data JPA)
├── service/      → PortScannerService (virtual-thread scan logic)
└── controller/   → PortScannerController, GlobalExceptionHandler

src/main/resources/
└── static/index.html   → Bootstrap 5 + Vanilla JS dashboard
```

## Compatibility

Tested and verified on:

* Java 21 LTS (Virtual Threads)
* Spring Boot 4.1.0
* Gradle (via the included Gradle Wrapper)
* Linux (Pop!_OS / Ubuntu) and Windows
* Modern web browsers (Chrome, Firefox, Edge, Safari)

## Security Note

This tool performs live TCP-connect probes against the hosts you specify. Only scan hosts and networks **you own or are explicitly authorized to test** — unauthorized port scanning may be illegal in your jurisdiction. `scanme.nmap.org` is a good, legally safe target for casual testing.

## Contributing

* **Bug Reporting:** Open an issue describing the bug and steps to reproduce.
* **Feature Requests:** Submit an issue discussing your proposed enhancement.
* **Pull Requests:** Fork the repo, create your feature branch, and submit a PR!

## License

Distributed under the MIT License.
