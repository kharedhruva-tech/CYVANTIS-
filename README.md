# CYVANTIS — Enterprise Gateway Intelligence & Security Nexus

**Tagline:** Deceive. Detect. Correlate. Prioritize. Defend.

CYVANTIS is an enterprise-grade AI-powered Cyber Threat Intelligence, Intrusion Detection, and Risk Prioritization platform. Built for modern Security Operations Centers (SOC), CYVANTIS continuously ingests security logs from honeypots and perimeter gateways, enriches telemetry with external threat feeds, correlates disparate events into unified incidents, predicts attack severity using machine learning, and calculates explainable risk scores with actionable defensive recommendations.

---

## 🏛️ System Architecture

```
                                  CYVANTIS ARCHITECTURE
+----------------------------------------------------------------------------------------------------+
|                                      DATA INGESTION LAYER                                          |
|  +--------------------+     +---------------------+     +--------------------+                     |
|  | Cowrie Honeypot    |     | Linux Auth Logs     |     | Network Security   |                     |
|  | JSON Events (22/23)|     | (/var/log/auth.log) |     | Telemetry Feeds    |                     |
|  +---------+----------+     +----------+----------+     +---------+----------+                     |
|            |                           |                          |                                |
|            +---------------------------+--------------------------+                                |
|                                        v                                                           |
|                 +-----------------------------------------------+                                  |
|                 | Incremental File Tailer & Checkpointer        |                                  |
|                 | - Persistent file offset tracking (.checkpoint) |                                 |
|                 | - Deterministic SHA-256 event hash deduplication |                                |
|                 | - UTC timestamp normalization & log rotation   |                                 |
|                 +----------------------+------------------------+                                  |
+----------------------------------------|-----------------------------------------------------------+
                                         v
+----------------------------------------------------------------------------------------------------+
|                                    PROCESSING & ENRICHMENT                                         |
|  +-------------------------------------+      +-------------------------------------------------+  |
|  | Threat Intelligence Engine          |      | AI / ML Detection Pipeline                      |  |
|  | - AbuseIPDB v2 IP reputation        |      | - Random Forest Classifier (100 Trees, Balanced)|  |
|  | - VirusTotal v3 Hash & Domain Intel |      | - Isolation Forest (Outlier Anomaly Detection)  |  |
|  | - NVD API 2.0 CVE Vulnerabilities   |      | - 70/15/15 Held-out Train/Val/Test Split        |  |
|  | - Local SQLite cache with TTL & backoff|   | - Leak-free feature extraction & explainability |  |
|  +------------------+------------------+      +------------------------+------------------------+  |
+---------------------|--------------------------------------------------|---------------------------+
                      +-------------------------+------------------------+
                                                v
+----------------------------------------------------------------------------------------------------+
|                               DETECTION & INCIDENT CORRELATION                                     |
|  +-----------------------------------------------------------------------------------------------+ |
|  | Rule-Based Detection Engine (Brute Force, Privileged Activity, Payloads, IOCs, Anomalies)    | |
|  +--------------------------------------------+--------------------------------------------------+ |
|                                               v                                                    |
|  +-----------------------------------------------------------------------------------------------+ |
|  | Incident Correlator & Deduplication Service                                                    | |
|  | - 30-Minute correlation window by IP & session into unified Investigation Cases               | |
|  | - 5-Minute alert deduplication with recurrence frequency counters                            | |
|  | - MITRE ATT&CK framework mapping (Tactics & Techniques)                                       | |
|  | - Automated actionable defensive mitigation recommendations                                    | |
|  +--------------------------------------------+--------------------------------------------------+ |
|                                               v                                                    |
|  +-----------------------------------------------------------------------------------------------+ |
|  | Explainable Risk Prioritization Engine (0 - 100 Score)                                        | |
|  | - Severity (30%) + Threat Intel (25%) + Scope (15%) + ML Anomaly (15%) + Asset Tier (15%)      | |
|  | - Factor-by-factor human-readable explanation and confidence multipliers                       | |
|  +--------------------------------------------+--------------------------------------------------+ |
+-----------------------------------------------|----------------------------------------------------+
                                                v
+----------------------------------------------------------------------------------------------------+
|                                   DELIVERY & PRESENTATION LAYER                                    |
|  +------------------------------------+       +-------------------------------------------------+  |
|  | Authenticated FastAPI REST & WS    |       | React 19 + TypeScript SOC Dashboard             |  |
|  | - JWT auth on WebSocket (/ws/events)|       | - Real-time live event streaming with reconnect |  |
|  | - Credential redaction (non-admin) |       | - Real vs Synthetic telemetry provenance labels |  |
|  | - Account lockout after 5 failures |       | - Interactive Threat Intel & CVE Radar search   |  |
|  | - Strict CORS origin validation    |       | - Alert triage drawer with explainable factors  |  |
|  +------------------------------------+       +-------------------------------------------------+  |
+----------------------------------------------------------------------------------------------------+
```

---

## 🌟 Core Capabilities & Requirements Matrix

| Requirement | Implementation Detail | Status |
| :--- | :--- | :--- |
| **Real Security Data Ingestion** | `app/ingestion/`: Cowrie JSON parser (`cowrie_parser.py`), Linux auth log parser (`auth_log_parser.py`), and atomic file tailer (`file_tailer.py`) with persistent `.checkpoint` offsets, file rotation handling, and SHA-256 deduplication. | ✅ Verified |
| **Telemetry Provenance** | Clear distinction between `data_source: cowrie` (real log ingestion) and `is_simulated: true` (demo telemetry) across backend and UI badges. | ✅ Verified |
| **Threat Intelligence Engine** | `app/services/threat_intelligence.py`: Multi-source client for AbuseIPDB, VirusTotal v3, and NVD API 2.0 with rate-limiting, exponential backoff, and local SQLite caching (`threat_intel_iocs`). | ✅ Verified |
| **Detection & Event Correlation** | `app/services/detection_engine.py` & `app/services/incident_correlator.py`: Multi-rule matching, 30-minute time-window incident grouping, 5-minute alert deduplication, MITRE ATT&CK alignment. | ✅ Verified |
| **MITRE ATT&CK Intelligence** | `app/services/mitre_attack.py` & `routers/mitre.py`: Authoritative v15.1 catalog (T1110.001, T1059.004, T1078, T1105, T1046, T1003.008, T1098, T1036, T1190) across 8 tactics, dynamic finding mapping, explicit non-proof disclaimer, and live matrix coverage aggregator. | ✅ Verified |
| **Threat Investigation Graph** | `app/services/investigation_graph.py`: Multi-relational network connecting Events, Incidents, Users, Assets, IPs, File Hashes, and CVEs. Strictly distinguishes **`OBSERVED`** edges (packet ground truth, confidence 1.0) from **`INFERRED`** edges (correlation & CVE mapping). | ✅ Verified |
| **Attack Pattern & Kill-Chain** | `app/services/attack_pattern_service.py`: 6-stage progression tracking (Recon -> Credential Access -> Initial Access -> Discovery -> Priv Escalation -> Ingress/C2), burst velocity anomaly detection, and heuristic forecasting with explicit non-deterministic guardrail. | ✅ Verified |
| **Asset & Vulnerability Context** | `app/services/asset_vulnerability_service.py`: Managed perimeter asset inventory (IP, hostname, tier, exposure, open ports) correlated with verified CVEs (regreSSHion, Telnetd buffer overflow, sudo Baron Samedit), CVSS scores, exploit status, and data freshness tracking. | ✅ Verified |
| **Analyst Feedback & Guardrails** | `routers/rules.py` & `models.py`: Analyst review workflow (`true_positive`, `false_positive`, `needs_review`) with mandatory audit logging. Safe guardrail: auto-mutation of production rule thresholds is disabled without SOC admin sign-off. | ✅ Verified |
| **Detection Benchmark Suite** | `app/services/detection_evaluation.py`: Repeatable synthetic benchmark suite with 20 ground-truth intrusion test vectors (10 TP, 10 TN). Evaluates Precision, Recall, F1-Score, False Positive Rate, and Latency with sample-size limitation notices. | ✅ Verified |
| **Valid AI / ML Pipeline** | `app/ml/trainer.py` & `app/ml/predictor.py`: Random Forest + Isolation Forest trained on 133,043 real telemetry samples without label leakage. 79.14% real accuracy, 74.28% F1 score, dynamic feature rationales. | ✅ Verified |
| **Explainable Risk Scoring** | `app/services/risk_scoring.py`: Documented mathematical formula across 5 bounded dimensions, priority bands (Critical, High, Medium, Low), and factor explanations. | ✅ Verified |
| **End-to-End Event Ingestion API** | `app/services/event_pipeline.py` & `routers/events.py`: Complete vertical slice via `POST /events/ingest`, `POST /events/import`, and `POST /events/upload`. Normalization, IP validation, SHA-256 idempotency, GeoIP, ML scoring, detection, correlation, and live WebSocket broadcast. | ✅ Verified |
| **Security Hardening** | JWT token authentication required on WebSocket, account lockout after 5 failed login attempts (15-min cooldown), password redaction (`****** (redacted)`) for non-admins, strict CORS whitelist. | ✅ Verified |
| **Centralized SOC Dashboard** | React 19 + TypeScript + Tailwind interface with live WebSocket reconnect, Omni-Source Threat Lookup, Case Management, Alert Triage, Chronological Incident Timeline, Containment Actions, and Ingest Modal. | ✅ Verified |
| **Automated Test Suite** | 57 unit and integration tests across 14 test modules covering ingestion, threat intel, correlation, risk scoring, ML pipeline, containment actions, MITRE ATT&CK, threat graphs, attack patterns, asset CVEs, feedback, and benchmarks. | ✅ 57/57 Passing |

---

## 🔬 Explainable Risk Prioritization Methodology

CYVANTIS calculates a deterministic risk score between **0.0 and 100.0** for every detected alert and correlated incident using a documented 5-dimensional weighted model:

$$\text{Risk Score} = 100 \times \left( 0.30 \times S + 0.25 \times T + 0.15 \times I + 0.15 \times M + 0.15 \times A \right) \times C$$

Where each factor is normalized between $0.0$ and $1.0$:

1. **Severity Score ($S$, weight: 30%)**:
   - `CRITICAL` = 1.0
   - `HIGH` = 0.75
   - `MEDIUM` = 0.50
   - `LOW` = 0.25
2. **Threat Intelligence Reputation ($T$, weight: 25%)**:
   - Normalized reputation from external feeds (AbuseIPDB abuse confidence percentage, VirusTotal malicious votes ratio). Defaults to baseline 0.30 if external intel is unconfigured.
3. **Incident Scope & Frequency ($I$, weight: 15%)**:
   - Bounded logarithmic scaling: $\min(1.0, \frac{\log_{10}(\text{related\_events} + 1)}{2.0})$. Multiple related attacks escalate priority.
4. **Machine Learning Anomaly Score ($M$, weight: 15%)**:
   - Outlier distance computed by Isolation Forest plus normalized classifier confidence.
5. **Asset Criticality & Exposure ($A$, weight: 15%)**:
   - Tier 1 (Critical Gateway / DMZ) = 1.0
   - Tier 2 (Application Node) = 0.70
   - Tier 3 (Internal Subnet / Honeypot) = 0.40
6. **Confidence Multiplier ($C$)**:
   - Bounds the score based on evidence quality (0.70 for unconfirmed heuristics to 1.0 for multi-source confirmed detections).

### Priority Thresholds:
- **CRITICAL**: Score $\ge 80.0$ (Immediate page / automated isolation)
- **HIGH**: Score $60.0 - 79.9$ (Analyst review required within 1 hour)
- **MEDIUM**: Score $40.0 - 59.9$ (Standard triage queue)
- **LOW**: Score $< 40.0$ (Informational logging / telemetry archival)

Every alert includes a `risk_factors` array explaining exactly which dimensions contributed to the calculated score.

---

## 🤖 Machine Learning Pipeline & Empirical Metrics

The machine learning subsystem implements dual-engine defense:
1. **Supervised Classifier**: Balanced Random Forest (100 estimators) classifying attack severity (`low`, `medium`, `high`, `critical`).
2. **Unsupervised Anomaly Detector**: Isolation Forest (100 estimators, 10% contamination) detecting novel, zero-day, or anomalous connection behaviors.

### Feature Engineering (Leakage-Free):
To prevent data leakage, direct labels and target-correlated flags (`event_login_success`, `event_login_failed`, `event_cmd_input`) were removed from training. Models train strictly on behavioral telemetry:
- `dst_port`: Destination port
- `duration`: Session duration in seconds
- `cmd_length`: Length of executed commands
- `username_length`: Target username length
- `has_password`: Whether credentials were submitted
- `is_ssh`: SSH protocol flag
- `is_telnet`: Telnet protocol flag
- `is_high_risk_port`: Privileged port targeting flag
- `cmd_has_curl_wget`: File retrieval payload indicator
- `cmd_has_sh_bash`: Shell execution indicator

### Empirical Evaluation on 133,043 Real Telemetry Records:
Models were trained using a 70% Train / 15% Validation / 15% Held-Out Test split on the historical honeypot dataset:

| Metric | Measured Value | Notes |
| :--- | :--- | :--- |
| **Dataset Size** | 133,043 events | Real historical Cowrie intrusion captures |
| **Held-Out Test Set** | 19,957 events | Never exposed during model training |
| **Classifier Accuracy** | **79.14%** | Genuine out-of-fold generalization |
| **Weighted Precision** | **79.47%** | Precision across all 4 severity classes |
| **Weighted Recall** | **79.14%** | Recall across all 4 severity classes |
| **Weighted F1 Score** | **74.28%** | Harmonic mean of precision and recall |
| **Anomaly Rate** | **8.04%** | Detected by unsupervised Isolation Forest |

Model artifacts are persisted in `backend/app/ml/saved_models/` (`severity_classifier.joblib`, `anomaly_detector.joblib`, `metrics.json`). Retraining is reproducible via CLI or the web UI.

---

## 🛡️ Security Hardening Specifications

1. **WebSocket JWT Authentication**:
   - Connection URL: `/api/v1/ws/events?token=<JWT_BEARER_TOKEN>`
   - Unauthenticated connection attempts are rejected immediately with WebSocket close code `1008` (Policy Violation).
2. **Credential Redaction**:
   - Plaintext passwords in captured telemetry are redacted to `****** (redacted)` for `analyst` and `viewer` roles across REST endpoints, detail drawers, and CSV/JSON exports. Only `admin` can view raw credentials.
3. **Account Lockout Policy**:
   - 5 consecutive failed login attempts automatically lock the account for 15 minutes (`locked_until`).
4. **Password Policy**:
   - Minimum 8 characters enforced on user registration and password updates.
5. **CORS Security**:
   - Replaced wildcard regex with strict configured origin whitelist (`CORS_ORIGINS`).
6. **OWASP Defensive Headers**:
   - Automated middleware injects `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and `Content-Security-Policy`.

---

## 🚀 Quickstart & Installation

### Prerequisites:
- Python 3.11+
- Node.js 18+ & npm
- Docker & Docker Compose (Optional)

---

### Method 1: Local Development

#### 1. Backend Setup:
```bash
cd backend
python -m venv venv

# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

# Install dependencies:
pip install -r requirements.txt
pip install email-validator

# Run database auto-migration & startup:
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### 2. Frontend Setup:
```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

---

### Method 2: Docker Compose

Deploy the complete multi-container stack (Cowrie honeypot, FastAPI backend, and Nginx frontend):

```bash
# Copy and configure environment variables
cp .env.example .env

# Build and start services
docker-compose up -d --build
```

- **Frontend SOC Dashboard**: `http://localhost`
- **Backend API & Swagger Docs**: `http://localhost:8000/api/v1/docs`
- **Cowrie Honeypot SSH**: `localhost:2222`
- **Cowrie Honeypot Telnet**: `localhost:2223`

---

## 🔑 Default Credentials

| Username | Password | Role | Permissions |
| :--- | :--- | :--- | :--- |
| `admin` | `Admin@Cyvantis2026!` | **Admin** | Full system control, credential visibility, backup/restore, user administration |
| `analyst` | `Analyst@Cyvantis2026!` | **Analyst** | Event investigation, note taking, alert acknowledgement, rule tuning |
| `viewer` | `Viewer@Cyvantis2026!` | **Viewer** | Read-only dashboards and report generation |

---

## 🔍 Threat Investigation & ATT&CK Intelligence (Phase 4)

CYVANTIS includes a deep threat investigation engine, MITRE ATT&CK alignment, kill-chain sequence analysis, asset-vulnerability context, and human-in-the-loop analyst feedback with rigorous SOC guardrails:

### 1. MITRE ATT&CK™ Enterprise Matrix Integration (v15.1)
- Authoritative local catalog covering 9 enterprise techniques across 8 tactics:
  - `T1110.001` (Password Guessing - Credential Access)
  - `T1059.004` (Unix Shell Execution - Execution)
  - `T1078` (Valid Accounts - Initial Access / Persistence)
  - `T1105` (Ingress Tool Transfer - Command and Control)
  - `T1046` (Network Service Discovery - Discovery)
  - `T1003.008` (/etc/passwd and /etc/shadow - Credential Access)
  - `T1098` (Account Manipulation - Persistence)
  - `T1036` (Masquerading - Defense Evasion)
  - `T1190` (Exploit Public-Facing Application - Initial Access)
- **Legal & Technical Guardrail**: Every mapped technique includes an explicit disclaimer stating that technique alignment demonstrates behavioral pattern similarity based on observed telemetry and does **NOT** constitute definitive proof of an adversary breach.
- Live ATT&CK Matrix coverage endpoint (`GET /api/v1/mitre/matrix`) tracks triggered detection counts and active technique density in real time.

### 2. Multi-Relational Threat Investigation Graph
- Interactive multi-entity network (`GET /api/v1/investigations/{id}/graph`) connecting:
  - **Incidents** (`incident`)
  - **Events** (`event`)
  - **Source IP Addresses** (`ip_address`)
  - **Target User Accounts** (`user`)
  - **Target Assets & Gateways** (`asset`)
  - **Ingressed Payloads & File Hashes** (`file_hash`)
  - **Correlated CVE Vulnerabilities** (`cve`)
- **Strict Relationship Semantics**:
  - `OBSERVED` Edges (Confidence 1.0): Direct raw log proof (packet source IP, targeted port, entered username, executed bash command, downloaded payload hash).
  - `INFERRED` Edges (Confidence 0.65 - 0.90): Analytics and correlation conclusions (incident time-window clustering, asset tier exposure, service-to-CVE vulnerability matches).
- Safe node-explosion bound limits rendering to 100 relevant entities with deep evidence inspection drawers.

### 3. Cyber Kill-Chain Sequence Analysis & Heuristic Forecasting
- Multi-stage sequence tracker (`GET /api/v1/investigations/{id}/attack-patterns`) mapping events across the 6-stage intrusion lifecycle:
  `Reconnaissance` → `Credential Access` → `Initial Access` → `Discovery` → `Privilege Escalation` → `Ingress Tool Transfer / C2`
- Identifies confirmed observed stages vs statistical burst velocity anomalies.
- **Forecasting Guardrail**: Projected next stages are explicitly labeled as **`HEURISTIC FORECAST (NON-DETERMINISTIC)`** with a strict requirement directing analysts to corroborate predictions with host forensics prior to executing containment.

### 4. Managed Asset Inventory & CVE Vulnerability Context
- Tracks perimeter infrastructure (`gw-edge-01`, `sensor-ssh-01`, `bastion-core-01`) with asset tier, network exposure, open ports, and installed services.
- Automatically correlates observed attack vectors with verified CVE advisories:
  - `CVE-2024-6387` (regreSSHion - OpenSSH Remote Code Execution)
  - `CVE-2020-10188` (Telnetd Buffer Overflow)
  - `CVE-2023-38408` (OpenSSH PKCS#11 Forwarding)
  - `CVE-2021-3156` (Sudo Baron Samedit Local Privilege Escalation)
- Displays CVSS scores, known exploited status, remediation instructions, data sources, and telemetry freshness.

### 5. Human Analyst Feedback & Anti-Mutation Guardrails
- SOC analysts can verify alerts with ground-truth classifications (`POST /api/v1/rules/alerts/{id}/feedback`):
  - `true_positive`: Confirmed malicious adversary activity.
  - `false_positive`: Benign administrative or benign scanner noise candidate for tuning.
  - `needs_review`: Ambiguous pattern requiring escalation or additional telemetry.
- **Safety Policy**: Feedback submissions record cryptographic audit log trails and update validation metrics (`GET /api/v1/rules/alerts/feedback-summary`), but **DISABLED from automatically mutating live production rule thresholds** without administrative review.

### 6. Standardized Synthetic Detection Benchmark
- Repeatable 20-vector intrusion benchmark (`POST /api/v1/rules/evaluation/run-benchmark`):
  - 10 Ground-Truth Attacks (Droppers, reverse shells, credential dumping, persistence backdoors, cryptominers).
  - 10 Ground-Truth Benign Operations (System health checks, uptime, user queries, clean log reads).
  - Measures Precision, Recall, F1-Score, False Positive Rate (FPR), and per-event processing latency.

---

## 🧪 Running Automated Tests

Run the full pytest suite (57 automated tests across 14 test modules) from the `backend/` directory:

```bash
cd backend
.\venv\Scripts\python.exe -m pytest tests -v
```

### Test Coverage Highlights:
- `tests/test_threat_investigation_phase4.py`: 7 automated tests verifying MITRE ATT&CK v15.1 catalog lookup, matrix coverage aggregation, threat investigation graph observed vs inferred edge classification, kill-chain sequence analysis, asset vulnerability context correlation, analyst feedback workflow with RBAC rejection, and synthetic benchmark evaluation metrics.
- `tests/test_event_ingestion_api.py`: Complete end-to-end event ingestion pipeline (`POST /events/ingest`, `/import`, `/upload`), IP and severity validation, SHA-256 deduplication idempotency, detection rule triggers, and RBAC rejection.
- `tests/test_investigation_timeline.py`: Incident chronology ordered events timeline, explicit containment authorization confirmation, RBAC containment enforcement, and automated audit logging.
- `tests/test_ingestion.py`: Cowrie JSON parsing, auth log syslog parsing, malformed JSON recovery, and atomic checkpointing.
- `tests/test_threat_intel.py`: AbuseIPDB IP enrichment, VirusTotal hash lookup, NVD CVE resolution, and caching TTL.
- `tests/test_detection_and_correlation.py`: Detection rule triggers, 30-min incident correlation, alert deduplication, and risk scoring formula bounds.
- `tests/test_ml.py`: Model training verification, feature extraction, held-out test predictions, and `/ml/predict` inference.
- `tests/test_security_hardening.py`: Account lockout policy verification, password redaction for non-admins, and WebSocket unauthenticated rejection.
- `tests/test_auth.py`: Login, 2FA setup/verification, token expiration, first-login password changes.
- `tests/test_events.py`: Event explorer pagination, protocol filters, overview analytics.
- `tests/test_backup.py`: Atomic SQLite snapshot backup creation, list, and storage health.
- `tests/test_tools.py`: Subnet calculator, password analyzer, log extractor, header auditor, and hash generator.

---

## 💻 CYVANTIS Administrative CLI

The platform includes an administrative CLI (`cyvantis.py` / `cyvantis.bat`):

```bash
# System health check
python cyvantis.py health

# Train ML models from command line
python cyvantis.py train-ml

# Export security telemetry
python cyvantis.py events export --format csv --output events.csv

# Create atomic SQLite backup snapshot
python cyvantis.py storage backup

# Launch interactive 32-option SOC console
python cyvantis.py menu
```

---

## 📁 Repository Structure

```
CYVANTIS/
├── backend/
│   ├── app/
│   │   ├── config.py                  # Platform settings & environment variables
│   │   ├── database.py                # SQLite connection & auto-migration engine
│   │   ├── models.py                  # SQLAlchemy ORM database models
│   │   ├── schemas.py                 # Pydantic v2 validation schemas
│   │   ├── security.py                # JWT auth, password hashing, RBAC dependencies
│   │   ├── websocket.py               # Authenticated WebSocket connection manager
│   │   ├── cowrie_watcher.py          # Unified log ingestion & correlation worker
│   │   ├── ingestion/                 # Modular log ingestion layer
│   │   │   ├── base.py                # BaseLogSource interface & NormalizedEvent
│   │   │   ├── cowrie_parser.py       # Cowrie JSON honeypot parser
│   │   │   ├── auth_log_parser.py     # Linux SSH syslog parser
│   │   │   └── file_tailer.py         # Incremental tailer with checkpoint offsets
│   │   ├── services/                  # Core business logic services
│   │   │   ├── event_pipeline.py      # End-to-end event ingestion & detection pipeline
│   │   │   ├── threat_intelligence.py # AbuseIPDB, VirusTotal, NVD client & cache
│   │   │   ├── risk_scoring.py        # 5-factor explainable risk scoring engine
│   │   │   ├── detection_engine.py    # Rule-based threat detector
│   │   │   └── incident_correlator.py # Incident correlation & alert deduplicator
│   │   ├── ml/                        # Machine learning subsystem
│   │   │   ├── trainer.py             # Random Forest & Isolation Forest training
│   │   │   ├── predictor.py           # ML inference & feature rationale engine
│   │   │   └── saved_models/          # Persisted models & metrics.json
│   │   └── routers/                   # FastAPI REST API endpoints
│   ├── tests/                         # Pytest test suite (38 tests)
│   └── requirements.txt               # Backend Python dependencies
├── frontend/
│   ├── src/
│   │   ├── components/                # Reusable UI cards, badges, charts
│   │   ├── context/                   # AuthContext, WebSocketContext (auto-reconnect)
│   │   ├── pages/                     # 26 SOC dashboard & analysis views
│   │   ├── services/api.ts            # Typed HTTP client & WS connection builder
│   │   └── types/index.ts             # TypeScript domain interfaces
│   └── package.json                   # React 19 + Vite dependencies
├── docker/
│   ├── Dockerfile.backend             # Python 3.11 backend container
│   ├── Dockerfile.frontend            # Node 20 build + Nginx container
│   ├── Dockerfile.cowrie              # Cowrie honeypot container
│   └── nginx.conf                     # Nginx reverse proxy & SPA router
├── docker-compose.yml                 # Multi-container orchestration
├── .env.example                       # Documented environment configuration
├── cyvantis.py                        # Administrative CLI tool
└── README.md                          # Platform documentation
```

---

## 📜 License & Compliance

CYVANTIS is designed for defensive security monitoring, honeypot telemetry analysis, and authorized penetration testing. All synthetic data generators and live log parsers operate within authorized organizational boundaries.
