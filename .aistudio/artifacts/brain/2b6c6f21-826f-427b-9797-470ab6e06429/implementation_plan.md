# SentinelPulse — Real-Time System Telemetry & Threat Alert Console

SentinelPulse restores and rebuilds the complete Python real-time system monitoring, ML threat classification, and SQLite-backed alert management platform (`alerts.db`) running on Flask and Socket.IO at port 3000, while resolving the root workspace startup failure caused by the missing application entry point and redundant virtual environment upload.

## User Review & Critical Decisions

> [!IMPORTANT]
> Review the confirmed architectural and product choices from our clarification step before execution begins:

- **Confirmed Application Scope**: Full rebuild of the real-time system monitoring and intrusion/anomaly alert console in this workspace, removing the broken Windows `.venv311new` upload artifact so the Linux Python runtime starts cleanly on port 3000.
- **Confirmed Core Feature Set**:
  1. Real-time system metrics and anomaly detection stream over Socket.IO.
  2. Live alert feed backed by persistent SQLite storage (`alerts.db`) with status workflow (`Open`, `Acknowledged`, `Resolved`).
  3. ML model threat classification and anomaly scoring engine (using `scikit-learn` / `joblib` Isolation Forest & Random Forest threat classifier with on-boot training/serialization and interactive threat testing).
  4. Interactive analytics charts (real-time CPU/Memory/Network/Disk telemetry + threat distribution breakdown) and multi-criteria alert filtering.
  5. Custom alert rules and threshold configuration manager persisted in SQLite.
- **Confirmed Technology Stack**: Python Flask + Flask-SocketIO + SQLite (`alerts.db`) served on `0.0.0.0:3000` with a zero-npm Python project configuration (`requirements.txt` + `app.py`) so the platform executes natively as a Python web application without `bun install` errors.

---

## 1. Overview & Core Concept

- **What It Does**: Continuously monitors host and simulated multi-node telemetry (CPU load, memory pressure, network packet throughput, outbound connection spikes, disk I/O latency, and process anomalies), evaluates every telemetry frame against both user-configurable threshold rules and a `joblib`-persisted ML anomaly/threat classification pipeline, persists triggered alerts into `alerts.db`, and broadcasts live updates to all connected operators via WebSockets.
- **Target Audience / Persona**: Security Operations Center (SOC) analysts, site reliability engineers (SREs), and system administrators who need immediate visibility into resource spikes, suspicious network/process behavior, and actionable alert triage.
- **Key Value**: Combines deterministic rule thresholds with ML-driven anomaly scoring and persistent SQLite audit trails in a single, low-latency real-time console.

---

## 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Live Telemetry & Triage Overview**: Upon opening the console, operators see a 4-metric KPI strip (System Health State, Active Unresolved Alerts, Mean Anomaly Score, and Telemetry Throughput), a live multi-series time-series chart streaming Socket.IO frames every 2 seconds, and the real-time Alert Triage Feed.
  2. **Alert Investigation & Status Workflow**: Clicking any alert row opens a detailed inspection drawer showing the exact telemetry snapshot at trigger time, ML threat category (`Benign`, `Resource Exhaustion`, `Port Scan / Network Flood`, `Privilege Escalation Anomaly`, `Data Exfiltration Spike`), confidence score, matched rule, and one-click actions to **Acknowledge**, **Resolve**, or **Delete** the alert (immediately synced across clients and saved to `alerts.db`).
  3. **ML Threat Classifier & Scenario Simulator**: Operators can trigger realistic workload or attack scenarios (e.g., *SYN Flood Spike*, *Memory Leak Runaway*, *Crypto-Miner CPU Anomaly*, *Unauthorized Port Sweep*) or submit custom telemetry vectors to inspect real-time ML classification probabilities and anomaly scores.
  4. **Custom Alert Rules & Thresholds**: Operators can create, toggle, edit, and delete custom threshold rules (e.g., `CPU Usage > 85%`, `Network Outbound > 450 Mbps`, `ML Anomaly Score > 0.75`) that take effect immediately in the live evaluation loop.
  5. **Filtering & Historical Export**: Instant filtering by severity (`Critical`, `Warning`, `Info`), lifecycle status, threat category, and free-text search, plus one-click CSV export of filtered `alerts.db` records.

- **Visual Identity & Theme**:
  - *Aesthetic Direction*: High-craft enterprise observability console (inspired by Linear, Datadog, and Chronicle) with clean 1px structural borders, single-elevation flat surfaces, and zero decorative clutter.
  - *Color Palette & Mood*:
    - `--background`: `#0B0F19` (Deep slate-obsidian canvas, 60% allocation)
    - `--surface`: `#111827` with `#1E293B` 1px hairline borders (30% structural surface allocation)
    - `--text-primary`: `#F8FAFC` / `--text-muted`: `#94A3B8`
    - `--accent`: `#3B82F6` ( Precision Cobalt for primary interactive controls, 10% allocation)
    - *Semantic States (Always paired with explicit text labels)*: Nominal `#16A34A` (`Nominal`), Warning `#D97706` (`Warning`), Critical `#DC2626` (`Critical`).
  - *Typography & Hierarchy*:
    - Display & Navigation: `Plus Jakarta Sans` (SemiBold 600, tight tracking)
    - UI Body & Controls: `DM Sans` (Regular 400 / Medium 500)
    - Telemetry, Timestamps, Scores & Tabular Data: `JetBrains Mono` with strict `font-variant-numeric: tabular-nums` so live streaming numbers never jitter horizontally.
  - *Component Styling & Layout*:
    - Full-viewport 1440px desktop architecture featuring a Top Bar adhering to the 3-zone contract (Brand wordmark on left, 4 single-line view navigation links in center: `Live Console`, `Alert Feed`, `ML Classifier`, `Threshold Rules`, and 1 primary action button `Inject Test Event` on right).
    - High-density data tables ($40\text{px}$ row height) with unboxed metadata separated by middle dots (`·`) and zero pill-badge clutter.

- **Interactive Feedback & Motion**:
  - Sub-150ms button and filter transitions using `cubic-bezier(0.16, 1, 0.3, 1)`.
  - Smooth chart canvas updates and idempotent Socket.IO event reconciliation without full-page reloads.
  - Explicit empty states, loading skeletons, and toast confirmations for rule changes and alert triage actions.

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Pure Python Runtime Alignment (`requirements.txt` + `app.py`)**
  - *Chosen Approach*: Configure the project as a canonical Python web application with `app.py` and `requirements.txt`, removing the uploaded Windows `.venv311new` directory and ensuring `package.json` contains zero npm dependencies.
  - *Why*: The platform runner automatically detects a Python project when `package.json` has no npm dependencies and `app.py` / `requirements.txt` are present, installing Python packages cleanly and running `python3 app.py` on port 3000 without invoking `bun install`.
  - *Alternatives Considered*: Keeping a hybrid Node + Python workspace was rejected because unnecessary npm steps caused `bun install` failures.

- **Decision 2: SQLite (`alerts.db`) with WAL Mode & Thread-Safe Repository Layer**
  - *Chosen Approach*: Persist all alerts, custom threshold rules, and telemetry audit snapshots in `alerts.db` using SQLite with Write-Ahead Logging (`PRAGMA journal_mode=WAL`).
  - *Why*: Matches the original repository's `.gitignore` (`alerts.db`) while enabling concurrent reads and writes between the background Socket.IO telemetry worker and HTTP REST endpoints.

- **Decision 3: Embedded `joblib` ML Threat Classifier**
  - *Chosen Approach*: Build and serialize a lightweight `scikit-learn` Random Forest + Isolation Forest pipeline via `joblib` (`threat_model.joblib`) on startup if not already cached on disk.
  - *Why*: Delivers real, deterministic machine-learning anomaly scores and multi-class threat probabilities on every telemetry tick and manual inspection request without external API latency.

---

## 4. Technical Architecture & Data Strategy *(Technical Reference)*

- **Architecture & Component Diagram**:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                     Browser Client (0.0.0.0:3000)                            │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │ Top Bar: Brand Wordmark  │  Console · Alerts · ML Lab · Rules  │ CTA   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│         │                         │                        │                 │
│         ▼                         ▼                        ▼                 │
│  ┌─────────────────┐    ┌───────────────────┐    ┌────────────────────────┐  │
│  │ Live Telemetry  │    │ Alert Triage Grid │    │ ML Threat Inspector &  │  │
│  │ & KPI Stream    │    │ & Detail Drawer   │    │ Threshold Rule Manager │  │
│  └────────▲────────┘    └─────────▲─────────┘    └───────────▲────────────┘  │
│           │                       │                          │               │
│           └───────────────────────┼──────────────────────────┘               │
│                     Socket.IO (telemetry:tick, alert:new,                    │
│                     alert:updated) + REST (/api/*)                           │
└───────────────────────────────────┼──────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                   Python Flask + Flask-SocketIO Server                       │
│                                                                              │
│  ┌─────────────────────────┐          ┌───────────────────────────────────┐  │
│  │ Background Telemetry &  │─────────►│ Rule Evaluator & Joblib ML Engine │  │
│  │ Host Collector Worker   │          │ (IsolationForest + RandomForest)  │  │
│  └─────────────────────────┘          └─────────────────┬─────────────────┘  │
│                                                         │                    │
│                                                         ▼                    │
│                                       ┌───────────────────────────────────┐  │
│                                       │ SQLite Persistence (alerts.db)    │  │
│                                       │ - alerts table                    │  │
│                                       │ - alert_rules table               │  │
│                                       │ - telemetry_history table         │  │
│                                       └───────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
```

- **Data Model & State (`alerts.db`)**:
  - `alerts`: `id`, `timestamp`, `source_host`, `metric_name`, `metric_value`, `threshold_value`, `severity` (`Critical` | `Warning` | `Info`), `threat_class`, `ml_anomaly_score`, `ml_confidence`, `status` (`Open` | `Acknowledged` | `Resolved`), `description`, `snapshot_json`.
  - `alert_rules`: `id`, `name`, `metric` (`cpu_percent`, `memory_percent`, `net_Mbps`, `disk_io_ms`, `failed_auth_rate`, `ml_score`), `operator` (`>`, `>=`, `<`), `threshold`, `severity`, `enabled`, `created_at`.
  - `telemetry_history`: Rolling window of recent telemetry frames (`timestamp`, `cpu_percent`, `memory_percent`, `net_Mbps`, `disk_io_ms`, `active_connections`, `failed_auth_rate`, `ml_anomaly_score`, `predicted_class`).

- **Interactive Component & State Mapping**:
  - **Live Stream & Pause/Resume Control**: Streams `telemetry:tick` events every 2 seconds via Socket.IO; client maintains a 60-point ring buffer and allows pausing/resuming live chart updates.
  - **Scenario Injection Controls**: Clicking a preset scenario (`SYN Flood`, `Memory Runaway`, `Brute-Force Auth`, `Disk Stall`) or `Inject Test Event` posts to `POST /api/simulate`, shifting the server telemetry generator into that anomaly regime for real evaluation and broadcasting resulting `alert:new` events to all connected clients.
  - **Alert Triage & Filtering**: `PATCH /api/alerts/<id>` updates status (`Open` → `Acknowledged` → `Resolved`) and emits `alert:updated` over Socket.IO; `DELETE /api/alerts/<id>` removes an alert; `POST /api/alerts/bulk-resolve` resolves filtered alerts.
  - **ML Classifier Sandbox**: `POST /api/ml/predict` accepts custom metric sliders (CPU, Memory, Network Mbps, Disk Latency, Failed Logins/min) and returns the exact `joblib` model anomaly score, predicted threat class, and per-class probability breakdown.
  - **Custom Rule CRUD**: `GET/POST /api/rules`, `PATCH /api/rules/<id>`, and `DELETE /api/rules/<id>` validate inputs, update `alerts.db`, and immediately reload the active rule set in the telemetry worker.
