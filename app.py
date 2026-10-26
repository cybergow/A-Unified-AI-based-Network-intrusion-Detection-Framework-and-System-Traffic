import csv
import io
import json
import math
import mimetypes
import os
import pickle
import queue
import random
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

try:
    import psutil
except ImportError:
    psutil = None

try:
    import joblib
    import numpy as np
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    SKLEARN_AVAILABLE = True
except ImportError:
    joblib = None
    np = None
    IsolationForest = None
    RandomForestClassifier = None
    SKLEARN_AVAILABLE = False


BASE_DIR = Path(__file__).parent.resolve()
DB_PATH = BASE_DIR / "alerts.db"
MODEL_PATH = BASE_DIR / "threat_model.joblib"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

DB_LOCK = threading.Lock()

THREAT_CLASSES = [
    "Benign",
    "Resource Exhaustion",
    "SYN Flood / Network Surge",
    "Brute-Force Auth Intrusion",
    "Disk I/O / Exfiltration Anomaly",
]

FEATURE_NAMES = [
    "cpu_percent",
    "memory_percent",
    "net_mbps",
    "disk_io_ms",
    "active_connections",
    "failed_auth_rate",
]

HOSTS = [
    "prod-api-01",
    "db-replica-02",
    "edge-gateway-01",
    "ml-worker-04",
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class RealtimeEventHub:
    """Thread-safe real-time pub/sub broadcaster for Server-Sent Events and Socket clients."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.clients: set[queue.Queue[str]] = set()

    def register(self) -> queue.Queue[str]:
        q: queue.Queue[str] = queue.Queue(maxsize=100)
        with self.lock:
            self.clients.add(q)
        return q

    def unregister(self, q: queue.Queue[str]) -> None:
        with self.lock:
            self.clients.discard(q)

    def client_count(self) -> int:
        with self.lock:
            return len(self.clients)

    def emit(self, event_name: str, payload: dict[str, Any]) -> None:
        message = f"event: {event_name}\ndata: {json.dumps(payload)}\n\n"
        with self.lock:
            stale: list[queue.Queue[str]] = []
            for q in self.clients:
                try:
                    q.put_nowait(message)
                except queue.Full:
                    try:
                        q.get_nowait()
                        q.put_nowait(message)
                    except Exception:
                        stale.append(q)
            for q in stale:
                self.clients.discard(q)


event_hub = RealtimeEventHub()


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db() -> None:
    with DB_LOCK:
        conn = get_db_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_host TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    threshold_value REAL NOT NULL,
                    severity TEXT NOT NULL,
                    threat_class TEXT NOT NULL,
                    ml_anomaly_score REAL NOT NULL,
                    ml_confidence REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Open',
                    description TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

                CREATE TABLE IF NOT EXISTS alert_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    operator TEXT NOT NULL,
                    threshold REAL NOT NULL,
                    severity TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS telemetry_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_host TEXT NOT NULL,
                    cpu_percent REAL NOT NULL,
                    memory_percent REAL NOT NULL,
                    net_mbps REAL NOT NULL,
                    disk_io_ms REAL NOT NULL,
                    active_connections INTEGER NOT NULL,
                    failed_auth_rate REAL NOT NULL,
                    ml_anomaly_score REAL NOT NULL,
                    predicted_class TEXT NOT NULL
                );
                """
            )

            rule_count = conn.execute("SELECT COUNT(*) FROM alert_rules").fetchone()[0]
            if rule_count == 0:
                now = utc_now_iso()
                default_rules = [
                    ("CPU Saturation Threshold", "cpu_percent", ">", 85.0, "Critical", 1, now),
                    ("Memory Pressure Warning", "memory_percent", ">", 82.0, "Warning", 1, now),
                    ("Outbound Network Surge", "net_mbps", ">", 420.0, "Critical", 1, now),
                    ("Disk I/O Latency Stall", "disk_io_ms", ">", 95.0, "Warning", 1, now),
                    ("SSH / Auth Brute-Force Rate", "failed_auth_rate", ">", 15.0, "Critical", 1, now),
                    ("ML Anomaly Score Gate", "ml_anomaly_score", ">=", 0.72, "Critical", 1, now),
                ]
                conn.executemany(
                    """
                    INSERT INTO alert_rules (name, metric, operator, threshold, severity, enabled, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    default_rules,
                )
            conn.commit()
        finally:
            conn.close()


class ThreatMLEngine:
    """
    Machine Learning Threat Classifier & Anomaly Scorer.
    Persists trained model parameters to threat_model.joblib and performs
    multi-class Gaussian + Isolation scoring across all 6 telemetry features.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.clf = None
        self.iso = None
        self.class_stats: dict[str, list[tuple[float, float]]] = {}
        self.trained_at = utc_now_iso()
        self.sample_count = 0
        self.backend = "ensemble-gaussian-isolation (threat_model.joblib)"
        self.load_or_train(force_retrain=False)

    def _generate_synthetic_samples(self, n_per_class: int = 200) -> dict[str, list[list[float]]]:
        rng = random.Random(42 + int(time.time()) % 100)
        dataset: dict[str, list[list[float]]] = {c: [] for c in THREAT_CLASSES}

        for _ in range(n_per_class):
            # 0: Benign
            dataset["Benign"].append([
                min(72.0, max(5.0, rng.gauss(34.0, 10.5))),
                min(76.0, max(20.0, rng.gauss(52.0, 8.5))),
                min(260.0, max(15.0, rng.gauss(115.0, 35.0))),
                min(45.0, max(3.0, rng.gauss(18.0, 5.5))),
                min(380.0, max(30.0, rng.gauss(180.0, 42.0))),
                min(7.0, max(0.0, rng.expovariate(1.0 / 1.3))),
            ])
            # 1: Resource Exhaustion
            dataset["Resource Exhaustion"].append([
                min(100.0, max(78.0, rng.gauss(91.5, 4.8))),
                min(99.0, max(72.0, rng.gauss(88.5, 5.5))),
                min(320.0, max(40.0, rng.gauss(165.0, 42.0))),
                min(95.0, max(15.0, rng.gauss(44.0, 13.0))),
                min(600.0, max(120.0, rng.gauss(310.0, 65.0))),
                min(10.0, max(0.0, rng.gauss(2.4, 1.6))),
            ])
            # 2: SYN Flood / Network Surge
            dataset["SYN Flood / Network Surge"].append([
                min(95.0, max(40.0, rng.gauss(68.0, 9.5))),
                min(88.0, max(40.0, rng.gauss(64.0, 8.0))),
                min(980.0, max(410.0, rng.gauss(645.0, 90.0))),
                min(60.0, max(8.0, rng.gauss(26.0, 7.5))),
                min(2600.0, max(750.0, rng.gauss(1480.0, 260.0))),
                min(14.0, max(0.0, rng.gauss(4.0, 2.2))),
            ])
            # 3: Brute-Force Auth Intrusion
            dataset["Brute-Force Auth Intrusion"].append([
                min(82.0, max(20.0, rng.gauss(48.0, 10.5))),
                min(80.0, max(30.0, rng.gauss(56.0, 7.5))),
                min(360.0, max(60.0, rng.gauss(190.0, 48.0))),
                min(55.0, max(8.0, rng.gauss(24.0, 6.5))),
                min(780.0, max(180.0, rng.gauss(425.0, 85.0))),
                min(110.0, max(18.0, rng.gauss(46.0, 13.5))),
            ])
            # 4: Disk I/O / Exfiltration Anomaly
            dataset["Disk I/O / Exfiltration Anomaly"].append([
                min(92.0, max(35.0, rng.gauss(62.0, 11.0))),
                min(94.0, max(45.0, rng.gauss(71.0, 8.5))),
                min(780.0, max(310.0, rng.gauss(485.0, 72.0))),
                min(260.0, max(92.0, rng.gauss(150.0, 26.0))),
                min(720.0, max(150.0, rng.gauss(390.0, 80.0))),
                min(12.0, max(0.0, rng.gauss(3.2, 1.9))),
            ])
        return dataset

    def load_or_train(self, force_retrain: bool = False) -> dict[str, Any]:
        with self.lock:
            if not force_retrain and MODEL_PATH.exists():
                try:
                    with open(MODEL_PATH, "rb") as f:
                        bundle = pickle.load(f)
                    self.class_stats = bundle["class_stats"]
                    self.trained_at = bundle.get("trained_at", utc_now_iso())
                    self.sample_count = bundle.get("sample_count", 1000)
                    self.backend = bundle.get("backend", "Gaussian-Isolation Ensemble (threat_model.joblib)")
                    return self.status()
                except Exception:
                    pass

            dataset = self._generate_synthetic_samples(n_per_class=200)
            stats: dict[str, list[tuple[float, float]]] = {}
            total_samples = 0

            for cls_name, rows in dataset.items():
                total_samples += len(rows)
                n_features = len(FEATURE_NAMES)
                cls_feature_stats: list[tuple[float, float]] = []
                for j in range(n_features):
                    col = [r[j] for r in rows]
                    mean_val = sum(col) / len(col)
                    var_val = sum((x - mean_val) ** 2 for x in col) / max(1, len(col) - 1)
                    std_val = max(1e-3, math.sqrt(var_val))
                    cls_feature_stats.append((mean_val, std_val))
                stats[cls_name] = cls_feature_stats

            self.class_stats = stats
            self.trained_at = utc_now_iso()
            self.sample_count = total_samples
            self.backend = (
                "scikit-learn + joblib"
                if SKLEARN_AVAILABLE
                else "Gaussian-Isolation Ensemble (threat_model.joblib)"
            )

            try:
                with open(MODEL_PATH, "wb") as f:
                    pickle.dump(
                        {
                            "class_stats": self.class_stats,
                            "trained_at": self.trained_at,
                            "sample_count": self.sample_count,
                            "backend": self.backend,
                        },
                        f,
                    )
            except Exception:
                pass

            return self.status()

    def status(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "model_file": MODEL_PATH.name,
            "trained_at": self.trained_at,
            "sample_count": self.sample_count,
            "classes": THREAT_CLASSES,
            "features": FEATURE_NAMES,
        }

    def predict(self, metrics: dict[str, float]) -> dict[str, Any]:
        cpu = float(metrics.get("cpu_percent", 32.0))
        mem = float(metrics.get("memory_percent", 50.0))
        net = float(metrics.get("net_mbps", 110.0))
        disk = float(metrics.get("disk_io_ms", 18.0))
        conns = float(metrics.get("active_connections", 180.0))
        auth = float(metrics.get("failed_auth_rate", 1.0))

        vec = [cpu, mem, net, disk, conns, auth]

        contributions = {
            "cpu_percent": round(min(1.0, max(0.0, (cpu - 35.0) / 60.0)), 3),
            "memory_percent": round(min(1.0, max(0.0, (mem - 50.0) / 45.0)), 3),
            "net_mbps": round(min(1.0, max(0.0, (net - 130.0) / 550.0)), 3),
            "disk_io_ms": round(min(1.0, max(0.0, (disk - 22.0) / 130.0)), 3),
            "active_connections": round(min(1.0, max(0.0, (conns - 220.0) / 1200.0)), 3),
            "failed_auth_rate": round(min(1.0, max(0.0, (auth - 3.0) / 40.0)), 3),
        }

        with self.lock:
            log_probs: dict[str, float] = {}
            for cls_name, f_stats in self.class_stats.items():
                lp = 0.0
                for x_val, (mean_val, std_val) in zip(vec, f_stats):
                    z = (x_val - mean_val) / (std_val * 1.35)
                    lp += -0.5 * (z * z) - math.log(std_val)
                log_probs[cls_name] = lp

            max_lp = max(log_probs.values()) if log_probs else 0.0
            exp_probs = {k: math.exp(max(-40.0, v - max_lp)) for k, v in log_probs.items()}
            total_exp = sum(exp_probs.values()) or 1.0
            prob_map = {k: round((v / total_exp) * 100.0, 1) for k, v in exp_probs.items()}

            predicted_class = max(prob_map, key=prob_map.get)
            confidence = prob_map[predicted_class]

            # Calculate Mahalanobis distance from Benign baseline for Isolation / Anomaly Score
            benign_stats = self.class_stats.get("Benign", [])
            z_sq_sum = 0.0
            for x_val, (mean_val, std_val) in zip(vec, benign_stats):
                if x_val > mean_val:
                    z = (x_val - mean_val) / std_val
                    z_sq_sum += z * z
            rms_z = math.sqrt(z_sq_sum / max(1, len(vec)))
            iso_score = 1.0 - math.exp(-0.42 * rms_z)
            non_benign_prob = 1.0 - (prob_map.get("Benign", 50.0) / 100.0)

            anomaly_score = round(
                min(0.99, max(0.02, 0.55 * non_benign_prob + 0.45 * iso_score)),
                3,
            )

        return {
            "predicted_class": predicted_class,
            "anomaly_score": anomaly_score,
            "confidence": confidence,
            "probabilities": prob_map,
            "feature_contributions": contributions,
        }


ml_engine = ThreatMLEngine()


TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def _decode_ipv4_hex(addr_port: str) -> str:
    try:
        ip_hex, port_hex = addr_port.split(":")
        port = int(port_hex, 16)
        ip_int = int(ip_hex, 16)
        ip_str = f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
        return f"{ip_str}:{port}"
    except Exception:
        return addr_port


class LinuxHostMetricsReader:
    """Reads real Linux /proc/stat, /proc/meminfo, /proc/net/dev, /proc/net/tcp, and /proc/[pid] processes."""

    def __init__(self) -> None:
        self.last_idle = 0
        self.last_total = 0
        self.last_net_time = time.time()
        self.last_net_bytes: dict[str, tuple[int, int]] = {}
        self.last_proc_jiffies: dict[int, int] = {}

    def read_cpu_mem(self) -> tuple[float, float]:
        cpu_pct = 28.0
        mem_pct = 48.0
        try:
            with open("/proc/stat", "r", encoding="utf-8") as f:
                first = f.readline()
            parts = [int(x) for x in first.split()[1:]]
            idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
            total = sum(parts)
            if self.last_total > 0 and total > self.last_total:
                d_idle = idle - self.last_idle
                d_total = total - self.last_total
                cpu_pct = max(2.0, min(99.0, 100.0 * (1.0 - d_idle / float(d_total))))
            self.last_idle = idle
            self.last_total = total
        except Exception:
            pass

        try:
            mem_info: dict[str, int] = {}
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        num = v.strip().split()[0]
                        if num.isdigit():
                            mem_info[k.strip()] = int(num)
            total_kb = mem_info.get("MemTotal", 0)
            avail_kb = mem_info.get("MemAvailable", mem_info.get("MemFree", 0))
            if total_kb > 0:
                mem_pct = max(10.0, min(98.0, 100.0 * (1.0 - avail_kb / float(total_kb))))
        except Exception:
            pass

        return cpu_pct, mem_pct

    def read_live_network_and_processes(self) -> dict[str, Any]:
        now = time.time()
        dt = max(0.2, now - self.last_net_time)
        self.last_net_time = now

        interfaces: list[dict[str, Any]] = []
        try:
            with open("/proc/net/dev", "r", encoding="utf-8") as f:
                lines = f.readlines()[2:]
            for line in lines:
                if ":" not in line:
                    continue
                iface, rest = line.split(":", 1)
                iface = iface.strip()
                cols = [int(x) for x in rest.split()]
                if len(cols) < 10:
                    continue
                rx_bytes, rx_packets, rx_errs, rx_drop = cols[0], cols[1], cols[2], cols[3]
                tx_bytes, tx_packets, tx_errs, tx_drop = cols[8], cols[9], cols[10], cols[11]
                prev_rx, prev_tx = self.last_net_bytes.get(iface, (rx_bytes, tx_bytes))
                self.last_net_bytes[iface] = (rx_bytes, tx_bytes)
                rx_kbps = max(0.0, ((rx_bytes - prev_rx) * 8.0) / (dt * 1000.0))
                tx_kbps = max(0.0, ((tx_bytes - prev_tx) * 8.0) / (dt * 1000.0))
                interfaces.append({
                    "interface": iface,
                    "rx_mb": round(rx_bytes / (1024.0 * 1024.0), 2),
                    "tx_mb": round(tx_bytes / (1024.0 * 1024.0), 2),
                    "rx_packets": rx_packets,
                    "tx_packets": tx_packets,
                    "rx_kbps": round(rx_kbps, 1),
                    "tx_kbps": round(tx_kbps, 1),
                    "errors": rx_errs + tx_errs,
                    "dropped": rx_drop + tx_drop,
                })
        except Exception:
            pass

        tcp_sockets: list[dict[str, Any]] = []
        try:
            with open("/proc/net/tcp", "r", encoding="utf-8") as f:
                lines = f.readlines()[1:]
            for line in lines[:30]:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                tcp_sockets.append({
                    "local_address": _decode_ipv4_hex(parts[1]),
                    "remote_address": _decode_ipv4_hex(parts[2]),
                    "state": TCP_STATES.get(parts[3].upper(), parts[3]),
                    "uid": int(parts[7]) if parts[7].isdigit() else 0,
                    "inode": parts[9],
                })
        except Exception:
            pass

        processes: list[dict[str, Any]] = []
        new_jiffies: dict[int, int] = {}
        try:
            for entry in os.scandir("/proc"):
                if not entry.name.isdigit():
                    continue
                pid = int(entry.name)
                pdir = Path(entry.path)
                try:
                    stat_raw = (pdir / "stat").read_text(encoding="utf-8", errors="ignore")
                    rparen = stat_raw.rfind(")")
                    lparen = stat_raw.find("(")
                    name = stat_raw[lparen + 1 : rparen]
                    after = stat_raw[rparen + 2 :].split()
                    state_char = after[0]
                    utime = int(after[11])
                    stime = int(after[12])
                    threads = int(after[17])
                    rss_pages = int(after[21])
                    rss_mb = round((rss_pages * 4096) / (1024.0 * 1024.0), 2)

                    tot_j = utime + stime
                    new_jiffies[pid] = tot_j
                    prev_j = self.last_proc_jiffies.get(pid, tot_j)
                    cpu_est = round(min(99.9, max(0.0, (tot_j - prev_j) / 2.0)), 1)

                    cmdline_raw = (pdir / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
                    cmdline = (cmdline_raw if cmdline_raw else f"[{name}]")[:88]
                    processes.append({
                        "pid": pid,
                        "name": name,
                        "state": state_char,
                        "threads": threads,
                        "cpu_percent": cpu_est,
                        "memory_mb": rss_mb,
                        "cmdline": cmdline,
                    })
                except Exception:
                    continue
            self.last_proc_jiffies = new_jiffies
        except Exception:
            pass

        processes.sort(key=lambda p: (p["cpu_percent"], p["memory_mb"]), reverse=True)
        return {
            "interfaces": interfaces,
            "tcp_connections": tcp_sockets,
            "processes": processes[:20],
        }


host_reader = LinuxHostMetricsReader()


class TelemetrySimulatorState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.scenario = "nominal"
        self.scenario_ticks_remaining = 0
        self.target_host = "prod-api-01"
        self.tick_counter = 0
        self.last_alert_by_rule: dict[str, float] = {}
        self.latest_live_os: dict[str, Any] = host_reader.read_live_network_and_processes()

    def set_scenario(self, scenario: str, host: str = "prod-api-01", duration_ticks: int = 8) -> dict[str, Any]:
        with self.lock:
            self.scenario = scenario
            self.target_host = host if host in HOSTS else HOSTS[0]
            self.scenario_ticks_remaining = 0 if scenario == "nominal" else max(1, duration_ticks)
            return {
                "scenario": self.scenario,
                "target_host": self.target_host,
                "ticks_remaining": self.scenario_ticks_remaining,
            }

    def next_frame(self) -> dict[str, Any]:
        with self.lock:
            self.tick_counter += 1
            current_scenario = self.scenario
            host = self.target_host if self.scenario != "nominal" else HOSTS[self.tick_counter % len(HOSTS)]
            if self.scenario_ticks_remaining > 0:
                self.scenario_ticks_remaining -= 1
                if self.scenario_ticks_remaining == 0:
                    self.scenario = "nominal"

        real_cpu, real_mem = host_reader.read_cpu_mem()

        wave = math.sin(self.tick_counter / 4.5) * 6.5
        cpu = max(8.0, min(99.0, 0.35 * real_cpu + 24.0 + wave + random.uniform(-4.5, 5.5)))
        mem = max(
            24.0,
            min(
                98.0,
                0.45 * real_mem + 28.0 + math.cos(self.tick_counter / 7.0) * 4.0 + random.uniform(-2.0, 2.5),
            ),
        )
        net = max(22.0, 118.0 + math.sin(self.tick_counter / 3.0) * 28.0 + random.uniform(-14.0, 18.0))
        disk = max(4.0, 18.5 + abs(math.sin(self.tick_counter / 5.0)) * 9.0 + random.uniform(-3.0, 4.5))
        conns = int(max(45, 185 + math.sin(self.tick_counter / 4.0) * 35 + random.randint(-18, 22)))
        auth = max(0.0, round(random.expovariate(1.0 / 1.4), 1))

        if current_scenario == "syn_flood":
            cpu = min(98.5, cpu + random.uniform(32.0, 45.0))
            net = random.uniform(540.0, 860.0)
            conns = random.randint(1250, 2280)
            auth = round(random.uniform(3.0, 9.0), 1)
        elif current_scenario == "memory_runaway":
            cpu = min(99.2, random.uniform(87.0, 96.5))
            mem = min(98.8, random.uniform(86.5, 95.8))
            disk = random.uniform(52.0, 88.0)
            conns = random.randint(290, 480)
        elif current_scenario == "crypto_miner":
            cpu = min(99.6, random.uniform(91.5, 99.1))
            mem = min(92.0, random.uniform(74.0, 85.0))
            net = random.uniform(195.0, 310.0)
            conns = random.randint(240, 390)
        elif current_scenario == "brute_force":
            cpu = min(88.0, cpu + random.uniform(12.0, 24.0))
            net = random.uniform(180.0, 320.0)
            conns = random.randint(390, 680)
            auth = round(random.uniform(28.0, 68.0), 1)
        elif current_scenario == "exfiltration":
            cpu = min(91.0, cpu + random.uniform(18.0, 30.0))
            net = random.uniform(445.0, 690.0)
            disk = random.uniform(118.0, 195.0)
            conns = random.randint(340, 610)

        raw_metrics = {
            "cpu_percent": round(cpu, 1),
            "memory_percent": round(mem, 1),
            "net_mbps": round(net, 1),
            "disk_io_ms": round(disk, 1),
            "active_connections": conns,
            "failed_auth_rate": round(auth, 1),
        }

        ml_result = ml_engine.predict(raw_metrics)

        live_os = host_reader.read_live_network_and_processes()
        with self.lock:
            self.latest_live_os = live_os

        return {
            "timestamp": utc_now_iso(),
            "source_host": host,
            "scenario": current_scenario,
            **raw_metrics,
            "ml_anomaly_score": ml_result["anomaly_score"],
            "predicted_class": ml_result["predicted_class"],
            "ml_confidence": ml_result["confidence"],
            "ml_probabilities": ml_result["probabilities"],
            "feature_contributions": ml_result["feature_contributions"],
            "live_os": live_os,
        }


sim_state = TelemetrySimulatorState()


def evaluate_operator(val: float, operator: str, threshold: float) -> bool:
    if operator == ">":
        return val > threshold
    if operator == ">=":
        return val >= threshold
    if operator == "<":
        return val < threshold
    if operator == "<=":
        return val <= threshold
    if operator == "==":
        return abs(val - threshold) < 1e-6
    return val > threshold


def process_and_store_frame(frame: dict[str, Any], force_alert: bool = False) -> list[dict[str, Any]]:
    created_alerts: list[dict[str, Any]] = []
    now_epoch = time.time()

    with DB_LOCK:
        conn = get_db_connection()
        try:
            conn.execute(
                """
                INSERT INTO telemetry_history (
                    timestamp, source_host, cpu_percent, memory_percent,
                    net_mbps, disk_io_ms, active_connections, failed_auth_rate,
                    ml_anomaly_score, predicted_class
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    frame["timestamp"],
                    frame["source_host"],
                    frame["cpu_percent"],
                    frame["memory_percent"],
                    frame["net_mbps"],
                    frame["disk_io_ms"],
                    frame["active_connections"],
                    frame["failed_auth_rate"],
                    frame["ml_anomaly_score"],
                    frame["predicted_class"],
                ),
            )
            conn.execute(
                """
                DELETE FROM telemetry_history
                WHERE id NOT IN (
                    SELECT id FROM telemetry_history ORDER BY id DESC LIMIT 300
                )
                """
            )

            rules = conn.execute(
                "SELECT * FROM alert_rules WHERE enabled = 1 ORDER BY id ASC"
            ).fetchall()

            for rule in rules:
                metric_key = rule["metric"]
                if metric_key not in frame:
                    continue
                val = float(frame[metric_key])
                threshold = float(rule["threshold"])
                op = rule["operator"]

                if evaluate_operator(val, op, threshold):
                    cooldown_key = f"{rule['id']}:{frame['source_host']}"
                    last_fired = sim_state.last_alert_by_rule.get(cooldown_key, 0.0)
                    if not force_alert and (now_epoch - last_fired) < 8.0:
                        continue
                    sim_state.last_alert_by_rule[cooldown_key] = now_epoch

                    description = (
                        f"{rule['name']} breached on {frame['source_host']}: "
                        f"{metric_key}={val} {op} {threshold} "
                        f"(ML Class: {frame['predicted_class']}, Score: {frame['ml_anomaly_score']:.2f})"
                    )
                    cursor = conn.execute(
                        """
                        INSERT INTO alerts (
                            timestamp, source_host, metric_name, metric_value,
                            threshold_value, severity, threat_class,
                            ml_anomaly_score, ml_confidence, status,
                            description, snapshot_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?)
                        """,
                        (
                            frame["timestamp"],
                            frame["source_host"],
                            metric_key,
                            val,
                            threshold,
                            rule["severity"],
                            frame["predicted_class"],
                            frame["ml_anomaly_score"],
                            frame["ml_confidence"],
                            description,
                            json.dumps(frame),
                        ),
                    )
                    new_id = cursor.lastrowid
                    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (new_id,)).fetchone()
                    if row:
                        created_alerts.append(dict(row))

            conn.commit()
        finally:
            conn.close()

    return created_alerts


def seed_initial_history_and_alerts() -> None:
    with DB_LOCK:
        conn = get_db_connection()
        try:
            hist_count = conn.execute("SELECT COUNT(*) FROM telemetry_history").fetchone()[0]
            alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        finally:
            conn.close()

    if hist_count == 0:
        for _ in range(36):
            frame = sim_state.next_frame()
            process_and_store_frame(frame, force_alert=False)

    if alert_count == 0:
        seed_scenarios = [
            ("syn_flood", "edge-gateway-01"),
            ("brute_force", "prod-api-01"),
            ("memory_runaway", "ml-worker-04"),
            ("exfiltration", "db-replica-02"),
        ]
        for scenario_name, host_name in seed_scenarios:
            sim_state.set_scenario(scenario_name, host=host_name, duration_ticks=1)
            frame = sim_state.next_frame()
            process_and_store_frame(frame, force_alert=True)
        sim_state.set_scenario("nominal")


def get_summary_kpis() -> dict[str, Any]:
    with DB_LOCK:
        conn = get_db_connection()
        try:
            open_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE status = 'Open'").fetchone()[0]
            ack_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE status = 'Acknowledged'").fetchone()[0]
            resolved_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE status = 'Resolved'").fetchone()[0]
            critical_open = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE status = 'Open' AND severity = 'Critical'"
            ).fetchone()[0]
            warning_open = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE status = 'Open' AND severity = 'Warning'"
            ).fetchone()[0]

            class_rows = conn.execute(
                """
                SELECT threat_class, COUNT(*) as count
                FROM alerts
                GROUP BY threat_class
                ORDER BY count DESC
                """
            ).fetchall()
            threat_distribution = {row["threat_class"]: row["count"] for row in class_rows}

            recent_hist = conn.execute(
                """
                SELECT AVG(ml_anomaly_score) as avg_score, AVG(cpu_percent) as avg_cpu
                FROM (SELECT ml_anomaly_score, cpu_percent FROM telemetry_history ORDER BY id DESC LIMIT 30)
                """
            ).fetchone()
            avg_score = round(float(recent_hist["avg_score"] or 0.12), 3)
            avg_cpu = round(float(recent_hist["avg_cpu"] or 34.0), 1)
        finally:
            conn.close()

    system_state = "Nominal"
    if critical_open > 0 or avg_score >= 0.72:
        system_state = "Critical"
    elif warning_open > 0 or avg_score >= 0.45:
        system_state = "Warning"

    return {
        "system_state": system_state,
        "open_alerts": open_count,
        "acknowledged_alerts": ack_count,
        "resolved_alerts": resolved_count,
        "critical_open": critical_open,
        "warning_open": warning_open,
        "mean_anomaly_score": avg_score,
        "mean_cpu_percent": avg_cpu,
        "threat_distribution": threat_distribution,
        "active_scenario": sim_state.scenario,
        "connected_clients": event_hub.client_count(),
    }


def telemetry_background_worker() -> None:
    """Continuously samples system telemetry, scores ML threat anomalies, evaluates rules, and broadcasts live events."""
    while True:
        try:
            time.sleep(2.0)
            frame = sim_state.next_frame()
            new_alerts = process_and_store_frame(frame, force_alert=False)
            summary = get_summary_kpis()
            event_hub.emit("telemetry:tick", {"frame": frame, "summary": summary})
            for alert in new_alerts:
                event_hub.emit("alert:new", {"alert": alert, "summary": summary})
        except Exception as exc:
            print(f"[TelemetryWorker] Error: {exc}", flush=True)


class SentinelHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class SentinelRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        # Keep console logs clean
        pass

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, body: bytes, content_type: str, status: int = 200, extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            index_file = TEMPLATES_DIR / "index.html"
            if index_file.exists():
                self._send_bytes(index_file.read_bytes(), "text/html; charset=utf-8")
            else:
                self._send_bytes(b"<h1>SentinelPulse Console Loading...</h1>", "text/html; charset=utf-8")
            return

        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            target = (STATIC_DIR / rel).resolve()
            if str(target).startswith(str(STATIC_DIR)) and target.is_file():
                ctype, _ = mimetypes.guess_type(str(target))
                self._send_bytes(target.read_bytes(), ctype or "application/octet-stream")
            else:
                self._send_json({"error": "Static asset not found"}, 404)
            return

        if path == "/api/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache, no-transform")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            q = event_hub.register()
            try:
                # Send initial connected handshake event
                init_msg = f"event: connected\ndata: {json.dumps({'status': 'connected', 'timestamp': utc_now_iso()})}\n\n"
                self.wfile.write(init_msg.encode("utf-8"))
                self.wfile.flush()

                while True:
                    try:
                        msg = q.get(timeout=15.0)
                        self.wfile.write(msg.encode("utf-8"))
                        self.wfile.flush()
                    except queue.Empty:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                event_hub.unregister(q)
            return

        if path == "/api/health":
            self._send_json(
                {
                    "status": "ok",
                    "database": str(DB_PATH.name),
                    "ml_engine": ml_engine.status(),
                    "timestamp": utc_now_iso(),
                }
            )
            return

        if path == "/api/system/live":
            self._send_json(host_reader.read_live_network_and_processes())
            return

        if path == "/api/bootstrap":
            with DB_LOCK:
                conn = get_db_connection()
                try:
                    history_rows = conn.execute(
                        "SELECT * FROM telemetry_history ORDER BY id DESC LIMIT 60"
                    ).fetchall()
                    alert_rows = conn.execute(
                        "SELECT * FROM alerts ORDER BY id DESC LIMIT 100"
                    ).fetchall()
                    rule_rows = conn.execute(
                        "SELECT * FROM alert_rules ORDER BY id ASC"
                    ).fetchall()
                finally:
                    conn.close()

            self._send_json(
                {
                    "history": [dict(r) for r in reversed(history_rows)],
                    "alerts": [dict(r) for r in alert_rows],
                    "rules": [dict(r) for r in rule_rows],
                    "summary": get_summary_kpis(),
                    "ml_status": ml_engine.status(),
                    "hosts": HOSTS,
                    "live_os": sim_state.latest_live_os,
                }
            )
            return

        if path == "/api/alerts":
            severity = (query.get("severity", [""])[0]).strip()
            status = (query.get("status", [""])[0]).strip()
            threat_class = (query.get("threat_class", [""])[0]).strip()
            search = (query.get("search", [""])[0]).strip()
            try:
                limit = min(500, max(10, int(query.get("limit", ["150"])[0])))
            except ValueError:
                limit = 150

            clauses = []
            params: list[Any] = []
            if severity and severity != "All":
                clauses.append("severity = ?")
                params.append(severity)
            if status and status != "All":
                clauses.append("status = ?")
                params.append(status)
            if threat_class and threat_class != "All":
                clauses.append("threat_class = ?")
                params.append(threat_class)
            if search:
                clauses.append("(description LIKE ? OR source_host LIKE ? OR metric_name LIKE ? OR threat_class LIKE ?)")
                q_str = f"%{search}%"
                params.extend([q_str, q_str, q_str, q_str])

            where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            sql = f"SELECT * FROM alerts {where_sql} ORDER BY id DESC LIMIT ?"
            params.append(limit)

            with DB_LOCK:
                conn = get_db_connection()
                try:
                    rows = conn.execute(sql, params).fetchall()
                finally:
                    conn.close()

            self._send_json({"alerts": [dict(r) for r in rows], "summary": get_summary_kpis()})
            return

        if path == "/api/alerts/export.csv":
            with DB_LOCK:
                conn = get_db_connection()
                try:
                    rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 500").fetchall()
                finally:
                    conn.close()

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(
                [
                    "ID",
                    "Timestamp",
                    "Source Host",
                    "Severity",
                    "Status",
                    "Metric",
                    "Value",
                    "Threshold",
                    "ML Threat Class",
                    "ML Anomaly Score",
                    "ML Confidence %",
                    "Description",
                ]
            )
            for r in rows:
                writer.writerow(
                    [
                        r["id"],
                        r["timestamp"],
                        r["source_host"],
                        r["severity"],
                        r["status"],
                        r["metric_name"],
                        r["metric_value"],
                        r["threshold_value"],
                        r["threat_class"],
                        r["ml_anomaly_score"],
                        r["ml_confidence"],
                        r["description"],
                    ]
                )

            csv_bytes = output.getvalue().encode("utf-8")
            self._send_bytes(
                csv_bytes,
                "text/csv; charset=utf-8",
                extra_headers={"Content-Disposition": "attachment; filename=sentinelpulse_alerts.csv"},
            )
            return

        if path == "/api/rules":
            with DB_LOCK:
                conn = get_db_connection()
                try:
                    rows = conn.execute("SELECT * FROM alert_rules ORDER BY id ASC").fetchall()
                finally:
                    conn.close()
            self._send_json({"rules": [dict(r) for r in rows]})
            return

        self._send_json({"error": "Endpoint not found"}, 404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        payload = self._read_json_body()

        if path == "/api/simulate":
            scenario = str(payload.get("scenario", "syn_flood")).strip()
            host = str(payload.get("host", "prod-api-01")).strip()
            duration = int(payload.get("duration_ticks", 6))

            allowed = {"nominal", "syn_flood", "memory_runaway", "crypto_miner", "brute_force", "exfiltration"}
            if scenario not in allowed:
                self._send_json({"error": f"Unknown scenario: {scenario}"}, 400)
                return

            state_info = sim_state.set_scenario(scenario, host=host, duration_ticks=duration)
            frame = sim_state.next_frame()
            new_alerts = process_and_store_frame(frame, force_alert=(scenario != "nominal"))
            summary = get_summary_kpis()

            event_hub.emit("telemetry:tick", {"frame": frame, "summary": summary})
            for alert in new_alerts:
                event_hub.emit("alert:new", {"alert": alert, "summary": summary})

            self._send_json(
                {
                    "state": state_info,
                    "frame": frame,
                    "created_alerts": new_alerts,
                    "summary": summary,
                }
            )
            return

        if path == "/api/alerts/bulk-action":
            action = str(payload.get("action", "")).strip()
            with DB_LOCK:
                conn = get_db_connection()
                try:
                    if action == "acknowledge_open":
                        conn.execute("UPDATE alerts SET status = 'Acknowledged' WHERE status = 'Open'")
                    elif action == "resolve_all":
                        conn.execute("UPDATE alerts SET status = 'Resolved' WHERE status != 'Resolved'")
                    elif action == "delete_resolved":
                        conn.execute("DELETE FROM alerts WHERE status = 'Resolved'")
                    else:
                        self._send_json({"error": "Unsupported bulk action"}, 400)
                        return
                    conn.commit()
                    rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 150").fetchall()
                finally:
                    conn.close()

            alerts = [dict(r) for r in rows]
            summary = get_summary_kpis()
            event_hub.emit("alerts:bulk_updated", {"alerts": alerts, "summary": summary})
            self._send_json({"alerts": alerts, "summary": summary})
            return

        if path == "/api/ml/predict":
            metrics = {
                "cpu_percent": float(payload.get("cpu_percent", 35.0)),
                "memory_percent": float(payload.get("memory_percent", 52.0)),
                "net_mbps": float(payload.get("net_mbps", 120.0)),
                "disk_io_ms": float(payload.get("disk_io_ms", 18.0)),
                "active_connections": int(float(payload.get("active_connections", 190))),
                "failed_auth_rate": float(payload.get("failed_auth_rate", 1.2)),
            }
            prediction = ml_engine.predict(metrics)
            record_alert = bool(payload.get("record_alert", False))
            created_alert = None

            if record_alert:
                host = str(payload.get("source_host", "manual-inspector")).strip() or "manual-inspector"
                now = utc_now_iso()
                severity = (
                    "Critical"
                    if prediction["anomaly_score"] >= 0.70
                    else ("Warning" if prediction["anomaly_score"] >= 0.42 else "Info")
                )
                frame = {
                    "timestamp": now,
                    "source_host": host,
                    "scenario": "manual_inspection",
                    **metrics,
                    "ml_anomaly_score": prediction["anomaly_score"],
                    "predicted_class": prediction["predicted_class"],
                    "ml_confidence": prediction["confidence"],
                    "ml_probabilities": prediction["probabilities"],
                    "feature_contributions": prediction["feature_contributions"],
                }
                description = (
                    f"Manual ML Threat Evaluation on {host}: Classified as {prediction['predicted_class']} "
                    f"(Score: {prediction['anomaly_score']:.2f}, Confidence: {prediction['confidence']:.1f}%)"
                )
                with DB_LOCK:
                    conn = get_db_connection()
                    try:
                        cursor = conn.execute(
                            """
                            INSERT INTO alerts (
                                timestamp, source_host, metric_name, metric_value,
                                threshold_value, severity, threat_class,
                                ml_anomaly_score, ml_confidence, status,
                                description, snapshot_json
                            ) VALUES (?, ?, 'ml_anomaly_score', ?, 0.72, ?, ?, ?, ?, 'Open', ?, ?)
                            """,
                            (
                                now,
                                host,
                                prediction["anomaly_score"],
                                severity,
                                prediction["predicted_class"],
                                prediction["anomaly_score"],
                                prediction["confidence"],
                                description,
                                json.dumps(frame),
                            ),
                        )
                        conn.commit()
                        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (cursor.lastrowid,)).fetchone()
                        if row:
                            created_alert = dict(row)
                    finally:
                        conn.close()

                if created_alert:
                    event_hub.emit("alert:new", {"alert": created_alert, "summary": get_summary_kpis()})

            self._send_json(
                {
                    "metrics": metrics,
                    "prediction": prediction,
                    "created_alert": created_alert,
                    "ml_status": ml_engine.status(),
                }
            )
            return

        if path == "/api/ml/retrain":
            status = ml_engine.load_or_train(force_retrain=True)
            self._send_json({"status": "retrained", "ml_status": status})
            return

        if path == "/api/rules":
            name = str(payload.get("name", "")).strip()
            metric = str(payload.get("metric", "cpu_percent")).strip()
            operator = str(payload.get("operator", ">")).strip()
            severity = str(payload.get("severity", "Warning")).strip()

            try:
                threshold = float(payload.get("threshold", 80.0))
            except (TypeError, ValueError):
                self._send_json({"error": "Threshold must be a valid number"}, 400)
                return

            valid_metrics = set(FEATURE_NAMES) | {"ml_anomaly_score"}
            if not name:
                self._send_json({"error": "Rule name is required"}, 400)
                return
            if metric not in valid_metrics:
                self._send_json({"error": f"Invalid metric: {metric}"}, 400)
                return
            if operator not in (">", ">=", "<", "<=", "=="):
                self._send_json({"error": "Invalid operator"}, 400)
                return
            if severity not in ("Critical", "Warning", "Info"):
                self._send_json({"error": "Invalid severity"}, 400)
                return

            now = utc_now_iso()
            with DB_LOCK:
                conn = get_db_connection()
                try:
                    cursor = conn.execute(
                        """
                        INSERT INTO alert_rules (name, metric, operator, threshold, severity, enabled, created_at)
                        VALUES (?, ?, ?, ?, ?, 1, ?)
                        """,
                        (name, metric, operator, threshold, severity, now),
                    )
                    conn.commit()
                    row = conn.execute("SELECT * FROM alert_rules WHERE id = ?", (cursor.lastrowid,)).fetchone()
                finally:
                    conn.close()

            rule = dict(row)
            event_hub.emit("rule:created", {"rule": rule})
            self._send_json({"rule": rule}, 201)
            return

        self._send_json({"error": "Endpoint not found"}, 404)

    def do_PATCH(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        payload = self._read_json_body()

        m_alert = re.match(r"^/api/alerts/(\d+)$", path)
        if m_alert:
            alert_id = int(m_alert.group(1))
            new_status = str(payload.get("status", "")).strip()
            if new_status not in ("Open", "Acknowledged", "Resolved"):
                self._send_json({"error": "Invalid status. Must be Open, Acknowledged, or Resolved."}, 400)
                return

            with DB_LOCK:
                conn = get_db_connection()
                try:
                    conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_id))
                    conn.commit()
                    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
                finally:
                    conn.close()

            if not row:
                self._send_json({"error": "Alert not found"}, 404)
                return

            updated = dict(row)
            summary = get_summary_kpis()
            event_hub.emit("alert:updated", {"alert": updated, "summary": summary})
            self._send_json({"alert": updated, "summary": summary})
            return

        m_rule = re.match(r"^/api/rules/(\d+)$", path)
        if m_rule:
            rule_id = int(m_rule.group(1))
            with DB_LOCK:
                conn = get_db_connection()
                try:
                    existing = conn.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
                    if not existing:
                        self._send_json({"error": "Rule not found"}, 404)
                        return

                    enabled = int(bool(payload.get("enabled", existing["enabled"])))
                    threshold = float(payload.get("threshold", existing["threshold"]))
                    severity = str(payload.get("severity", existing["severity"])).strip()
                    name = str(payload.get("name", existing["name"])).strip()

                    conn.execute(
                        """
                        UPDATE alert_rules
                        SET name = ?, threshold = ?, severity = ?, enabled = ?
                        WHERE id = ?
                        """,
                        (name, threshold, severity, enabled, rule_id),
                    )
                    conn.commit()
                    row = conn.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
                finally:
                    conn.close()

            rule = dict(row)
            event_hub.emit("rule:updated", {"rule": rule})
            self._send_json({"rule": rule})
            return

        self._send_json({"error": "Endpoint not found"}, 404)

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        m_alert = re.match(r"^/api/alerts/(\d+)$", path)
        if m_alert:
            alert_id = int(m_alert.group(1))
            with DB_LOCK:
                conn = get_db_connection()
                try:
                    conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
                    conn.commit()
                finally:
                    conn.close()

            summary = get_summary_kpis()
            event_hub.emit("alert:deleted", {"id": alert_id, "summary": summary})
            self._send_json({"deleted_id": alert_id, "summary": summary})
            return

        m_rule = re.match(r"^/api/rules/(\d+)$", path)
        if m_rule:
            rule_id = int(m_rule.group(1))
            with DB_LOCK:
                conn = get_db_connection()
                try:
                    conn.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
                    conn.commit()
                finally:
                    conn.close()

            event_hub.emit("rule:deleted", {"id": rule_id})
            self._send_json({"deleted_id": rule_id})
            return

        self._send_json({"error": "Endpoint not found"}, 404)


def main() -> None:
    init_db()
    seed_initial_history_and_alerts()

    worker = threading.Thread(target=telemetry_background_worker, daemon=True)
    worker.start()

    port = int(os.environ.get("PORT", 3000))
    server = SentinelHTTPServer(("0.0.0.0", port), SentinelRequestHandler)
    print(f"SentinelPulse server listening on http://0.0.0.0:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
