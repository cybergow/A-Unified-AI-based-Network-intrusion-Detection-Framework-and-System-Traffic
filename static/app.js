(() => {
  "use strict";

  const state = {
    activeView: "console",
    streamPaused: false,
    selectedHostFilter: "ALL",
    history: [],
    alerts: [],
    rules: [],
    summary: {
      system_state: "Nominal",
      open_alerts: 0,
      acknowledged_alerts: 0,
      resolved_alerts: 0,
      critical_open: 0,
      warning_open: 0,
      mean_anomaly_score: 0.1,
      mean_cpu_percent: 32.0,
      threat_distribution: {},
      active_scenario: "nominal",
    },
    mlStatus: null,
    activeSeries: new Set(["cpu_percent", "memory_percent", "ml_anomaly_pct"]),
    feedFilters: {
      search: "",
      severity: "All",
      status: "All",
      threatClass: "All",
    },
    inspectedAlertId: null,
    latestFrame: null,
  };

  function showToast(message) {
    const container = document.getElementById("toast-container");
    if (!container) return;
    const item = document.createElement("div");
    item.className = "toast-msg";
    item.textContent = message;
    container.appendChild(item);
    setTimeout(() => {
      item.remove();
    }, 3200);
  }

  function formatUtcShort(isoStr) {
    if (!isoStr) return "—";
    return isoStr.replace("T", " ").replace("Z", " UTC");
  }

  function severityClass(sev) {
    if (sev === "Critical") return "state-critical-text";
    if (sev === "Warning") return "state-warning-text";
    return "state-nominal";
  }

  function statusClass(st) {
    if (st === "Open") return "state-critical-text";
    if (st === "Acknowledged") return "state-warning-text";
    return "state-nominal";
  }

  function switchView(viewName) {
    state.activeView = viewName;
    document.querySelectorAll(".nav-link").forEach((link) => {
      link.classList.toggle("active", link.dataset.nav === viewName);
    });
    document.querySelectorAll(".workspace-view").forEach((sec) => {
      sec.classList.toggle("active", sec.id === `view-${viewName}`);
    });
    if (viewName === "console") {
      drawTelemetryChart();
    }
  }

  function updateKPIStrip() {
    const s = state.summary;
    const healthEl = document.getElementById("kpi-health-state");
    if (healthEl) {
      healthEl.textContent = s.system_state || "Nominal";
      healthEl.className = `kpi-primary-value ${
        s.system_state === "Critical"
          ? "state-critical"
          : s.system_state === "Warning"
          ? "state-warning"
          : "state-nominal"
      }`;
    }

    const regimeEl = document.getElementById("kpi-active-regime");
    if (regimeEl) {
      const scenarioLabel = (s.active_scenario || "nominal").replace(/_/g, " ");
      regimeEl.textContent = `Regime: ${scenarioLabel}`;
    }

    const openEl = document.getElementById("kpi-open-alerts");
    if (openEl) openEl.textContent = String(s.open_alerts ?? 0);

    const critEl = document.getElementById("kpi-critical-alerts");
    if (critEl) critEl.textContent = String(s.critical_open ?? 0);

    const warnEl = document.getElementById("kpi-warning-alerts");
    if (warnEl) warnEl.textContent = String(s.warning_open ?? 0);

    const ackResEl = document.getElementById("kpi-ack-resolved-summary");
    if (ackResEl) {
      ackResEl.textContent = `${s.acknowledged_alerts ?? 0} Acknowledged · ${
        s.resolved_alerts ?? 0
      } Resolved`;
    }

    const latest = state.latestFrame || state.history[state.history.length - 1];
    if (latest) {
      const scoreEl = document.getElementById("kpi-anomaly-score");
      if (scoreEl) {
        scoreEl.textContent = Number(latest.ml_anomaly_score || 0).toFixed(3);
      }
      const predEl = document.getElementById("kpi-predicted-class");
      if (predEl) {
        predEl.textContent = latest.predicted_class || "Benign";
      }
      const confEl = document.getElementById("kpi-ml-confidence");
      if (confEl) {
        const conf = latest.ml_confidence ?? 95.0;
        confEl.textContent = `Confidence: ${Number(conf).toFixed(1)}% · Mean: ${Number(
          s.mean_anomaly_score || 0.1
        ).toFixed(3)}`;
      }
      const cpuEl = document.getElementById("kpi-cpu-live");
      if (cpuEl) {
        cpuEl.textContent = `${Number(latest.cpu_percent || 0).toFixed(1)}%`;
      }
      const hostEl = document.getElementById("kpi-live-host");
      if (hostEl) {
        hostEl.textContent = latest.source_host || "prod-api-01";
      }
      const tupleEl = document.getElementById("kpi-resource-tuple");
      if (tupleEl) {
        tupleEl.textContent = `Mem ${Number(latest.memory_percent || 0).toFixed(
          1
        )}% · Net ${Number(latest.net_mbps || 0).toFixed(0)} Mbps · Disk ${Number(
          latest.disk_io_ms || 0
        ).toFixed(0)} ms`;
      }
      const tickTimeEl = document.getElementById("last-tick-timestamp");
      if (tickTimeEl) {
        tickTimeEl.textContent = formatUtcShort(latest.timestamp);
      }
    }

    document.querySelectorAll(".btn-scenario").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.scenario === (s.active_scenario || "nominal"));
    });
  }

  function getFilteredHistory() {
    if (state.selectedHostFilter === "ALL") {
      return state.history.slice(-60);
    }
    return state.history
      .filter((f) => f.source_host === state.selectedHostFilter)
      .slice(-60);
  }

  function drawTelemetryChart() {
    const canvas = document.getElementById("telemetry-chart-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const rect = canvas.parentElement.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const width = Math.max(320, Math.floor(rect.width));
    const height = Math.max(220, Math.floor(rect.height));

    if (canvas.width !== width * dpr || canvas.height !== height * dpr) {
      canvas.width = width * dpr;
      canvas.height = height * dpr;
    }
    ctx.save();
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);

    const padLeft = 42;
    const padRight = 16;
    const padTop = 16;
    const padBottom = 26;
    const plotW = width - padLeft - padRight;
    const plotH = height - padTop - padBottom;

    // Horizontal grid lines (0%, 25%, 50%, 75%, 100%)
    ctx.strokeStyle = "#1e293b";
    ctx.lineWidth = 1;
    ctx.fillStyle = "#94a3b8";
    ctx.font = "11px 'JetBrains Mono', monospace";
    ctx.textAlign = "right";

    for (let i = 0; i <= 4; i++) {
      const pct = 100 - i * 25;
      const y = padTop + (i / 4) * plotH;
      ctx.beginPath();
      ctx.moveTo(padLeft, y);
      ctx.lineTo(padLeft + plotW, y);
      ctx.stroke();
      ctx.fillText(`${pct}%`, padLeft - 6, y + 4);
    }

    const frames = getFilteredHistory();
    if (frames.length < 2) {
      ctx.fillStyle = "#94a3b8";
      ctx.textAlign = "center";
      ctx.fillText("Collecting live node telemetry...", padLeft + plotW / 2, padTop + plotH / 2);
      ctx.restore();
      return;
    }

    const seriesDefs = [
      {
        key: "cpu_percent",
        color: "#3b82f6",
        getter: (f) => Math.min(100, Math.max(0, Number(f.cpu_percent || 0))),
      },
      {
        key: "memory_percent",
        color: "#10b981",
        getter: (f) => Math.min(100, Math.max(0, Number(f.memory_percent || 0))),
      },
      {
        key: "ml_anomaly_pct",
        color: "#ef4444",
        getter: (f) => Math.min(100, Math.max(0, Number(f.ml_anomaly_score || 0) * 100)),
      },
      {
        key: "net_norm",
        color: "#f59e0b",
        getter: (f) => Math.min(100, Math.max(0, Number(f.net_mbps || 0) / 10)),
      },
    ];

    seriesDefs.forEach((s) => {
      if (!state.activeSeries.has(s.key)) return;
      ctx.strokeStyle = s.color;
      ctx.lineWidth = 2;
      ctx.beginPath();
      frames.forEach((frame, idx) => {
        const x = padLeft + (idx / Math.max(1, frames.length - 1)) * plotW;
        const val = s.getter(frame);
        const y = padTop + ((100 - val) / 100) * plotH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    });

    // Time axis labels
    ctx.fillStyle = "#94a3b8";
    ctx.textAlign = "left";
    const firstTs = (frames[0].timestamp || "").slice(11, 19);
    const lastTs = (frames[frames.length - 1].timestamp || "").slice(11, 19);
    ctx.fillText(firstTs, padLeft, height - 6);
    ctx.textAlign = "right";
    ctx.fillText(lastTs, padLeft + plotW, height - 6);

    ctx.restore();
  }

  function renderDistributionAndFeatureBars() {
    const featContainer = document.getElementById("live-feature-bars");
    const distContainer = document.getElementById("threat-distribution-bars");
    const latest = state.latestFrame || state.history[state.history.length - 1] || {};

    if (featContainer) {
      const contribs = latest.feature_contributions || {
        cpu_percent: Math.min(1, Math.max(0, ((latest.cpu_percent || 32) - 35) / 60)),
        memory_percent: Math.min(1, Math.max(0, ((latest.memory_percent || 50) - 50) / 45)),
        net_mbps: Math.min(1, Math.max(0, ((latest.net_mbps || 115) - 130) / 550)),
        disk_io_ms: Math.min(1, Math.max(0, ((latest.disk_io_ms || 18) - 22) / 130)),
        failed_auth_rate: Math.min(1, Math.max(0, ((latest.failed_auth_rate || 1) - 3) / 40)),
      };

      const labels = [
        ["cpu_percent", "CPU Load Deviation"],
        ["memory_percent", "Memory Pressure"],
        ["net_mbps", "Network Outbound Surge"],
        ["disk_io_ms", "Disk I/O Latency"],
        ["failed_auth_rate", "Auth Failure Spike"],
      ];

      featContainer.innerHTML = labels
        .map(([key, title]) => {
          const pct = Math.round(Number(contribs[key] || 0) * 100);
          const fillTone = pct >= 70 ? "fill-critical" : pct >= 40 ? "fill-warning" : "";
          return `
            <div class="bar-row">
              <div class="bar-label-line">
                <span>${title}</span>
                <span class="mono-num">${pct}%</span>
              </div>
              <div class="bar-track">
                <div class="bar-fill ${fillTone}" style="width: ${pct}%"></div>
              </div>
            </div>
          `;
        })
        .join("");
    }

    if (distContainer) {
      const dist = state.summary.threat_distribution || {};
      const allClasses = [
        "SYN Flood / Network Surge",
        "Resource Exhaustion",
        "Brute-Force Auth Intrusion",
        "Disk I/O / Exfiltration Anomaly",
        "Benign",
      ];
      const total = Object.values(dist).reduce((a, b) => a + Number(b || 0), 0) || 1;

      distContainer.innerHTML = allClasses
        .map((cls) => {
          const count = Number(dist[cls] || 0);
          const pct = Math.round((count / total) * 100);
          return `
            <div class="bar-row">
              <div class="bar-label-line">
                <span>${cls}</span>
                <span class="mono-num">${count} alerts (${pct}%)</span>
              </div>
              <div class="bar-track">
                <div class="bar-fill" style="width: ${pct}%"></div>
              </div>
            </div>
          `;
        })
        .join("");
    }
  }

  function getFilteredAlerts() {
    return state.alerts.filter((a) => {
      if (state.selectedHostFilter !== "ALL" && a.source_host !== state.selectedHostFilter) {
        return false;
      }
      const f = state.feedFilters;
      if (f.severity !== "All" && a.severity !== f.severity) return false;
      if (f.status !== "All" && a.status !== f.status) return false;
      if (f.threatClass !== "All" && a.threat_class !== f.threatClass) return false;
      if (f.search) {
        const q = f.search.toLowerCase();
        const hay = `${a.source_host} ${a.metric_name} ${a.threat_class} ${a.description}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }

  function renderAlertsTables() {
    const consoleTbody = document.getElementById("console-alerts-tbody");
    const feedTbody = document.getElementById("feed-alerts-tbody");

    const consoleList = state.alerts
      .filter((a) => state.selectedHostFilter === "ALL" || a.source_host === state.selectedHostFilter)
      .slice(0, 10);

    if (consoleTbody) {
      if (consoleList.length === 0) {
        consoleTbody.innerHTML = `<tr><td colspan="9" class="empty-state-cell">No alerts recorded for the selected node scope.</td></tr>`;
      } else {
        consoleTbody.innerHTML = consoleList
          .map(
            (a) => `
          <tr data-alert-id="${a.id}">
            <td class="mono-num">#${a.id}</td>
            <td class="mono-meta">${formatUtcShort(a.timestamp)}</td>
            <td class="mono-meta">${a.source_host}</td>
            <td class="${severityClass(a.severity)}">${a.severity}</td>
            <td>${a.threat_class}</td>
            <td class="num-col">${a.metric_name}: ${Number(a.metric_value).toFixed(1)} / ${Number(
              a.threshold_value
            ).toFixed(1)}</td>
            <td class="num-col">${Number(a.ml_anomaly_score).toFixed(3)}</td>
            <td class="${statusClass(a.status)}">${a.status}</td>
            <td class="action-col">
              ${
                a.status === "Open"
                  ? `<button type="button" class="btn-secondary btn-sm" data-quick-status="Acknowledged" data-id="${a.id}">Acknowledge</button>`
                  : ""
              }
              ${
                a.status !== "Resolved"
                  ? `<button type="button" class="btn-secondary btn-sm" data-quick-status="Resolved" data-id="${a.id}">Resolve</button>`
                  : `<span class="mono-meta">Closed</span>`
              }
            </td>
          </tr>
        `
          )
          .join("");
      }
    }

    if (feedTbody) {
      const filtered = getFilteredAlerts();
      if (filtered.length === 0) {
        feedTbody.innerHTML = `<tr><td colspan="9" class="empty-state-cell">No alerts match the active filter criteria.</td></tr>`;
      } else {
        feedTbody.innerHTML = filtered
          .map(
            (a) => `
          <tr data-alert-id="${a.id}">
            <td class="mono-num">#${a.id}</td>
            <td class="mono-meta">${formatUtcShort(a.timestamp)}</td>
            <td class="mono-meta">${a.source_host}</td>
            <td class="${severityClass(a.severity)}">${a.severity}</td>
            <td>${a.threat_class}</td>
            <td>${a.description}</td>
            <td class="num-col">${Number(a.ml_anomaly_score).toFixed(3)}</td>
            <td class="${statusClass(a.status)}">${a.status}</td>
            <td class="action-col">
              ${
                a.status === "Open"
                  ? `<button type="button" class="btn-secondary btn-sm" data-quick-status="Acknowledged" data-id="${a.id}">Ack</button>`
                  : ""
              }
              ${
                a.status !== "Resolved"
                  ? `<button type="button" class="btn-secondary btn-sm" data-quick-status="Resolved" data-id="${a.id}">Resolve</button>`
                  : ""
              }
              <button type="button" class="btn-danger btn-sm" data-delete-alert="${a.id}">Delete</button>
            </td>
          </tr>
        `
          )
          .join("");
      }
    }
  }

  function renderRulesTable() {
    const tbody = document.getElementById("rules-tbody");
    if (!tbody) return;

    if (state.rules.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-state-cell">No custom threshold rules configured.</td></tr>`;
      return;
    }

    tbody.innerHTML = state.rules
      .map(
        (r) => `
      <tr>
        <td class="mono-num">#${r.id}</td>
        <td>${r.name}</td>
        <td class="mono-meta">${r.metric}</td>
        <td class="num-col">${r.operator} ${Number(r.threshold)}</td>
        <td class="${severityClass(r.severity)}">${r.severity}</td>
        <td class="${r.enabled ? "state-nominal" : "mono-meta"}">${
          r.enabled ? "Enabled" : "Disabled"
        }</td>
        <td class="action-col">
          <button type="button" class="btn-secondary btn-sm" data-toggle-rule="${
            r.id
          }" data-enabled="${r.enabled ? "1" : "0"}">
            ${r.enabled ? "Disable" : "Enable"}
          </button>
          <button type="button" class="btn-danger btn-sm" data-delete-rule="${r.id}">Delete</button>
        </td>
      </tr>
    `
      )
      .join("");
  }

  function openAlertDrawer(alertId) {
    const alertObj = state.alerts.find((a) => Number(a.id) === Number(alertId));
    if (!alertObj) return;
    state.inspectedAlertId = alertObj.id;

    document.getElementById("drawer-alert-id").textContent = `Alert #${alertObj.id} · ${alertObj.severity} · ${alertObj.status}`;
    document.getElementById("drawer-alert-title").textContent = alertObj.threat_class;
    document.getElementById("drawer-meta-line").textContent = `${alertObj.source_host} · ${formatUtcShort(
      alertObj.timestamp
    )} · Confidence ${Number(alertObj.ml_confidence).toFixed(1)}%`;
    document.getElementById("drawer-description").textContent = alertObj.description;

    let snap = {};
    try {
      snap = JSON.parse(alertObj.snapshot_json || "{}");
    } catch {
      snap = {};
    }

    const kvPairs = [
      ["Host Node", snap.source_host || alertObj.source_host],
      ["Triggered Metric", `${alertObj.metric_name} = ${alertObj.metric_value}`],
      ["Rule Threshold", String(alertObj.threshold_value)],
      ["ML Anomaly Score", Number(alertObj.ml_anomaly_score).toFixed(3)],
      ["CPU Utilization", `${snap.cpu_percent ?? "—"}%`],
      ["Memory Pressure", `${snap.memory_percent ?? "—"}%`],
      ["Network Throughput", `${snap.net_mbps ?? "—"} Mbps`],
      ["Disk I/O Latency", `${snap.disk_io_ms ?? "—"} ms`],
      ["Active Connections", String(snap.active_connections ?? "—")],
      ["Failed Auth Rate", `${snap.failed_auth_rate ?? "—"} /min`],
    ];

    document.getElementById("drawer-snapshot-grid").innerHTML = kvPairs
      .map(
        ([k, v]) => `
        <div class="kv-item">
          <span class="kv-key">${k}</span>
          <span class="kv-val">${v}</span>
        </div>
      `
      )
      .join("");

    document.getElementById("drawer-raw-json").textContent = JSON.stringify(snap, null, 2);

    const drawer = document.getElementById("alert-drawer");
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
  }

  function closeAlertDrawer() {
    const drawer = document.getElementById("alert-drawer");
    if (!drawer) return;
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
    state.inspectedAlertId = null;
  }

  async function updateAlertStatus(alertId, status) {
    try {
      const res = await fetch(`/api/alerts/${alertId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      if (!res.ok) throw new Error("Failed to update status");
      const data = await res.json();
      upsertAlertInState(data.alert);
      if (data.summary) state.summary = data.summary;
      updateKPIStrip();
      renderAlertsTables();
      if (state.inspectedAlertId === Number(alertId)) {
        openAlertDrawer(alertId);
      }
      showToast(`Alert #${alertId} marked ${status}`);
    } catch (err) {
      showToast(err.message);
    }
  }

  async function deleteAlertById(alertId) {
    try {
      const res = await fetch(`/api/alerts/${alertId}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to delete alert");
      const data = await res.json();
      state.alerts = state.alerts.filter((a) => Number(a.id) !== Number(alertId));
      if (data.summary) state.summary = data.summary;
      if (state.inspectedAlertId === Number(alertId)) {
        closeAlertDrawer();
      }
      updateKPIStrip();
      renderAlertsTables();
      showToast(`Alert #${alertId} removed from alerts.db`);
    } catch (err) {
      showToast(err.message);
    }
  }

  function upsertAlertInState(alertObj) {
    if (!alertObj || !alertObj.id) return;
    const idx = state.alerts.findIndex((a) => Number(a.id) === Number(alertObj.id));
    if (idx >= 0) {
      state.alerts[idx] = alertObj;
    } else {
      state.alerts.unshift(alertObj);
      if (state.alerts.length > 200) state.alerts.pop();
    }
  }

  async function triggerScenario(scenarioName) {
    const hostSelect = document.getElementById("scenario-target-host");
    const host = hostSelect ? hostSelect.value : "prod-api-01";
    try {
      const res = await fetch("/api/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario: scenarioName,
          host,
          duration_ticks: 6,
        }),
      });
      if (!res.ok) throw new Error("Scenario injection failed");
      const data = await res.json();
      if (data.frame) {
        state.latestFrame = data.frame;
        state.history.push(data.frame);
        if (state.history.length > 60) state.history.shift();
      }
      if (Array.isArray(data.created_alerts)) {
        data.created_alerts.forEach((a) => upsertAlertInState(a));
      }
      if (data.summary) state.summary = data.summary;
      updateKPIStrip();
      drawTelemetryChart();
      renderDistributionAndFeatureBars();
      renderAlertsTables();
      showToast(
        scenarioName === "nominal"
          ? "Telemetry returned to nominal baseline"
          : `Injected ${scenarioName.replace(/_/g, " ")} on ${host}`
      );
    } catch (err) {
      showToast(err.message);
    }
  }

  async function evaluateMLSandbox(recordAlert = false) {
    const payload = {
      cpu_percent: parseFloat(document.getElementById("ml-cpu").value),
      memory_percent: parseFloat(document.getElementById("ml-mem").value),
      net_mbps: parseFloat(document.getElementById("ml-net").value),
      disk_io_ms: parseFloat(document.getElementById("ml-disk").value),
      active_connections: parseInt(document.getElementById("ml-conns").value, 10),
      failed_auth_rate: parseFloat(document.getElementById("ml-auth").value),
      record_alert: recordAlert,
      source_host: document.getElementById("scenario-target-host")?.value || "prod-api-01",
    };

    try {
      const res = await fetch("/api/ml/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error("ML prediction failed");
      const data = await res.json();
      const pred = data.prediction;

      document.getElementById("ml-out-class").textContent = pred.predicted_class;
      const scoreEl = document.getElementById("ml-out-score");
      scoreEl.textContent = Number(pred.anomaly_score).toFixed(3);
      scoreEl.className = `ml-big-num mono-num ${
        pred.anomaly_score >= 0.7
          ? "state-critical"
          : pred.anomaly_score >= 0.42
          ? "state-warning"
          : "state-nominal"
      }`;
      document.getElementById("ml-out-conf").textContent = `${Number(pred.confidence).toFixed(1)}%`;

      const probContainer = document.getElementById("ml-prob-bars");
      if (probContainer && pred.probabilities) {
        probContainer.innerHTML = Object.entries(pred.probabilities)
          .sort((a, b) => b[1] - a[1])
          .map(([cls, pct]) => {
            const p = Number(pct).toFixed(1);
            return `
              <div class="bar-row">
                <div class="bar-label-line">
                  <span>${cls}</span>
                  <span class="mono-num">${p}%</span>
                </div>
                <div class="bar-track">
                  <div class="bar-fill" style="width: ${Math.min(100, Number(pct))}%"></div>
                </div>
              </div>
            `;
          })
          .join("");
      }

      const contribContainer = document.getElementById("ml-contrib-bars");
      if (contribContainer && pred.feature_contributions) {
        contribContainer.innerHTML = Object.entries(pred.feature_contributions)
          .map(([feat, val]) => {
            const pct = Math.round(Number(val) * 100);
            const tone = pct >= 70 ? "fill-critical" : pct >= 40 ? "fill-warning" : "";
            return `
              <div class="bar-row">
                <div class="bar-label-line">
                  <span class="mono-meta">${feat}</span>
                  <span class="mono-num">${pct}%</span>
                </div>
                <div class="bar-track">
                  <div class="bar-fill ${tone}" style="width: ${pct}%"></div>
                </div>
              </div>
            `;
          })
          .join("");
      }

      if (data.created_alert) {
        upsertAlertInState(data.created_alert);
        renderAlertsTables();
        showToast(`Logged Alert #${data.created_alert.id} (${pred.predicted_class}) to alerts.db`);
      }
    } catch (err) {
      showToast(err.message);
    }
  }

  function applyMLPreset(preset) {
    const presets = {
      benign: { cpu: 31, mem: 49, net: 112, disk: 16, conns: 175, auth: 1.0 },
      syn_flood: { cpu: 76, mem: 64, net: 720, disk: 28, conns: 1850, auth: 4.5 },
      exhaustion: { cpu: 95, mem: 92, net: 180, disk: 58, conns: 340, auth: 2.0 },
      brute_force: { cpu: 52, mem: 58, net: 210, disk: 22, conns: 490, auth: 54.0 },
      exfiltration: { cpu: 68, mem: 74, net: 540, disk: 175, conns: 440, auth: 3.0 },
    };

    let p = presets[preset];
    if (preset === "live" && state.latestFrame) {
      p = {
        cpu: state.latestFrame.cpu_percent,
        mem: state.latestFrame.memory_percent,
        net: state.latestFrame.net_mbps,
        disk: state.latestFrame.disk_io_ms,
        conns: state.latestFrame.active_connections,
        auth: state.latestFrame.failed_auth_rate,
      };
    }
    if (!p) p = presets.benign;

    document.getElementById("ml-cpu").value = p.cpu;
    document.getElementById("ml-mem").value = p.mem;
    document.getElementById("ml-net").value = p.net;
    document.getElementById("ml-disk").value = p.disk;
    document.getElementById("ml-conns").value = p.conns;
    document.getElementById("ml-auth").value = p.auth;
    syncMLSliderLabels();
    evaluateMLSandbox(false);
  }

  function syncMLSliderLabels() {
    document.getElementById("ml-cpu-val").textContent = `${Number(
      document.getElementById("ml-cpu").value
    ).toFixed(1)}%`;
    document.getElementById("ml-mem-val").textContent = `${Number(
      document.getElementById("ml-mem").value
    ).toFixed(1)}%`;
    document.getElementById("ml-net-val").textContent = `${Number(
      document.getElementById("ml-net").value
    ).toFixed(0)} Mbps`;
    document.getElementById("ml-disk-val").textContent = `${Number(
      document.getElementById("ml-disk").value
    ).toFixed(0)} ms`;
    document.getElementById("ml-conns-val").textContent = String(
      document.getElementById("ml-conns").value
    );
    document.getElementById("ml-auth-val").textContent = `${Number(
      document.getElementById("ml-auth").value
    ).toFixed(1)} /min`;
  }

  function renderLiveOSTables(liveOsData) {
    if (!liveOsData) return;
    state.liveOs = liveOsData;

    const procTbody = document.getElementById("live-processes-tbody");
    if (procTbody && Array.isArray(liveOsData.processes)) {
      procTbody.innerHTML = liveOsData.processes
        .map(
          (p) => `
        <tr>
          <td class="mono-num">${p.pid}</td>
          <td class="mono-meta">${p.name}</td>
          <td class="mono-meta">${p.state}</td>
          <td class="num-col">${p.threads}</td>
          <td class="num-col">${Number(p.cpu_percent).toFixed(1)}%</td>
          <td class="num-col">${Number(p.memory_mb).toFixed(2)} MB</td>
          <td class="mono-meta">${p.cmdline}</td>
        </tr>
      `
        )
        .join("");
    }

    const netTbody = document.getElementById("live-net-interfaces-tbody");
    if (netTbody && Array.isArray(liveOsData.interfaces)) {
      netTbody.innerHTML = liveOsData.interfaces
        .map(
          (iface) => `
        <tr>
          <td class="mono-meta">${iface.interface}</td>
          <td class="num-col">${Number(iface.rx_mb).toFixed(2)} MB (${iface.rx_packets} pkts)</td>
          <td class="num-col">${Number(iface.tx_mb).toFixed(2)} MB (${iface.tx_packets} pkts)</td>
          <td class="num-col">${Number(iface.rx_kbps).toFixed(1)} kbps</td>
          <td class="num-col">${Number(iface.tx_kbps).toFixed(1)} kbps</td>
        </tr>
      `
        )
        .join("");
    }

    const tcpTbody = document.getElementById("live-tcp-sockets-tbody");
    if (tcpTbody && Array.isArray(liveOsData.tcp_connections)) {
      tcpTbody.innerHTML = liveOsData.tcp_connections
        .slice(0, 12)
        .map(
          (sock) => `
        <tr>
          <td class="mono-meta">${sock.local_address}</td>
          <td class="mono-meta">${sock.remote_address}</td>
          <td class="${sock.state === "ESTABLISHED" ? "state-nominal" : "mono-meta"}">${
            sock.state
          }</td>
          <td class="num-col">${sock.inode}</td>
        </tr>
      `
        )
        .join("");
    }
  }

  function connectRealtimeStream() {
    const connText = document.getElementById("stream-connection-text");
    const es = new EventSource("/api/stream");

    es.addEventListener("connected", () => {
      if (connText && !state.streamPaused) {
        connText.textContent = "Live Stream Connected";
        connText.classList.remove("paused");
      }
    });

    es.addEventListener("telemetry:tick", (ev) => {
      if (state.streamPaused) return;
      try {
        const data = JSON.parse(ev.data);
        if (data.frame) {
          state.latestFrame = data.frame;
          state.history.push(data.frame);
          if (state.history.length > 60) state.history.shift();
          if (data.frame.live_os) {
            renderLiveOSTables(data.frame.live_os);
          }
        }
        if (data.summary) state.summary = data.summary;
        updateKPIStrip();
        if (state.activeView === "console") {
          drawTelemetryChart();
          renderDistributionAndFeatureBars();
        }
      } catch {
        // ignore malformed frame
      }
    });

    es.addEventListener("alert:new", (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data.alert) upsertAlertInState(data.alert);
        if (data.summary) state.summary = data.summary;
        updateKPIStrip();
        renderAlertsTables();
        renderDistributionAndFeatureBars();
      } catch {
        // ignore
      }
    });

    es.addEventListener("alert:updated", (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data.alert) upsertAlertInState(data.alert);
        if (data.summary) state.summary = data.summary;
        updateKPIStrip();
        renderAlertsTables();
      } catch {
        // ignore
      }
    });

    es.addEventListener("alert:deleted", (ev) => {
      try {
        const data = JSON.parse(ev.data);
        state.alerts = state.alerts.filter((a) => Number(a.id) !== Number(data.id));
        if (data.summary) state.summary = data.summary;
        updateKPIStrip();
        renderAlertsTables();
      } catch {
        // ignore
      }
    });

    es.addEventListener("alerts:bulk_updated", (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (Array.isArray(data.alerts)) state.alerts = data.alerts;
        if (data.summary) state.summary = data.summary;
        updateKPIStrip();
        renderAlertsTables();
      } catch {
        // ignore
      }
    });

    es.onerror = () => {
      if (connText && !state.streamPaused) {
        connText.textContent = "Reconnecting Stream...";
      }
    };
  }

  async function loadInitialBootstrap() {
    try {
      const res = await fetch("/api/bootstrap");
      if (!res.ok) throw new Error("Failed to load initial telemetry state");
      const data = await res.json();
      state.history = data.history || [];
      state.alerts = data.alerts || [];
      state.rules = data.rules || [];
      if (data.summary) state.summary = data.summary;
      if (data.ml_status) {
        state.mlStatus = data.ml_status;
        const metaEl = document.getElementById("ml-model-meta");
        if (metaEl) {
          metaEl.textContent = `Artifact: ${data.ml_status.model_file} · ${data.ml_status.sample_count} calibration samples · ${data.ml_status.backend}`;
        }
      }
      if (state.history.length > 0) {
        state.latestFrame = state.history[state.history.length - 1];
      }
      if (data.live_os) {
        renderLiveOSTables(data.live_os);
      }
      updateKPIStrip();
      drawTelemetryChart();
      renderDistributionAndFeatureBars();
      renderAlertsTables();
      renderRulesTable();
      evaluateMLSandbox(false);
    } catch (err) {
      showToast(err.message);
    }
  }

  function bindEvents() {
    // Top bar navigation
    document.querySelectorAll("[data-nav]").forEach((el) => {
      el.addEventListener("click", (e) => {
        e.preventDefault();
        switchView(el.dataset.nav);
      });
    });

    // Primary Top Bar CTA: cycle/inject high-priority anomaly scenario
    document.getElementById("btn-quick-inject")?.addEventListener("click", () => {
      const scenarios = ["syn_flood", "brute_force", "memory_runaway", "exfiltration"];
      const pick = scenarios[Math.floor(Math.random() * scenarios.length)];
      triggerScenario(pick);
    });

    // Node scope selector
    document.getElementById("host-filter-select")?.addEventListener("change", (e) => {
      state.selectedHostFilter = e.target.value;
      drawTelemetryChart();
      renderAlertsTables();
    });

    // Pause / Resume Stream button
    document.getElementById("btn-toggle-stream")?.addEventListener("click", (e) => {
      state.streamPaused = !state.streamPaused;
      e.currentTarget.textContent = state.streamPaused ? "Resume Stream" : "Pause Stream";
      const connText = document.getElementById("stream-connection-text");
      if (connText) {
        connText.textContent = state.streamPaused ? "Stream Paused" : "Live Stream Connected";
        connText.classList.toggle("paused", state.streamPaused);
      }
    });

    // Scenario toolbar buttons
    document.querySelectorAll(".btn-scenario").forEach((btn) => {
      btn.addEventListener("click", () => {
        triggerScenario(btn.dataset.scenario);
      });
    });

    // Chart series toggles
    document.querySelectorAll("#chart-series-toggles .seg-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const key = btn.dataset.series;
        if (state.activeSeries.has(key)) {
          if (state.activeSeries.size > 1) state.activeSeries.delete(key);
        } else {
          state.activeSeries.add(key);
        }
        btn.classList.toggle("active", state.activeSeries.has(key));
        drawTelemetryChart();
      });
    });

    // Console shortcuts
    document.getElementById("btn-console-view-all")?.addEventListener("click", () => {
      switchView("alerts");
    });

    document.getElementById("btn-console-ack-all")?.addEventListener("click", async () => {
      await performBulkAlertAction("acknowledge_open", "All open alerts acknowledged");
    });

    // Bulk actions in Alert Feed
    document.getElementById("btn-bulk-ack")?.addEventListener("click", async () => {
      await performBulkAlertAction("acknowledge_open", "All open alerts acknowledged");
    });
    document.getElementById("btn-bulk-resolve")?.addEventListener("click", async () => {
      await performBulkAlertAction("resolve_all", "All active alerts resolved");
    });
    document.getElementById("btn-bulk-clear")?.addEventListener("click", async () => {
      await performBulkAlertAction("delete_resolved", "Purged resolved alerts from alerts.db");
    });

    // Alert table delegation (row click vs quick action click)
    ["console-alerts-tbody", "feed-alerts-tbody"].forEach((tbodyId) => {
      document.getElementById(tbodyId)?.addEventListener("click", (e) => {
        const quickBtn = e.target.closest("[data-quick-status]");
        if (quickBtn) {
          e.stopPropagation();
          updateAlertStatus(quickBtn.dataset.id, quickBtn.dataset.quickStatus);
          return;
        }
        const delBtn = e.target.closest("[data-delete-alert]");
        if (delBtn) {
          e.stopPropagation();
          deleteAlertById(delBtn.dataset.deleteAlert);
          return;
        }
        const row = e.target.closest("tr[data-alert-id]");
        if (row) {
          openAlertDrawer(row.dataset.alertId);
        }
      });
    });

    // Drawer buttons
    document.getElementById("btn-close-drawer")?.addEventListener("click", closeAlertDrawer);
    document.getElementById("btn-drawer-ack")?.addEventListener("click", () => {
      if (state.inspectedAlertId) updateAlertStatus(state.inspectedAlertId, "Acknowledged");
    });
    document.getElementById("btn-drawer-resolve")?.addEventListener("click", () => {
      if (state.inspectedAlertId) updateAlertStatus(state.inspectedAlertId, "Resolved");
    });
    document.getElementById("btn-drawer-delete")?.addEventListener("click", () => {
      if (state.inspectedAlertId) deleteAlertById(state.inspectedAlertId);
    });

    // Alert Feed Filters
    document.getElementById("alert-search-input")?.addEventListener("input", (e) => {
      state.feedFilters.search = e.target.value;
      renderAlertsTables();
    });

    document.querySelectorAll("#filter-severity-group .seg-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.feedFilters.severity = btn.dataset.severity;
        document
          .querySelectorAll("#filter-severity-group .seg-btn")
          .forEach((b) => b.classList.toggle("active", b === btn));
        renderAlertsTables();
      });
    });

    document.querySelectorAll("#filter-status-group .seg-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.feedFilters.status = btn.dataset.status;
        document
          .querySelectorAll("#filter-status-group .seg-btn")
          .forEach((b) => b.classList.toggle("active", b === btn));
        renderAlertsTables();
      });
    });

    document.getElementById("filter-threat-select")?.addEventListener("change", (e) => {
      state.feedFilters.threatClass = e.target.value;
      renderAlertsTables();
    });

    // ML Sandbox Sliders & Presets
    ["ml-cpu", "ml-mem", "ml-net", "ml-disk", "ml-conns", "ml-auth"].forEach((id) => {
      document.getElementById(id)?.addEventListener("input", () => {
        syncMLSliderLabels();
        evaluateMLSandbox(false);
      });
    });

    document.querySelectorAll("[data-ml-preset]").forEach((btn) => {
      btn.addEventListener("click", () => {
        applyMLPreset(btn.dataset.mlPreset);
      });
    });

    document.getElementById("ml-predict-form")?.addEventListener("submit", (e) => {
      e.preventDefault();
      evaluateMLSandbox(false);
    });

    document.getElementById("btn-ml-record-alert")?.addEventListener("click", () => {
      evaluateMLSandbox(true);
    });

    document.getElementById("btn-retrain-model")?.addEventListener("click", async () => {
      try {
        const res = await fetch("/api/ml/retrain", { method: "POST" });
        if (!res.ok) throw new Error("Failed to retrain model");
        const data = await res.json();
        if (data.ml_status) {
          document.getElementById(
            "ml-model-meta"
          ).textContent = `Artifact: ${data.ml_status.model_file} · Retrained ${formatUtcShort(
            data.ml_status.trained_at
          )}`;
        }
        evaluateMLSandbox(false);
        showToast("Recalibrated and saved threat_model.joblib");
      } catch (err) {
        showToast(err.message);
      }
    });

    // Rules Form & Table Actions
    document.getElementById("create-rule-form")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = document.getElementById("rule-name-input").value.trim();
      const metric = document.getElementById("rule-metric-select").value;
      const operator = document.getElementById("rule-operator-select").value;
      const threshold = parseFloat(document.getElementById("rule-threshold-input").value);
      const severity = document.getElementById("rule-severity-select").value;

      try {
        const res = await fetch("/api/rules", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name, metric, operator, threshold, severity }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Failed to create rule");
        state.rules.push(data.rule);
        renderRulesTable();
        document.getElementById("rule-name-input").value = "";
        showToast(`Created rule "${data.rule.name}"`);
      } catch (err) {
        showToast(err.message);
      }
    });

    document.getElementById("rules-tbody")?.addEventListener("click", async (e) => {
      const toggleBtn = e.target.closest("[data-toggle-rule]");
      if (toggleBtn) {
        const id = toggleBtn.dataset.toggleRule;
        const currentlyEnabled = toggleBtn.dataset.enabled === "1";
        try {
          const res = await fetch(`/api/rules/${id}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ enabled: !currentlyEnabled }),
          });
          if (!res.ok) throw new Error("Failed to update rule");
          const data = await res.json();
          const idx = state.rules.findIndex((r) => Number(r.id) === Number(id));
          if (idx >= 0) state.rules[idx] = data.rule;
          renderRulesTable();
          showToast(`Rule #${id} ${data.rule.enabled ? "enabled" : "disabled"}`);
        } catch (err) {
          showToast(err.message);
        }
        return;
      }

      const delBtn = e.target.closest("[data-delete-rule]");
      if (delBtn) {
        const id = delBtn.dataset.deleteRule;
        try {
          const res = await fetch(`/api/rules/${id}`, { method: "DELETE" });
          if (!res.ok) throw new Error("Failed to delete rule");
          state.rules = state.rules.filter((r) => Number(r.id) !== Number(id));
          renderRulesTable();
          showToast(`Deleted rule #${id}`);
        } catch (err) {
          showToast(err.message);
        }
      }
    });

    window.addEventListener("resize", () => {
      if (state.activeView === "console") {
        drawTelemetryChart();
      }
    });
  }

  async function performBulkAlertAction(action, toastText) {
    try {
      const res = await fetch("/api/alerts/bulk-action", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      });
      if (!res.ok) throw new Error("Bulk action failed");
      const data = await res.json();
      if (Array.isArray(data.alerts)) state.alerts = data.alerts;
      if (data.summary) state.summary = data.summary;
      updateKPIStrip();
      renderAlertsTables();
      showToast(toastText);
    } catch (err) {
      showToast(err.message);
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    bindEvents();
    loadInitialBootstrap();
    connectRealtimeStream();
  });
})();
