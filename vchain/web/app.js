(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const SERIES_COLORS = ["#22d3ee", "#a78bfa", "#34d399", "#fbbf24", "#60a5fa"];
  const state = {
    snap: null,
    paused: false,
    attacksBuilt: false,
    lastErrorAt: 0,
    chartFrame: null,
  };

  const el = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  };

  const fmt = (value, digits = 0) =>
    value === null || value === undefined || Number.isNaN(value)
      ? "—"
      : Number(value).toLocaleString(undefined, {
          minimumFractionDigits: digits,
          maximumFractionDigits: digits,
        });

  const shortHash = (hash, head = 10, tail = 4) =>
    !hash ? "—" : hash.length <= head + tail + 1 ? hash : `${hash.slice(0, head)}…${hash.slice(-tail)}`;

  const fmtTemp = (value) =>
    value === null || value === undefined ? "—" : `${Number(value).toFixed(2)}°`;

  const clock = (iso) =>
    !iso ? "—" : new Date(iso).toLocaleTimeString([], { hour12: false });

  const ago = (iso) => {
    if (!iso) return "—";
    const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (seconds < 5) return "just now";
    if (seconds < 60) return `${Math.floor(seconds)}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };

  const uptime = (seconds) => {
    if (seconds === null || seconds === undefined) return "—";
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    if (h) return `Up ${h}h ${String(m).padStart(2, "0")}m`;
    if (m) return `Up ${m}m ${String(s).padStart(2, "0")}s`;
    return `Up ${s}s`;
  };

  async function api(path, options = {}) {
    const response = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      cache: "no-store",
      ...options,
    });
    if (!response.ok) {
      let detail = `HTTP ${response.status}`;
      try {
        const body = await response.json();
        if (body && body.detail) {
          detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
        }
      } catch (_) {
        /* keep status text */
      }
      throw new Error(detail);
    }
    return response.json();
  }

  let toastTimer = null;
  function toast(message, bad = false) {
    const node = $("#toast");
    node.textContent = message;
    node.classList.toggle("bad", bad);
    node.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => node.classList.remove("show"), 4200);
  }

  // ------------------------------------------------------------------ render
  function render(snap) {
    state.snap = snap;
    renderPills(snap);
    renderIntro(snap);
    renderBanner(snap);
    renderKpis(snap);
    renderFleet(snap);
    renderLegend(snap);
    scheduleChart();
    renderAudit(snap);
    renderTamper(snap);
    renderAlerts(snap);
    renderBlocks(snap);
    renderReadings(snap);
    $("#last-update").textContent = `updated ${clock(snap.now)}`;
  }

  function renderPills(snap) {
    const network = snap.network;
    const mqtt = $("#net-mqtt");
    mqtt.className = `pill ${network.mqtt_connected ? "ok" : "bad"}`;
    $("span:last-child", mqtt).textContent = network.mqtt_connected ? "MQTT live" : "MQTT offline";
    mqtt.title = `${network.broker} broker at ${network.mqtt_host}:${network.mqtt_port}`;

    const chain = $("#net-chain");
    chain.className = `pill ${snap.stats.chain_ok ? "ok" : "bad"}`;
    $("span:last-child", chain).textContent = snap.stats.chain_ok ? "Chain verified" : "Chain broken";
    chain.title = `${snap.stats.chain_issue_count} structural issues`;

    const nodes = $("#net-nodes");
    nodes.className = `pill ${network.nodes_online ? "ok" : "bad"}`;
    $("span:last-child", nodes).textContent = `Nodes ${network.nodes_online}/${network.nodes_total}`;

    $("#uptime span").textContent = uptime(network.uptime_s);
  }

  function renderIntro(snap) {
    const latest = snap.blocks[snap.blocks.length - 1];
    if (!latest) {
      $("#latest-seal").textContent = "—";
      $("#latest-seal-sub").textContent = "waiting for first block";
      return;
    }
    $("#latest-seal").textContent = shortHash(latest.hash, 12, 6);
    $("#latest-seal-sub").textContent =
      `block #${latest.index} · ${latest.reading_count} readings · sealed ${ago(latest.created_at)} · ${fmt(latest.mine_ms, 0)} ms PoW`;
  }

  function renderBanner(snap) {
    const auditFailed = snap.audit && !snap.audit.ok;
    const broken = !snap.stats.chain_ok || auditFailed;
    const banner = $("#integrity-banner");
    banner.hidden = !broken;
    if (!broken) return;
    const count = snap.stats.chain_issue_count + (snap.audit ? snap.audit.failure_count : 0);
    $("#banner-text").textContent = `${count} integrity discrepancy${count === 1 ? "" : "ies"} found. Anchored data no longer matches the stored records.`;
  }

  function renderKpis(snap) {
    const stats = snap.stats;
    const latency = stats.latency;
    $("#kpi-latency").textContent = latency.n ? `${fmt(latency.p95_ms, 0)} ms` : "—";
    $("#kpi-latency-sub").textContent = latency.n
      ? `avg ${fmt(latency.avg_ms, 0)} ms · p50 ${fmt(latency.p50_ms, 0)} ms · n=${latency.n}`
      : "awaiting MQTT samples";

    $("#kpi-readings").textContent = fmt(stats.readings_anchored);
    $("#kpi-readings-sub").textContent =
      `${fmt(stats.readings_pending)} pending · ${fmt(stats.readings_rejected)} rejected · ${fmt(stats.throughput_per_min)}/min`;

    const mineTimes = snap.blocks.map((b) => b.mine_ms).filter((v) => typeof v === "number");
    const avgMine = mineTimes.length ? mineTimes.reduce((a, b) => a + b, 0) / mineTimes.length : null;
    $("#kpi-blocks").textContent = fmt(stats.chain_height);
    $("#kpi-blocks-sub").textContent =
      `${snap.blocks.length} recent · ${avgMine === null ? "—" : fmt(avgMine, 0) + " ms"} avg seal`;

    $("#kpi-tamper").textContent = `${fmt(stats.tamper_detected)}/${fmt(stats.tamper_attempts)}`;
    $("#kpi-tamper-sub").textContent =
      stats.detection_rate === null
        ? "no attacks yet"
        : `${fmt(stats.detection_rate * 100, 0)}% detection · ${fmt(stats.tamper_attempts)} attack${stats.tamper_attempts === 1 ? "" : "s"}`;

    $("#kpi-alerts").textContent = fmt(stats.alerts_total);
    $("#kpi-alerts-sub").textContent = `${fmt(stats.excursions)} excursion${stats.excursions === 1 ? "" : "s"} · ${fmt(stats.alerts_critical)} critical`;

    $("#kpi-battery").textContent = `${fmt(snap.battery.runtime_hours, 0)} h`;
    $("#kpi-battery-sub").textContent = `${fmt(snap.battery.average_current_ma, 1)} mA avg · ${fmt(snap.battery.interval_seconds, 0)}s duty cycle`;
  }

  function renderFleet(snap) {
    const fleet = $("#fleet");
    fleet.replaceChildren();
    $("#fleet-count").textContent = `${snap.network.nodes_online}/${snap.network.nodes_total} online`;

    snap.devices.forEach((device) => {
      const row = el("div", "fleet-row");
      if (device.excursion_active) row.classList.add("excursion");
      if (!device.online) row.classList.add("offline");

      const left = el("div");
      left.append(el("div", "fleet-id", device.id), el("div", "fleet-name", device.name));

      const meta = el("div", "fleet-meta");
      const humidity = el("span", "", "RH ");
      humidity.append(el("b", "", device.humidity_pct === null ? "—" : `${fmt(device.humidity_pct, 1)}%`));
      const mkt = el("span", "", "MKT ");
      mkt.append(el("b", "", device.mkt_c === null ? "—" : `${fmt(device.mkt_c, 2)}°`));
      const seq = el("span", "", "seq ");
      seq.append(el("b", "", device.seq === null ? "—" : fmt(device.seq)));

      const battery = el("span", "battery");
      battery.append(el("span", "", "batt"));
      const bar = el("span", "battery-bar");
      const fill = el("span", "battery-fill");
      const pct = Math.max(0, Math.min(100, device.battery_pct || 0));
      fill.style.width = `${pct}%`;
      if (pct < 20) fill.classList.add("critical");
      else if (pct < 50) fill.classList.add("low");
      bar.append(fill);
      battery.append(bar, el("b", "", `${fmt(pct, 0)}%`));

      meta.append(humidity, mkt, seq, battery);
      left.append(meta);

      const right = el("div");
      right.style.textAlign = "right";
      const temp = el("div", "fleet-temp", fmtTemp(device.temperature_c));
      if (device.temperature_c !== null && (device.temperature_c < snap.policy.min_temp_c || device.temperature_c > snap.policy.max_temp_c)) {
        temp.classList.add("warn");
      }
      temp.append(el("small", "", "C"));

      const actions = el("div", "fleet-actions");
      const toggle = el("button", "btn tiny ghost", device.excursion_active ? "End excursion" : "Force excursion");
      toggle.title = device.excursion_active ? "Return the node to its normal profile" : "Simulate a 9.4 °C cold-chain breach on this node";
      toggle.addEventListener("click", () => toggleExcursion(device.id, !device.excursion_active, toggle));
      actions.append(toggle);
      right.append(temp, actions);

      row.append(left, right);
      fleet.append(row);
    });
  }

  function renderLegend(snap) {
    const legend = $("#chart-legend");
    legend.replaceChildren();
    snap.devices.forEach((device, index) => {
      const item = el("span", "legend-item");
      const swatch = el("span", "legend-swatch");
      swatch.style.background = SERIES_COLORS[index % SERIES_COLORS.length];
      item.append(swatch, el("span", "", `${device.id} ${fmtTemp(device.temperature_c)}`));
      legend.append(item);
    });
  }

  function scheduleChart() {
    if (state.chartFrame) cancelAnimationFrame(state.chartFrame);
    state.chartFrame = requestAnimationFrame(() => {
      state.chartFrame = null;
      drawChart();
    });
  }

  function drawChart() {
    const snap = state.snap;
    const canvas = $("#temp-chart");
    if (!snap || !canvas) return;
    const series = snap.series || {};
    const entries = Object.entries(series).filter(([, points]) => points.length);
    $("#chart-empty").hidden = entries.length > 0;

    const rect = canvas.getBoundingClientRect();
    if (rect.width < 20) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, rect.width, rect.height);

    const pad = { l: 44, r: 16, t: 16, b: 26 };
    const plotW = rect.width - pad.l - pad.r;
    const plotH = rect.height - pad.t - pad.b;
    if (plotW <= 0 || plotH <= 0) return;

    const allTemps = entries.flatMap(([, points]) => points.map((p) => p.temp));
    let minY = 0;
    let maxY = 12;
    if (allTemps.length) {
      minY = Math.min(0, Math.floor(Math.min(...allTemps) - 1));
      maxY = Math.max(12, Math.ceil(Math.max(...allTemps) + 1));
    }
    const maxLen = Math.max(...entries.map(([, points]) => points.length), 1);
    const xAt = (i) => pad.l + (maxLen === 1 ? 0 : (i / (maxLen - 1)) * plotW);
    const yAt = (v) => pad.t + ((maxY - v) / (maxY - minY)) * plotH;

    ctx.font = '10px ui-monospace, "SFMono-Regular", Menlo, monospace';
    ctx.textBaseline = "middle";

    // safe band
    const safeTop = yAt(snap.policy.max_temp_c);
    const safeBottom = yAt(snap.policy.min_temp_c);
    const band = ctx.createLinearGradient(0, safeTop, 0, safeBottom);
    band.addColorStop(0, "rgba(52, 211, 153, 0.10)");
    band.addColorStop(1, "rgba(52, 211, 153, 0.045)");
    ctx.fillStyle = band;
    ctx.fillRect(pad.l, safeTop, plotW, safeBottom - safeTop);

    // horizontal grid
    for (let t = minY; t <= maxY; t += 2) {
      const y = yAt(t);
      ctx.strokeStyle = "rgba(148, 163, 184, 0.10)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(pad.l, y + 0.5);
      ctx.lineTo(pad.l + plotW, y + 0.5);
      ctx.stroke();
      ctx.fillStyle = "#5f7391";
      ctx.textAlign = "right";
      ctx.fillText(`${t}°`, pad.l - 8, y);
    }

    // thresholds
    ctx.setLineDash([5, 5]);
    [snap.policy.min_temp_c, snap.policy.max_temp_c].forEach((value) => {
      const y = yAt(value);
      ctx.strokeStyle = "rgba(52, 211, 153, 0.55)";
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.moveTo(pad.l, y);
      ctx.lineTo(pad.l + plotW, y);
      ctx.stroke();
    });
    ctx.setLineDash([]);
    ctx.fillStyle = "rgba(52, 211, 153, 0.8)";
    ctx.textAlign = "left";
    ctx.fillText(`SAFE ${snap.policy.min_temp_c}–${snap.policy.max_temp_c}°C`, pad.l + 8, safeTop - 7);

    // series
    entries.forEach(([deviceId, points], index) => {
      const color = SERIES_COLORS[index % SERIES_COLORS.length];
      const offset = maxLen - points.length;
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.lineJoin = "round";
      ctx.lineCap = "round";
      ctx.shadowColor = color;
      ctx.shadowBlur = 7;
      ctx.beginPath();
      points.forEach((point, i) => {
        const x = xAt(offset + i);
        const y = yAt(point.temp);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
      ctx.shadowBlur = 0;

      points.forEach((point, i) => {
        const x = xAt(offset + i);
        const y = yAt(point.temp);
        const excursion = point.temp < snap.policy.min_temp_c || point.temp > snap.policy.max_temp_c;
        ctx.beginPath();
        ctx.fillStyle = excursion ? "#fb7185" : color;
        ctx.arc(x, y, excursion ? 3.2 : 1.7, 0, Math.PI * 2);
        ctx.fill();
        if (excursion) {
          ctx.strokeStyle = "rgba(251, 113, 133, 0.35)";
          ctx.lineWidth = 3;
          ctx.beginPath();
          ctx.arc(x, y, 6, 0, Math.PI * 2);
          ctx.stroke();
        }
      });

    });

    // current value labels, spread vertically so close lines stay readable
    const labels = entries
      .map(([, points], index) => {
        const last = points[points.length - 1];
        return last
          ? {
              color: SERIES_COLORS[index % SERIES_COLORS.length],
              text: `${last.temp.toFixed(1)}°`,
              y: Math.max(pad.t + 7, Math.min(pad.t + plotH - 4, yAt(last.temp) - 9)),
            }
          : null;
      })
      .filter(Boolean)
      .sort((a, b) => a.y - b.y);
    for (let i = 1; i < labels.length; i++) {
      if (labels[i].y - labels[i - 1].y < 11) labels[i].y = labels[i - 1].y + 11;
    }
    ctx.textAlign = "right";
    ctx.font = '10px ui-monospace, "SFMono-Regular", Menlo, monospace';
    labels.forEach((label) => {
      ctx.fillStyle = label.color;
      ctx.fillText(label.text, pad.l + plotW - 2, label.y);
    });

    // x labels
    ctx.fillStyle = "#5f7391";
    ctx.font = '9.5px ui-monospace, "SFMono-Regular", Menlo, monospace';
    ctx.textAlign = "left";
    ctx.fillText("oldest", pad.l, rect.height - 10);
    ctx.textAlign = "right";
    ctx.fillText("now", pad.l + plotW, rect.height - 10);
  }

  function renderAudit(snap) {
    const summary = $("#audit-summary");
    const meta = $("#audit-meta");
    const failures = $("#audit-failures");
    summary.replaceChildren();
    meta.replaceChildren();
    failures.replaceChildren();

    const audit = snap.audit;
    if (!audit) {
      summary.append(el("span", "badge neutral", "Not run yet"), el("span", "muted", "Run an audit to re-derive every hash, signature and proof."));
    } else {
      const newReadings = Math.max(0, snap.stats.readings_total - audit.readings_checked);
      const newBlocks = Math.max(0, snap.stats.chain_height + 1 - audit.blocks_checked);
      const stale = newReadings > 0 || newBlocks > 0;
      summary.append(
        el("span", `badge ${audit.ok ? "ok" : "bad"}`, audit.ok ? "Integrity verified" : `${audit.failure_count} integrity failures`)
      );
      if (stale) {
        summary.append(
          el("span", "badge neutral", "prefix"),
          el("span", "muted", `Verified the first ${fmt(audit.readings_checked)} readings and ${fmt(audit.blocks_checked)} blocks; ${fmt(newReadings)} readings and ${fmt(newBlocks)} blocks sealed since.`)
        );
      } else {
        summary.append(
          el("span", "muted", audit.ok ? "Every reading matches its anchored commitment." : "Anchored data and stored data disagree.")
        );
      }
      meta.append(
        metaItem("last run", ago(audit.finished_at)),
        metaItem("checks", fmt(audit.checks)),
        metaItem("readings", fmt(audit.readings_checked)),
        metaItem("blocks", fmt(audit.blocks_checked)),
        metaItem("alerts", fmt(audit.alerts_checked)),
        metaItem("duration", `${fmt(audit.duration_ms, 0)} ms`)
      );
    }

    const issues = audit && audit.failures && audit.failures.length ? audit.failures : snap.chain_issues || [];
    if (!issues.length) {
      if (audit && audit.ok) {
        const clean = el("div", "failure");
        clean.style.borderColor = "rgba(52,211,153,.25)";
        clean.style.background = "rgba(52,211,153,.05)";
        clean.append(el("code", "", "NO DISCREPANCIES"), el("p", "", "All hashes, Merkle proofs, proof-of-work targets and validator signatures verify."));
        failures.append(clean);
      }
      return;
    }
    issues.slice(0, 10).forEach((issue) => {
      const row = el("div", "failure");
      const code = el("code", "", issue.kind || "ISSUE");
      const body = el("div");
      body.append(el("p", "", issue.detail || "integrity issue"));
      if (issue.block_index !== null && issue.block_index !== undefined) {
        body.append(el("div", "where", `block #${issue.block_index}`));
      }
      row.append(code, body);
      failures.append(row);
    });
    if (issues.length > 10) {
      failures.append(el("div", "dim", `+ ${issues.length - 10} more findings`));
    }
  }

  function metaItem(label, value) {
    const span = el("span");
    span.append(document.createTextNode(`${label} `), el("b", "", value));
    return span;
  }

  function renderTamper(snap) {
    const grid = $("#tamper-grid");
    if (!state.attacksBuilt) {
      grid.replaceChildren();
      (snap.attacks || []).forEach((attack) => {
        const button = el("button", "attack-btn");
        button.append(el("strong", "", attack.name), el("span", "", attack.layer));
        button.title = attack.description;
        button.addEventListener("click", () => runAttack(attack.key, button));
        grid.append(button);
      });
      state.attacksBuilt = true;
    }

    const history = $("#tamper-history");
    history.replaceChildren();
    (snap.tamper_events || []).forEach((event) => {
      const row = el("div", "history-row");
      const left = el("span");
      left.append(el("b", "", event.attack), document.createTextNode(` · ${ago(event.created_at)}`));
      const verdict = el("span", "", event.detected ? "detected" : "missed");
      verdict.style.color = event.detected ? "var(--emerald)" : "var(--red)";
      row.append(left, verdict);
      history.append(row);
    });
  }

  function renderAlerts(snap) {
    const list = $("#alerts");
    list.replaceChildren();
    $("#alert-count").textContent = `${snap.stats.alerts_total} total`;
    if (!snap.alerts.length) {
      list.append(el("div", "dim", "No alerts yet. The fleet is inside its cold-chain envelope."));
      return;
    }
    snap.alerts.forEach((alert) => {
      const row = el("div", `alert ${alert.severity}`);
      row.append(el("span", "sev"));
      const body = el("div");
      const head = el("strong", "", alert.kind.replaceAll("_", " ").toLowerCase());
      body.append(head);
      const code = el("code", "", `${alert.device_id} · ${shortHash(alert.reading_digest, 8, 4)}`);
      if (alert.block_index !== null) code.textContent += ` · block #${alert.block_index}`;
      body.append(code, el("p", "", alert.message));
      const when = el("span", "when", ago(alert.created_at));
      row.append(body, when);
      if (alert.reading_digest) {
        row.style.cursor = "pointer";
        row.addEventListener("click", () => openReading(alert.reading_digest));
      }
      list.append(row);
    });
  }

  function renderBlocks(snap) {
    const body = $("#blocks");
    body.replaceChildren();
    $("#chain-tag").textContent = `${snap.stats.chain_height} blocks · ${snap.stats.chain_ok ? "verified" : "failed"}`;
    [...snap.blocks].reverse().forEach((block) => {
      const row = el("tr");
      row.append(
        el("td", "mono dim", `#${block.index}`),
        el("td", "hash cyan", shortHash(block.hash, 14, 6)),
        el("td", "hash", shortHash(block.merkle_root, 14, 6)),
        el("td", "", fmt(block.reading_count)),
        el("td", "", fmt(block.alert_count)),
        el("td", "", `${block.validators.length}/${snap.policy.validators}`),
        el("td", "dim", `${clock(block.created_at)} · ${fmt(block.mine_ms, 0)} ms`)
      );
      row.title = "Inspect block, Merkle root and validator signatures";
      row.addEventListener("click", () => openBlock(block.index));
      body.append(row);
    });
  }

  function renderReadings(snap) {
    const body = $("#readings");
    body.replaceChildren();
    $("#reading-count").textContent = `${snap.stats.readings_anchored} anchored`;
    snap.readings.forEach((reading) => {
      const row = el("tr");
      const tempCell = el("td", "mono", fmtTemp(reading.temperature_c));
      if (reading.temperature_c < snap.policy.min_temp_c || reading.temperature_c > snap.policy.max_temp_c) {
        tempCell.style.color = "var(--red)";
      }
      const status = el("td");
      status.append(el("span", `chip ${reading.status}`, reading.status));
      if (reading.violations && reading.violations.some((v) => v.severity === "critical")) {
        status.append(document.createTextNode(" "), el("span", "chip heat", "excursion"));
      }
      row.append(
        el("td", "dim", clock(reading.measured_at)),
        el("td", "mono", reading.device_id),
        tempCell,
        el("td", "mono dim", `${fmt(reading.humidity_pct, 1)}%`),
        el("td", "mono dim", fmt(reading.seq)),
        el("td", "mono", reading.block_index === null ? "—" : `#${reading.block_index}`),
        el("td", "mono dim", reading.latency_ms === null ? "—" : `${fmt(reading.latency_ms, 0)} ms`),
        el("td", "hash", shortHash(reading.digest, 10, 4)),
        status
      );
      row.addEventListener("click", () => openReading(reading.digest));
      body.append(row);
    });
  }

  // ------------------------------------------------------------------ modals
  function openModal(title, content) {
    $("#modal-title").textContent = title;
    $("#modal-body").replaceChildren(content);
    $("#modal").hidden = false;
  }

  function closeModal() {
    $("#modal").hidden = true;
  }

  function verifyHero(state, title, subtitle) {
    const palette = {
      ok: ["rgba(52,211,153,.14)", "var(--emerald)", "rgba(52,211,153,.4)", "✓"],
      bad: ["rgba(251,113,133,.14)", "var(--red)", "rgba(251,113,133,.4)", "✕"],
      neutral: ["rgba(148,163,184,.12)", "var(--muted)", "rgba(148,163,184,.35)", "…"],
    };
    const [background, color, border, glyph] = palette[state] || palette.neutral;
    const hero = el("div", `verify-hero ${state}`);
    const mark = el("span", "check");
    mark.style.width = "30px";
    mark.style.height = "30px";
    mark.style.borderRadius = "50%";
    mark.style.display = "grid";
    mark.style.placeItems = "center";
    mark.style.background = background;
    mark.style.color = color;
    mark.style.border = `1px solid ${border}`;
    mark.textContent = glyph;
    const text = el("div");
    text.append(el("strong", "", title), el("p", "", subtitle));
    hero.append(mark, text);
    return hero;
  }

  function kvList(pairs) {
    const dl = el("dl", "kv");
    pairs.forEach(([key, value]) => {
      dl.append(el("dt", "", key), el("dd", "", value === null || value === undefined ? "—" : value));
    });
    return dl;
  }

  function checkGrid(checks) {
    const grid = el("div", "check-grid");
    Object.entries(checks).forEach(([name, value]) => {
      if (name === "verified") return;
      const row = el("div", `check ${value ? "pass" : "fail"}`);
      row.append(el("span", "mark", value ? "✓" : "✕"), el("span", "", name.replaceAll("_", " ")));
      grid.append(row);
    });
    return grid;
  }

  async function openReading(digest) {
    try {
      const detail = await api(`/api/readings/${encodeURIComponent(digest)}`);
      const reading = detail.reading;
      const content = el("div");
      const ok = detail.checks.verified;
      const pending = reading.status === "pending";
      const rejected = reading.status === "rejected";
      const heroState = ok ? "ok" : pending ? "neutral" : "bad";
      const heroTitle = ok
        ? "Cryptographically verified"
        : pending
          ? "Awaiting block seal"
          : rejected
            ? "Rejected by the gateway"
            : "Verification failed";
      const heroSubtitle = ok
        ? "Payload digest, device signature and Merkle inclusion all verify."
        : pending
          ? "The reading is signed and queued; Merkle inclusion begins when the next block is sealed."
          : rejected
            ? "The gateway refused this packet, so it was never anchored."
            : "One or more integrity checks failed for this reading.";
      content.append(verifyHero(heroState, heroTitle, heroSubtitle));
      content.append(kvList([
        ["Device", reading.device_id],
        ["Sequence", fmt(reading.seq)],
        ["Measured", reading.measured_at],
        ["Temperature", `${fmtTemp(reading.temperature_c)}C`],
        ["Humidity", `${fmt(reading.humidity_pct, 1)} %RH`],
        ["GPS", `${reading.lat.toFixed(5)}, ${reading.lon.toFixed(5)}${reading.gps_fix ? "" : " (no fix)"}`],
        ["Block", reading.block_index === null ? "pending" : `#${reading.block_index}`],
        ["Status", reading.status],
        ["Latency", reading.latency_ms === null ? "—" : `${fmt(reading.latency_ms, 1)} ms`],
        ["Digest", reading.digest],
        ["Signature", detail.signature],
      ]));

      content.append(el("div", "section-title", "Verification checks"));
      content.append(checkGrid(detail.checks));

      if (detail.proof) {
        content.append(el("div", "section-title", "Merkle inclusion proof"));
        const proof = el("div", "proof");
        proof.append(
          proofRow("block hash", detail.proof.block_hash),
          proofRow("merkle root", detail.proof.merkle_root),
          proofRow("leaf index", String(detail.proof.leaf_index))
        );
        detail.proof.proof.forEach((step, index) => {
          proof.append(proofRow(`sibling ${index + 1}`, `${step.position} · ${step.hash}`));
        });
        content.append(proof);
      }
      openModal(`Reading ${shortHash(digest, 12, 6)}`, content);
    } catch (error) {
      toast(`Could not load reading: ${error.message}`, true);
    }
  }

  function proofRow(label, value) {
    const row = el("div", "proof-row");
    row.append(el("b", "", label), el("span", "", value));
    return row;
  }

  async function openBlock(index) {
    try {
      const detail = await api(`/api/blocks/${index}`);
      const block = detail.block;
      const content = el("div");
      const ok = Object.entries(detail.checks)
        .filter(([key]) => key !== "validator_signatures_valid")
        .every(([, value]) => value);
      content.append(
        verifyHero(
          ok ? "ok" : "bad",
          ok ? "Block verified" : "Block verification failed",
          ok
            ? "Header hash, Merkle root, proof-of-work and validator quorum all verify."
            : "The block no longer matches its commitments."
        )
      );
      content.append(kvList([
        ["Block", `#${block.index}`],
        ["Hash", block.hash],
        ["Previous", block.prev_hash],
        ["Merkle root", block.merkle_root],
        ["Created", block.created_at],
        ["Nonce", fmt(block.nonce)],
        ["Difficulty", `${block.difficulty} leading hex zeros`],
        ["Proof-of-work", `${fmt(block.mine_ms, 1)} ms`],
        ["Validators", `${detail.checks.validator_signatures_valid}/${state.snap.policy.validators} signatures`],
        ["Readings", fmt(block.reading_count)],
        ["Excursions", fmt(block.excursion_count)],
      ]));
      content.append(el("div", "section-title", "Block checks"));
      content.append(checkGrid(detail.checks));

      content.append(el("div", "section-title", `Committed readings (${detail.readings.length})`));
      if (!detail.readings.length) {
        content.append(el("div", "dim", "Genesis block has no readings."));
      } else {
        const table = el("table", "table");
        const thead = el("thead");
        const headRow = el("tr");
        ["Device", "Seq", "Temp", "Digest", "Status"].forEach((label) => headRow.append(el("th", "", label)));
        thead.append(headRow);
        const tbody = el("tbody");
        detail.readings.forEach((reading) => {
          const row = el("tr");
          row.append(
            el("td", "mono", reading.device_id),
            el("td", "mono dim", fmt(reading.seq)),
            el("td", "mono", fmtTemp(reading.temperature_c)),
            el("td", "hash", shortHash(reading.digest, 12, 4)),
            el("td", "", reading.status)
          );
          row.addEventListener("click", () => openReading(reading.digest));
          tbody.append(row);
        });
        table.append(thead, tbody);
        const wrap = el("div", "table-wrap");
        wrap.style.padding = "0";
        wrap.append(table);
        content.append(wrap);
      }

      if (detail.alerts.length) {
        content.append(el("div", "section-title", `Committed alerts (${detail.alerts.length})`));
        detail.alerts.forEach((alert) => {
          const row = el("div", "failure");
          row.append(el("code", "", alert.kind), el("p", "", `${alert.device_id}: ${alert.message}`));
          content.append(row);
        });
      }
      openModal(`Block #${block.index}`, content);
    } catch (error) {
      toast(`Could not load block: ${error.message}`, true);
    }
  }

  function showAttackResult(result) {
    const content = el("div", "attack-result");
    content.append(
      verifyHero(
        result.detected ? "ok" : "bad",
        result.detected ? "Tamper detected" : "Tamper NOT detected",
        result.description
      )
    );
    const pills = el("div", "pill-row");
    pills.append(
      el("span", `badge ${result.detected ? "bad" : "warn"}`, result.detected ? "DETECTED" : "MISSED"),
      el("span", "badge neutral", result.layer),
      el("span", "badge neutral", `${fmt(result.duration_ms, 0)} ms`)
    );
    content.append(pills);

    if (result.failures.length) {
      content.append(el("div", "section-title", `New integrity findings (${result.failures.length})`));
      const list = el("div", "failures");
      list.style.padding = "0";
      result.failures.forEach((failure) => {
        const row = el("div", "failure");
        const body = el("div");
        body.append(el("p", "", failure.detail));
        if (failure.block_index !== null && failure.block_index !== undefined) {
          body.append(el("div", "where", `block #${failure.block_index}`));
        }
        row.append(el("code", "", failure.kind), body);
        list.append(row);
      });
      content.append(list);
    }

    const report = result.report;
    content.append(
      el("div", "section-title", "Audit response"),
      kvList([
        ["Checks", fmt(report.checks)],
        ["Readings", fmt(report.readings_checked)],
        ["Blocks", fmt(report.blocks_checked)],
        ["Failures", fmt(report.failure_count)],
        ["Duration", `${fmt(report.duration_ms, 0)} ms`],
      ])
    );
    content.append(el("div", "dim", "The ledger stays corrupted as evidence. Use Reset demo to rebuild it from genesis."));
    openModal(result.name, content);
  }

  // ------------------------------------------------------------------ actions
  async function refresh() {
    try {
      const snap = await api("/api/snapshot");
      render(snap);
    } catch (error) {
      const now = Date.now();
      if (now - state.lastErrorAt > 8000) {
        state.lastErrorAt = now;
        toast(`Live feed unavailable: ${error.message}`, true);
      }
    }
  }

  async function runAudit(button) {
    const buttons = [$("#btn-audit"), $("#btn-audit-2"), button].filter(Boolean);
    buttons.forEach((b) => (b.disabled = true));
    try {
      const report = await api("/api/audit", { method: "POST" });
      toast(
        report.ok
          ? `Audit verified ${fmt(report.readings_checked)} readings in ${fmt(report.duration_ms, 0)} ms`
          : `Audit found ${report.failure_count} integrity failures`,
        !report.ok
      );
      await refresh();
    } catch (error) {
      toast(`Audit failed: ${error.message}`, true);
    } finally {
      buttons.forEach((b) => (b.disabled = false));
    }
  }

  async function runAttack(key, button) {
    const all = [...document.querySelectorAll(".attack-btn")];
    all.forEach((b) => (b.disabled = true));
    try {
      const result = await api(`/api/tamper/${encodeURIComponent(key)}`, { method: "POST" });
      showAttackResult(result);
      await refresh();
    } catch (error) {
      toast(`Attack failed: ${error.message}`, true);
    } finally {
      all.forEach((b) => (b.disabled = false));
    }
  }

  async function resetDemo() {
    if (!window.confirm("Rebuild the ledger from genesis? This discards the current chain and all tamper evidence.")) return;
    const button = $("#btn-reset");
    button.disabled = true;
    try {
      await api("/api/reset", { method: "POST" });
      toast("Ledger rebuilt from genesis and demo fleet re-seeded");
      await refresh();
    } catch (error) {
      toast(`Reset failed: ${error.message}`, true);
    } finally {
      button.disabled = false;
    }
  }

  async function toggleExcursion(deviceId, active, button) {
    button.disabled = true;
    try {
      await api("/api/excursion", {
        method: "POST",
        body: JSON.stringify({ device_id: deviceId, active }),
      });
      toast(`${deviceId} ${active ? "now reporting a 9.4 °C excursion" : "returned to its normal profile"}`);
      await refresh();
    } catch (error) {
      toast(`Could not update node: ${error.message}`, true);
      button.disabled = false;
    }
  }

  function togglePause() {
    state.paused = !state.paused;
    const button = $("#btn-pause");
    button.textContent = state.paused ? "Resume" : "Pause";
    button.classList.toggle("ghost", true);
    if (!state.paused) refresh();
  }

  // -------------------------------------------------------------------- boot
  $("#btn-audit").addEventListener("click", () => runAudit());
  $("#btn-audit-2").addEventListener("click", () => runAudit());
  $("#banner-audit").addEventListener("click", () => runAudit());
  $("#btn-reset").addEventListener("click", resetDemo);
  $("#btn-pause").addEventListener("click", togglePause);
  $("#btn-export").addEventListener("click", () => {
    window.location.href = "/api/export";
  });
  $("#modal-close").addEventListener("click", closeModal);
  $("#modal").addEventListener("click", (event) => {
    if (event.target.matches("[data-close]")) closeModal();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeModal();
  });
  window.addEventListener("resize", scheduleChart);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && !state.paused) refresh();
  });

  refresh();
  setInterval(() => {
    if (!state.paused && !document.hidden) refresh();
  }, 1500);
})();
