/**
 * component_dashboard.js — TEM Module Breakdown Panel (Step 7C)
 *
 * Populates the 5 component cards with live data from TEMReport.
 * Each card: mini-viz canvas, stat readouts, sparkline.
 * Veracity Mandate: every readout maps to a real TEMReport field.
 */

const ComponentDashboard = (() => {
  'use strict';

  // Sparkline rendering helper
  function drawSparkline(canvasId, values, opts = {}) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !values || values.length === 0) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const max = opts.max || Math.max(...values, 0.001);
    const min = opts.min || 0;
    const range = max - min || 1;
    const step = w / (values.length - 1 || 1);

    // Threshold line
    if (opts.threshold != null) {
      const ty = h - ((opts.threshold - min) / range) * h;
      ctx.strokeStyle = 'rgba(239, 68, 68, 0.3)';
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.moveTo(0, ty);
      ctx.lineTo(w, ty);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // Line
    ctx.strokeStyle = opts.color || '#22d3ee';
    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    ctx.beginPath();
    values.forEach((v, i) => {
      const x = i * step;
      const y = h - ((v - min) / range) * h;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Fill under
    ctx.lineTo((values.length - 1) * step, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, (opts.color || '#22d3ee') + '30');
    grad.addColorStop(1, 'transparent');
    ctx.fillStyle = grad;
    ctx.fill();
  }

  // Radial gauge for AISE intent
  function drawRadialGauge(canvasId, value, maxVal = 1.0) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const cx = w / 2, cy = h / 2 + 10;
    const r = Math.min(w, h) * 0.35;
    const startAngle = Math.PI * 0.8;
    const endAngle = Math.PI * 2.2;
    const pct = Math.min(value / maxVal, 1);
    const valAngle = startAngle + (endAngle - startAngle) * pct;

    // Background arc
    ctx.beginPath();
    ctx.arc(cx, cy, r, startAngle, endAngle);
    ctx.strokeStyle = 'rgba(148,163,184,0.15)';
    ctx.lineWidth = 8;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Value arc with color gradient
    const color = pct < 0.3 ? '#2ecc71' : pct < 0.6 ? '#f59e0b' : '#ef4444';
    ctx.beginPath();
    ctx.arc(cx, cy, r, startAngle, valAngle);
    ctx.strokeStyle = color;
    ctx.lineWidth = 8;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Center value
    ctx.fillStyle = '#e2e8f0';
    ctx.font = '600 16px "JetBrains Mono"';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(value.toFixed(2), cx, cy - 5);

    // Label
    ctx.fillStyle = '#94a3b8';
    ctx.font = '500 9px "Inter"';
    ctx.fillText('INTENT', cx, cy + 14);
  }

  // Multi-bar chart for comparing several scalar metrics
  function drawMultiBar(canvasId, values, labels, opts = {}) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !values || values.length === 0) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const max = opts.max || Math.max(...values, 0.001);
    const barW = (w - 4) / values.length - 2;
    const colors = opts.colors || ['#22d3ee', '#818cf8', '#a78bfa', '#f59e0b', '#ef4444'];

    values.forEach((v, i) => {
      const barH = (v / max) * (h - 14);
      const x = 2 + i * (barW + 2);
      const y = h - 12 - barH;
      ctx.fillStyle = colors[i % colors.length];
      ctx.fillRect(x, y, barW, barH);
      // Label
      if (labels && labels[i]) {
        ctx.fillStyle = '#94a3b8';
        ctx.font = '500 7px "Inter"';
        ctx.textAlign = 'center';
        ctx.fillText(labels[i], x + barW / 2, h - 2);
      }
    });
  }

  // 10-spoke radar chart for AISE intent vector
  function drawIntentRadar(canvasId, categories, opts = {}) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !categories || categories.length === 0) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const cx = w / 2, cy = h / 2;
    const r = Math.min(w, h) * 0.38;
    const n = categories.length;
    const step = (Math.PI * 2) / n;

    // Background rings
    for (let ring = 0.25; ring <= 1; ring += 0.25) {
      ctx.beginPath();
      for (let i = 0; i <= n; i++) {
        const angle = i * step - Math.PI / 2;
        const px = cx + Math.cos(angle) * r * ring;
        const py = cy + Math.sin(angle) * r * ring;
        if (i === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.closePath();
      ctx.strokeStyle = 'rgba(148,163,184,0.08)';
      ctx.lineWidth = 0.5;
      ctx.stroke();
    }

    // Spokes
    for (let i = 0; i < n; i++) {
      const angle = i * step - Math.PI / 2;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + Math.cos(angle) * r, cy + Math.sin(angle) * r);
      ctx.strokeStyle = 'rgba(148,163,184,0.06)';
      ctx.lineWidth = 0.5;
      ctx.stroke();
    }

    // Data polygon
    ctx.beginPath();
    categories.forEach((cat, i) => {
      const angle = i * step - Math.PI / 2;
      const v = Math.min(cat.value, 1.0);
      const px = cx + Math.cos(angle) * r * v;
      const py = cy + Math.sin(angle) * r * v;
      if (i === 0) ctx.moveTo(px, py);
      else ctx.lineTo(px, py);
    });
    ctx.closePath();
    ctx.fillStyle = 'rgba(239, 68, 68, 0.15)';
    ctx.fill();
    ctx.strokeStyle = '#ef4444';
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Dots + labels
    categories.forEach((cat, i) => {
      const angle = i * step - Math.PI / 2;
      const v = Math.min(cat.value, 1.0);
      const px = cx + Math.cos(angle) * r * v;
      const py = cy + Math.sin(angle) * r * v;
      // Dot
      ctx.beginPath();
      ctx.arc(px, py, 2, 0, Math.PI * 2);
      ctx.fillStyle = v > 0.3 ? '#ef4444' : '#22d3ee';
      ctx.fill();
      // Label
      const lx = cx + Math.cos(angle) * (r + 12);
      const ly = cy + Math.sin(angle) * (r + 12);
      ctx.fillStyle = '#94a3b8';
      ctx.font = '500 6px "Inter"';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(cat.label, lx, ly);
    });
  }

  // Populate viewport HUD badges from TEMReport
  function populateHUD(report) {
    const hudEntropy = document.getElementById('hud-entropy');
    const hudThreat = document.getElementById('hud-threat');
    const hudVerdict = document.getElementById('hud-verdict');
    if (hudEntropy) hudEntropy.textContent = 'H̄ ' + report.tfea_mean_entropy.toFixed(2);
    if (hudThreat) hudThreat.textContent = (report.composite_threat_score * 100).toFixed(0) + '% threat';
    if (hudVerdict) {
      const vmap = { 0: '✔ CLEAR', 1: '◉ MONITOR', 2: '⚠ QUARANTINE', 3: '☢ DESTROY' };
      hudVerdict.textContent = vmap[report.quarantine_verdict] || '—';
      hudVerdict.className = 'hud-badge hud-verdict v-' + report.quarantine_verdict;
    }
  }

  // Simple entropy heatmap strip for TFEA mini-viz
  function drawEntropyStrip(canvasId, windows) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !windows || windows.length === 0) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const barW = w / windows.length;
    windows.forEach((e, i) => {
      const t = e / 8.0;
      const r = Math.floor(30 + t * 209);
      const g = Math.floor(64 + (1 - Math.abs(t - 0.5) * 2) * 147);
      const b = Math.floor(175 - t * 120);
      ctx.fillStyle = `rgb(${r},${g},${b})`;
      ctx.fillRect(i * barW, 0, barW + 0.5, h);
    });
  }

  // Format number for display
  function fmt(v, decimals = 3) {
    if (v == null || isNaN(v)) return '—';
    return typeof v === 'number' ? v.toFixed(decimals) : String(v);
  }
  function fmtPct(v) { return v != null ? (v * 100).toFixed(1) + '%' : '—'; }
  function fmtInt(v) { return v != null ? v.toLocaleString() : '—'; }
  function fmtHex(v) {
    if (v == null) return '—';
    try { return '0x' + BigInt(v).toString(16).padStart(16, '0').slice(0, 12) + '…'; }
    catch { return '—'; }
  }

  /**
   * Populate all component cards from a TEMReport.
   */
  function populate(report) {
    if (!report) return;

    // ── TFEA ──
    _setText('stat-tfea-shannon', fmt(report.tfea_mean_entropy));
    _setText('stat-tfea-compression', fmt(report.tfea_compression_ratio));
    _setText('stat-tfea-structured', fmtPct(report.structured_fraction));
    _setText('stat-tfea-peak', fmt(report.tfea_mismatch_sigma));
    _setText('stat-tfea-variance', fmt(report.tfea_entropy_variance, 4));
    _setText('stat-tfea-flags', report.tfea_anomaly_flags ? '0x' + report.tfea_anomaly_flags.toString(16) : '0x0');

    // TFEA sparkline — window entropies
    if (report.tfea_window_entropies && report.tfea_window_entropies.length > 0) {
      drawSparkline('spark-tfea', report.tfea_window_entropies, { max: 8, threshold: 7.5 });
      drawEntropyStrip('viz-tfea', report.tfea_window_entropies);
    }

    // ── Markov ──
    _setText('stat-markov-bigram', fmt(report.markov_bigram_entropy));
    _setText('stat-markov-conditional', fmt(report.markov_conditional_entropy));
    _setText('stat-markov-density', fmt(report.markov_edge_density));
    _setText('stat-markov-pairs', fmtInt(report.markov_distinct_pairs));
    _setText('stat-markov-rowstd', fmt(report.markov_std_row_entropy));
    _setText('stat-markov-fp', fmtHex(report.markov_structural_fingerprint));

    // Markov sparkline — multi-bar comparison
    drawMultiBar('spark-markov',
      [report.markov_bigram_entropy || 0, report.markov_conditional_entropy || 0, report.markov_mean_row_entropy || 0],
      ['H₂', 'H|', 'H̄ᵣ'],
      { max: 8, colors: ['#818cf8', '#a78bfa', '#c4b5fd'] }
    );
    // Markov mini-viz — density heatmap strip (simplified)
    drawMultiBar('viz-markov',
      [report.markov_edge_density || 0, (report.markov_distinct_pairs || 0) / 65536, report.markov_std_row_entropy || 0],
      ['Density', 'Pairs', 'σ(H)'],
      { max: 1, colors: ['#22d3ee', '#818cf8', '#f59e0b'] }
    );

    // ── TCGE ──
    _setText('stat-tcge-nodes', fmtInt(report.tcge_node_count));
    _setText('stat-tcge-edges', fmtInt(report.tcge_edge_count));
    _setText('stat-tcge-backedge', fmtPct(report.tcge_back_edge_ratio));
    _setText('stat-tcge-scc', fmt(report.tcge_scc_ratio));
    _setText('stat-tcge-density', fmt(report.tcge_graph_density, 4));
    _setText('stat-tcge-cycles', fmtInt(report.tcge_cycle_count));

    // TCGE sparkline — topology metrics
    drawMultiBar('spark-tcge',
      [report.tcge_back_edge_ratio || 0, report.tcge_graph_density || 0, report.tcge_scc_ratio || 0],
      ['B/E', 'ρ', 'SCC'],
      { max: 1, colors: ['#ef4444', '#f59e0b', '#22d3ee'] }
    );
    // TCGE mini-viz — degree distribution
    drawMultiBar('viz-tcge',
      [report.tcge_avg_degree || 0, report.tcge_max_degree || 0, (report.tcge_connected_components || 0), (report.tcge_cycle_count || 0)],
      ['d̄', 'max', 'CC', '⟳'],
      { colors: ['#22d3ee', '#ef4444', '#818cf8', '#f59e0b'] }
    );

    // ── AISE ──
    _setText('stat-aise-intent', fmt(report.aise_composite_intent, 4));
    _setText('stat-aise-hits', fmtInt(report.aise_total_pattern_hits));
    _setText('stat-aise-cats', fmtInt(report.aise_unique_categories));
    _setText('stat-aise-shell', report.aise_shell_plus_decode ? '⚠ YES' : '—');
    _setText('stat-aise-netfs', report.aise_network_plus_filesystem ? '⚠ YES' : '—');
    _setText('stat-aise-eval', report.aise_eval_plus_obfuscation ? '⚠ YES' : '—');

    // AISE radial gauge
    drawRadialGauge('viz-aise', report.aise_composite_intent || 0);

    // AISE sparkline — intent category radar
    drawIntentRadar('spark-aise', [
      { label: 'Shell',  value: report.aise_shell_execution || 0 },
      { label: 'Eval',   value: report.aise_code_evaluation || 0 },
      { label: 'Decode', value: report.aise_data_decoding || 0 },
      { label: 'Net',    value: report.aise_network_communication || 0 },
      { label: 'FS',     value: report.aise_filesystem_manipulation || 0 },
      { label: 'Proc',   value: report.aise_process_control || 0 },
      { label: 'Cred',   value: report.aise_credential_access || 0 },
      { label: 'Obfusc', value: report.aise_obfuscation_indicator || 0 },
      { label: 'Persist',value: report.aise_persistence_mechanism || 0 },
      { label: 'Recon',  value: report.aise_information_gathering || 0 },
    ]);

    // Co-occurrence flag highlighting
    _setAnomaly('stat-aise-shell', report.aise_shell_plus_decode);
    _setAnomaly('stat-aise-netfs', report.aise_network_plus_filesystem);
    _setAnomaly('stat-aise-eval', report.aise_eval_plus_obfuscation);

    // ── CQSF ──
    _setText('stat-cqsf-anomaly', fmt(report.structural_anomaly_index, 1) + ' / 10');
    _setText('stat-cqsf-composite', fmtPct(report.composite_threat_score));
    _setText('stat-cqsf-confidence', fmtPct(report.quarantine_confidence));
    _setText('stat-cqsf-duration', fmt(report.pipeline_duration_ms, 1) + 'ms');
    _setText('stat-cqsf-type', report.tfea_declared_type != null ? String(report.tfea_declared_type) : '—');
    _setText('stat-cqsf-verdict', report.quarantine_verdict_name || '—');

    // CQSF composite gauge
    drawRadialGauge('viz-cqsf', report.composite_threat_score || 0);

    // Anomaly index highlighting
    if (report.structural_anomaly_index > 5) {
      _setAnomaly('stat-cqsf-anomaly', true);
    }

    // Populate HUD badges
    populateHUD(report);
  }

  function _setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function _setAnomaly(id, isAnomaly) {
    const el = document.getElementById(id);
    if (el) {
      if (isAnomaly) el.classList.add('anomaly');
      else el.classList.remove('anomaly');
    }
  }

  return { populate, drawSparkline, drawRadialGauge, drawEntropyStrip, drawMultiBar, drawIntentRadar };
})();
