/**
 * shape-scan v2.0 — Application Logic (Phase 2)
 *
 * Handles scan invocation via Tauri IPC and orchestrates all
 * visualization subsystems: verdict, heatmap, dual-viewport,
 * component dashboard, and detail lens.
 *
 * The Semantic Firewall is enforced: only numeric data from
 * TEMReport crosses the IPC boundary.
 */

// ─── Tauri IPC ───
const { invoke } = window.__TAURI__.core;

// ─── DOM References ───
const filePathInput    = document.getElementById('file-path-input');
const scanBtn          = document.getElementById('scan-btn');
const browseBtn        = document.getElementById('browse-btn');
const scanStatus       = document.getElementById('scan-status');
const resultsContainer = document.getElementById('results-container');

const verdictBanner    = document.getElementById('verdict-banner');
const verdictIcon      = document.getElementById('verdict-icon');
const verdictLabel     = document.getElementById('verdict-label');
const resultSize       = document.getElementById('result-size');
const resultHash       = document.getElementById('result-hash');
const resultDuration   = document.getElementById('result-duration');
const confidenceValue  = document.getElementById('confidence-value');

const scoreEntropy     = document.getElementById('score-entropy');
const scoreTopology    = document.getElementById('score-topology');
const scoreIntent      = document.getElementById('score-intent');
const scoreComposite   = document.getElementById('score-composite');
const scoreEntropyVal  = document.getElementById('score-entropy-val');
const scoreTopologyVal = document.getElementById('score-topology-val');
const scoreIntentVal   = document.getElementById('score-intent-val');
const scoreCompositeVal= document.getElementById('score-composite-val');

const detectionFlags   = document.getElementById('detection-flags');
const flagBackdoor     = document.getElementById('flag-backdoor');
const flagDropper      = document.getElementById('flag-dropper');
const flagWebshell     = document.getElementById('flag-webshell');
const flagMismatch     = document.getElementById('flag-mismatch');

const heatmapMeta      = document.getElementById('heatmap-meta');
const fingerprintValue = document.getElementById('fingerprint-value');

// ─── Verdict Mapping ───
const VERDICT_MAP = {
  0: { label: 'CLEAR',      icon: '✓', cls: 'clear',      color: '#2ecc71' },
  1: { label: 'MONITOR',    icon: '⚡', cls: 'monitor',    color: '#f59e0b' },
  2: { label: 'QUARANTINE', icon: '✗', cls: 'quarantine', color: '#ef4444' },
  3: { label: 'DESTROY',    icon: '☠', cls: 'destroy',    color: '#c0392b' },
};

// ─── State ───
let currentPath = '';
let isScanning  = false;
let lastReport  = null;

// ─── Event Handlers ───
scanBtn.addEventListener('click', () => startScan());
filePathInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') startScan();
});

// Browse: open native file dialog, populate input, auto-scan
browseBtn.addEventListener('click', async () => {
  if (isScanning) return;
  browseBtn.classList.add('loading');
  try {
    const selected = await invoke('browse_file');
    if (selected) {
      filePathInput.value = selected;
      startScan();
    }
  } catch (err) {
    console.warn('Browse error:', err);
  } finally {
    browseBtn.classList.remove('loading');
  }
});

// Viewport reset button
document.getElementById('viewport-reset-btn')?.addEventListener('click', () => {
  if (typeof ViewportControls !== 'undefined') ViewportControls.resetCamera();
});

// ─── Scan Status Helpers ───
function setScanPhase(phase) {
  scanStatus.classList.remove('hidden', 'error');
  scanStatus.classList.add('scanning');
  scanStatus.innerHTML = `<span class="scan-spinner"></span><span class="scan-phase">${phase}</span>`;
}

function setScanButton(scanning) {
  scanBtn.disabled = scanning;
  if (scanning) {
    scanBtn.classList.add('scanning');
    scanBtn.innerHTML = `<span class="scan-spinner btn-spinner"></span><span class="btn-text">Scanning</span>`;
  } else {
    scanBtn.classList.remove('scanning');
    scanBtn.innerHTML = `<span class="btn-icon">◈</span><span class="btn-text">Scan</span>`;
  }
}

// ─── Scan Orchestration ───
async function startScan() {
  const path = filePathInput.value.trim();
  if (!path || isScanning) return;

  isScanning  = true;
  currentPath = path;
  resultsContainer.classList.add('hidden');

  setScanButton(true);
  setScanPhase('Reading file...');

  try {
    const startTime = performance.now();

    // Phase 1: Full pipeline scan
    setScanPhase('Analyzing entropy + topology + intent...');
    const report = await invoke('scan_file', { path });
    lastReport = report;
    const duration = (performance.now() - startTime).toFixed(1);

    // Phase 2: Render verdict + score bars
    setScanPhase('Rendering verdict...');
    renderVerdict(report, duration);

    // Phase 2.5: Generate analysis brief (context-aware narrative)
    setScanPhase('Generating analysis brief...');
    if (typeof AnalysisBrief !== 'undefined') {
      AnalysisBrief.populate(report);
    }

    // Phase 3: Component dashboard (populated from TEMReport)
    setScanPhase('Populating component dashboard...');
    if (typeof ComponentDashboard !== 'undefined') {
      ComponentDashboard.populate(report);
    }

    // Phase 4: Entropy heatmap
    setScanPhase('Building entropy heatmap...');
    await renderEntropyHeatmap(path);

    // Unhide results BEFORE rendering geometry so containers have dimensions
    resultsContainer.classList.remove('hidden');
    scanStatus.classList.add('hidden');
    scanStatus.classList.remove('scanning');

    // Yield a frame so the browser computes layout (clientWidth/clientHeight)
    await new Promise(resolve => requestAnimationFrame(resolve));

    // Phase 5: Initialize render swap (must init before geometry registers renders)
    if (typeof RenderSwap !== 'undefined') {
      RenderSwap.init();
    }

    // Phase 6: 3D Geometry viewports (results already visible — no status needed)
    await setupGeometryViewports(path);

    // Phase 7: Auto-save to SQLite (Step 5 — non-blocking)
    try {
      await invoke('save_scan', {
        timestamp: report.analysis_timestamp,
        shaPrefix: report.file_sha256_prefix,
        fileSize: report.file_size,
        verdict: report.quarantine_verdict,
        confidence: report.quarantine_confidence,
        compositeScore: report.composite_threat_score,
        meanEntropy: report.tfea_mean_entropy,
        intentScore: report.aise_composite_intent,
        reportJson: JSON.stringify(report),
      });
      await refreshScanHistory();
    } catch (dbErr) {
      console.warn('Scan persistence error (non-fatal):', dbErr);
    }

  } catch (err) {
    scanStatus.classList.remove('hidden', 'scanning');
    scanStatus.classList.add('error');
    scanStatus.innerHTML = `<span class="scan-phase">✗ ${err}</span>`;
  } finally {
    isScanning = false;
    setScanButton(false);
  }
}

// ─── Verdict Rendering ───
function renderVerdict(report, duration) {
  const v = VERDICT_MAP[report.quarantine_verdict] || VERDICT_MAP[0];

  verdictBanner.className = `verdict-banner glass-panel ${v.cls}`;
  verdictIcon.textContent = v.icon;
  verdictIcon.style.color = v.color;
  verdictLabel.textContent = v.label;
  verdictLabel.style.color = v.color;

  resultSize.textContent = report.file_size.toLocaleString();
  resultHash.textContent = '0x' + BigInt(report.file_sha256_prefix).toString(16).padStart(16, '0');
  resultDuration.textContent = duration;

  const conf = (report.quarantine_confidence * 100).toFixed(0);
  confidenceValue.textContent = `${conf}%`;

  animateScore(scoreEntropy,   scoreEntropyVal,   report.entropy_threat_score);
  animateScore(scoreTopology,  scoreTopologyVal,  report.topology_threat_score);
  animateScore(scoreIntent,    scoreIntentVal,    report.intent_threat_score);
  animateScore(scoreComposite, scoreCompositeVal, report.composite_threat_score);

  const hasFlags = report.backdoor_pattern_detected || report.dropper_pattern_detected ||
                   report.webshell_pattern_detected || report.header_mismatch_detected;
  if (hasFlags) {
    detectionFlags.classList.remove('hidden');
    toggleFlag(flagBackdoor, report.backdoor_pattern_detected);
    toggleFlag(flagDropper,  report.dropper_pattern_detected);
    toggleFlag(flagWebshell, report.webshell_pattern_detected);
    toggleFlag(flagMismatch, report.header_mismatch_detected);
  } else {
    detectionFlags.classList.add('hidden');
  }

  fingerprintValue.textContent = '0x' + BigInt(report.markov_structural_fingerprint).toString(16).padStart(16, '0');
}

function animateScore(barEl, labelEl, value) {
  const pct = Math.min(100, Math.max(0, value * 100));
  requestAnimationFrame(() => {
    barEl.style.width = `${pct}%`;
    barEl.style.backgroundPosition = `${100 - pct}% 0`;
  });
  labelEl.textContent = `${pct.toFixed(1)}%`;
}

function toggleFlag(el, show) {
  if (show) el.classList.remove('hidden');
  else el.classList.add('hidden');
}

// ─── Entropy Heatmap ───
async function renderEntropyHeatmap(path) {
  try {
    const windows = await invoke('get_entropy_windows', { path });
    heatmapMeta.textContent = `${windows.length} windows`;
    ShapeScanHeatmap.render('entropy-heatmap', windows, lastReport ? lastReport.file_size : 0);
  } catch (err) {
    console.warn('Heatmap error:', err);
    heatmapMeta.textContent = 'unavailable';
  }
}

// ─── 3D Geometry Viewports ───
// Default State (per Spec 2C.1):
//   Primary   = Superformula Mugshot (Step 2B)
//   Thumbnail = Toroidal Fingerprint (Step 2A)
//   Graph     = independent panel (Step 3)
async function setupGeometryViewports(path) {
  const primarySlot = document.getElementById('viewport-primary');
  const thumbSlot   = document.getElementById('viewport-thumb');
  const loading     = document.getElementById('viewport-loading');

  if (!primarySlot || !thumbSlot) return;

  loading?.classList.remove('hidden');

  try {
    // Fetch data for all views
    const [markovMatrix, graphData] = await Promise.all([
      invoke('get_markov_matrix', { path }),
      invoke('get_graph_data', { path }),
    ]);

    // PRIMARY VIEWPORT: Superformula Morphological Mugshot (Step 2B)
    if (typeof MorphologyEngine !== 'undefined' && lastReport) {
      MorphologyEngine.render('viewport-primary', lastReport, markovMatrix);
    } else if (typeof ShapeScanGraph !== 'undefined') {
      // Fallback: causal graph if superformula unavailable
      ShapeScanGraph.render('viewport-primary', graphData);
    }

    // THUMBNAIL VIEWPORT: Toroidal Markov Fingerprint (Step 2A)
    if (typeof MarkovTorus !== 'undefined') {
      MarkovTorus.render('viewport-thumb', markovMatrix, lastReport);
    } else if (typeof ShapeScanMarkov !== 'undefined') {
      ShapeScanMarkov.render('viewport-thumb', markovMatrix);
    }

    // Register both renders with swap system (Step 2C)
    if (typeof RenderSwap !== 'undefined') {
      const morphState = (typeof MorphologyEngine !== 'undefined') && MorphologyEngine.getRenderState();
      const markovState = (typeof MarkovTorus !== 'undefined') && MarkovTorus.getRenderState();
      if (morphState) RenderSwap.registerRender('morphology', morphState);
      if (markovState) RenderSwap.registerRender('markov', markovState);
    }

    // GRAPH PANEL: Causal Structure Graph (Step 3 — independent canvas)
    const graphContainer = document.getElementById('graph-container');
    if (graphContainer && typeof ShapeScanGraph !== 'undefined' && graphData) {
      ShapeScanGraph.render('graph-container', graphData);
      // Update graph metadata
      const graphMeta = document.getElementById('graph-meta');
      if (graphMeta) {
        const layout = (graphData.nodes.length <= 512 && graphData.nodes.length >= 4)
          ? 'Spectral' : 'Force-directed';
        graphMeta.textContent = `${graphData.nodes.length} nodes · ${graphData.links.length} edges · ${layout}`;
      }
    }
  } catch (err) {
    console.warn('Geometry error:', err);
  }

  loading?.classList.add('hidden');
}

// ─── Graph Panel Toggle ───
document.addEventListener('DOMContentLoaded', () => {
  const toggleBtn = document.getElementById('graph-toggle-btn');
  const graphContainer = document.getElementById('graph-container');
  if (toggleBtn && graphContainer) {
    toggleBtn.addEventListener('click', () => {
      graphContainer.classList.toggle('collapsed');
      toggleBtn.textContent = graphContainer.classList.contains('collapsed') ? '▶' : '▼';
    });
  }

  // History panel toggle
  const histToggle = document.getElementById('history-toggle-btn');
  const histList = document.getElementById('history-list');
  if (histToggle && histList) {
    histToggle.addEventListener('click', () => {
      histList.classList.toggle('collapsed');
      histToggle.textContent = histList.classList.contains('collapsed') ? '▶' : '▼';
    });
  }

  // Load history on startup
  refreshScanHistory();

  // Focus Lens close button (Step 2D)
  const lensCloseBtn = document.getElementById('detail-lens-close');
  if (lensCloseBtn) {
    lensCloseBtn.addEventListener('click', () => {
      if (typeof FocusLens !== 'undefined') FocusLens.hide();
    });
  }

  // Analysis Brief toggle
  const briefToggle = document.getElementById('brief-toggle-btn');
  const briefContent = document.getElementById('brief-content');
  if (briefToggle && briefContent) {
    briefToggle.addEventListener('click', () => {
      briefContent.classList.toggle('collapsed');
      briefToggle.textContent = briefContent.classList.contains('collapsed') ? '▶' : '▼';
    });
  }
});

// ─── Scan History (Step 5) ───
const VERDICT_ICONS = { 0: '✔', 1: '◉', 2: '⚠', 3: '☢' };
const VERDICT_CLASSES = { 0: 'hist-clear', 1: 'hist-monitor', 2: 'hist-quarantine', 3: 'hist-destroy' };

async function refreshScanHistory() {
  const histList = document.getElementById('history-list');
  const histCount = document.getElementById('history-count');
  if (!histList) return;

  try {
    const scans = await invoke('list_scans', { limit: 25 });
    if (histCount) histCount.textContent = `${scans.length} scans`;

    if (scans.length === 0) {
      histList.innerHTML = '<div class="history-empty">No scan history yet</div>';
      return;
    }

    histList.innerHTML = scans.map(s => {
      const icon = VERDICT_ICONS[s.quarantine_verdict] || '?';
      const cls = VERDICT_CLASSES[s.quarantine_verdict] || '';
      const sha = '0x' + BigInt(s.file_sha256_prefix).toString(16).padStart(16, '0').slice(0, 10);
      const entropy = s.tfea_mean_entropy.toFixed(2);
      const threat = (s.composite_threat_score * 100).toFixed(0);
      const size = s.file_size > 1024*1024
        ? (s.file_size / (1024*1024)).toFixed(1) + ' MB'
        : s.file_size > 1024
          ? (s.file_size / 1024).toFixed(1) + ' KB'
          : s.file_size + ' B';
      const time = new Date(s.timestamp * 1000).toLocaleString();

      return `<div class="history-row ${cls}" data-scan-id="${s.id}">
        <span class="history-verdict">${icon}</span>
        <span class="history-sha">${sha}</span>
        <span class="history-size">${size}</span>
        <span class="history-entropy">H̄ ${entropy}</span>
        <span class="history-threat">${threat}%</span>
        <span class="history-time">${time}</span>
      </div>`;
    }).join('');
  } catch (err) {
    console.warn('History load error:', err);
  }
}
