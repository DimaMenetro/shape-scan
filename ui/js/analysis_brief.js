/**
 * analysis_brief.js — Context-Aware Forensic Narrative Engine
 * ════════════════════════════════════════════════════════════
 *
 * Transforms a raw TEMReport (58 numeric fields) into a structured,
 * human-readable forensic briefing. Designed for demonstration contexts
 * where non-technical audiences need to understand the significance
 * of the TEM pipeline's findings.
 *
 * Architecture:
 *   - Deterministic: same input → same output (no randomness, no AI)
 *   - Semantic Firewall: describes mathematical shapes, never raw bytes
 *   - Data Provenance: every displayed value traces to a TEMReport field
 *   - Dual-Mode Reading: scannable highlights (3s) + full narrative (30s)
 *
 * Public API:
 *   AnalysisBrief.populate(report)  — generate & render the briefing
 *   AnalysisBrief.clear()           — reset panel to empty state
 *
 * CP-002-O-D-JNP v2.0 — Janus SME Protocol
 * Inscribed by Kytheion (IC-004-R-D-KYN)
 */

const AnalysisBrief = (() => {
  'use strict';

  // ─── DOM References ───
  const _el = (id) => document.getElementById(id);

  // ─── Verdict Metadata ───
  const VERDICT_META = {
    0: { name: 'CLEAR',      icon: '✔', cls: 'brief-clear',      color: 'var(--verdict-clear)' },
    1: { name: 'MONITOR',    icon: '◉', cls: 'brief-monitor',    color: 'var(--verdict-monitor)' },
    2: { name: 'QUARANTINE', icon: '⚠', cls: 'brief-quarantine', color: 'var(--verdict-quarantine)' },
    3: { name: 'DESTROY',    icon: '☢', cls: 'brief-destroy',    color: 'var(--verdict-destroy)' },
  };

  // ─── Intent Dimension Labels (human-readable) ───
  const INTENT_LABELS = {
    aise_shell_execution:        'Shell Execution',
    aise_code_evaluation:        'Code Evaluation',
    aise_data_decoding:          'Data Decoding',
    aise_network_communication:  'Network Communication',
    aise_filesystem_manipulation:'Filesystem Manipulation',
    aise_process_control:        'Process Control',
    aise_credential_access:      'Credential Access',
    aise_obfuscation_indicator:  'Obfuscation',
    aise_persistence_mechanism:  'Persistence Mechanism',
    aise_information_gathering:  'Information Gathering',
  };

  // ─── Formatting Helpers ───
  function _fmt(n, decimals = 2) {
    if (n === undefined || n === null || isNaN(n)) return '—';
    return Number(n).toFixed(decimals);
  }

  function _pct(n) {
    if (n === undefined || n === null || isNaN(n)) return '—';
    return (Number(n) * 100).toFixed(1) + '%';
  }

  function _fmtSize(bytes) {
    if (bytes > 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    if (bytes > 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return bytes + ' B';
  }

  /** Wraps a value in a highlighted mono span */
  function _val(text) {
    return `<span class="brief-val">${text}</span>`;
  }

  // ════════════════════════════════════════════════════════
  // Section Generators
  // ════════════════════════════════════════════════════════

  /**
   * §1 — Executive Summary
   * Answers: "What did you find?"
   */
  function _executive(r) {
    const v = VERDICT_META[r.quarantine_verdict] || VERDICT_META[0];
    const conf = (r.quarantine_confidence * 100).toFixed(0);
    const composite = (r.composite_threat_score * 100).toFixed(1);

    let narrative = '';

    if (r.quarantine_verdict === 0) {
      narrative = `This file's mathematical shape is consistent with legitimate content. `
        + `No structural, topological, or behavioral anomalies were detected across the `
        + `four-module analysis pipeline. The composite threat score of ${_val(composite + '%')} `
        + `falls well within expected parameters for benign files. `
        + `Confidence: ${_val(conf + '%')}.`;
    } else if (r.quarantine_verdict === 1) {
      narrative = `This file exhibits characteristics that warrant continued observation. `
        + `While no definitive threat indicators were identified, one or more pipeline modules `
        + `registered elevated scores resulting in a composite threat assessment of ${_val(composite + '%')}. `
        + `The anomalies detected are not conclusive but deviate from expected baselines. `
        + `Confidence: ${_val(conf + '%')}.`;
    } else if (r.quarantine_verdict === 2) {
      narrative = `Significant structural anomalies detected. The file's entropy distribution, `
        + `control flow topology, and behavioral pattern signatures indicate characteristics `
        + `consistent with adversarial modification or obfuscation. `
        + `Composite threat score: ${_val(composite + '%')}. `
        + `This file has been flagged for isolation pending further review. `
        + `Confidence: ${_val(conf + '%')}.`;
    } else {
      narrative = `Critical threat profile identified. Multiple pipeline modules report extreme `
        + `anomalies with a composite threat score of ${_val(composite + '%')}. `
        + `The mathematical fingerprint of this file is strongly inconsistent with any legitimate `
        + `file structure in the training corpus. Immediate containment recommended. `
        + `Confidence: ${_val(conf + '%')}.`;
    }

    return `<div class="brief-section brief-executive ${v.cls}">
      <div class="brief-section-header">
        <span class="brief-verdict-icon" style="color:${v.color}">${v.icon}</span>
        <h3 class="brief-section-title">Executive Summary</h3>
        <span class="brief-verdict-tag" style="color:${v.color}">${v.name}</span>
      </div>
      <p class="brief-text">${narrative}</p>
    </div>`;
  }

  /**
   * §2 — Entropy Profile
   * Answers: "What does the randomness distribution tell us?"
   */
  function _entropy(r) {
    const mean = r.tfea_mean_entropy;
    const maxE = r.tfea_max_entropy;
    const minE = r.tfea_min_entropy;
    const variance = r.tfea_entropy_variance;
    const highRatio = r.tfea_high_entropy_ratio;
    const comprRatio = r.tfea_compression_ratio;

    let findings = [];

    // Mean entropy contextualization
    if (mean > 7.5) {
      findings.push(
        `Mean entropy of ${_val(_fmt(mean) + ' bits/byte')} approaches the theoretical maximum of 8.0, `
        + `indicating the file content is encrypted, compressed, or randomized. `
        + `Natural code or text rarely exceeds 6.5 bits/byte.`
      );
    } else if (mean > 6.0) {
      findings.push(
        `Mean entropy of ${_val(_fmt(mean) + ' bits/byte')} is moderately elevated, consistent with `
        + `compiled binaries, compressed archives, or mixed-content files.`
      );
    } else if (mean > 4.0) {
      findings.push(
        `Mean entropy of ${_val(_fmt(mean) + ' bits/byte')} is within normal range for structured content `
        + `such as source code, configuration files, or document formats.`
      );
    } else {
      findings.push(
        `Mean entropy of ${_val(_fmt(mean) + ' bits/byte')} is low, indicating highly structured or `
        + `repetitive content with limited information density.`
      );
    }

    // Variance interpretation
    if (variance > 2.0) {
      findings.push(
        `Entropy variance of ${_val(_fmt(variance))} is significantly elevated, suggesting the file `
        + `contains heterogeneous sections — a mix of structured headers and encrypted or compressed payloads. `
        + `This pattern is commonly associated with packed executables or files with embedded encrypted content.`
      );
    } else if (variance > 0.5) {
      findings.push(
        `Entropy variance of ${_val(_fmt(variance))} indicates moderate internal structure variation, `
        + `consistent with files containing distinct sections (e.g., headers, data segments, metadata).`
      );
    } else {
      findings.push(
        `Entropy variance of ${_val(_fmt(variance))} is low, indicating uniform content distribution `
        + `throughout the file — a characteristic of single-purpose, non-obfuscated content.`
      );
    }

    // High-entropy ratio
    if (highRatio > 0.7) {
      findings.push(
        `${_val(_pct(highRatio))} of the file consists of high-entropy windows, meaning the majority `
        + `of the content approaches maximum randomness.`
      );
    }

    // Header mismatch
    if (r.tfea_header_mismatch) {
      findings.push(
        `<strong class="brief-alert">⚠ Header Mismatch Detected:</strong> The file's declared format does not match `
        + `its actual entropy profile (σ = ${_val(_fmt(r.tfea_mismatch_sigma))}). This discrepancy suggests `
        + `the file may be masquerading as a different type — a technique used to bypass content-based filters.`
      );
    }

    return `<div class="brief-section">
      <h3 class="brief-section-title">Entropy Profile</h3>
      <div class="brief-meta-row">
        <span>Range: ${_val(_fmt(minE))} — ${_val(_fmt(maxE))} bits/byte</span>
        <span>Compression Ratio: ${_val(_fmt(comprRatio, 3))}</span>
        <span>File Size: ${_val(_fmtSize(r.file_size))}</span>
      </div>
      ${findings.map(f => `<p class="brief-text">${f}</p>`).join('')}
    </div>`;
  }

  /**
   * §3 — Structural Topology
   * Answers: "What does the control flow tell us?"
   */
  function _topology(r) {
    const nodes = r.tcge_node_count;
    const edges = r.tcge_edge_count;
    const backEdgeRatio = r.tcge_back_edge_ratio;
    const cycles = r.tcge_cycle_count;
    const components = r.tcge_connected_components;
    const sccRatio = r.tcge_scc_ratio;
    const density = r.tcge_graph_density;

    let findings = [];

    // Overall complexity
    findings.push(
      `The structural graph contains ${_val(nodes)} nodes and ${_val(edges)} edges `
      + `with a graph density of ${_val(_fmt(density, 3))}. `
      + (components > 1
        ? `The graph decomposes into ${_val(components)} connected components, suggesting `
          + `the file contains multiple independent structural units.`
        : `The graph forms a single connected component, indicating a monolithic internal structure.`)
    );

    // Back-edge analysis
    if (backEdgeRatio > 0.3) {
      findings.push(
        `Back-edge ratio of ${_val(_pct(backEdgeRatio))} is significantly elevated, suggesting heavy use of `
        + `loops or self-modifying control flow — a common characteristic of obfuscated or packed code.`
      );
    } else if (backEdgeRatio > 0.1) {
      findings.push(
        `Back-edge ratio of ${_val(_pct(backEdgeRatio))} indicates moderate use of iterative constructs, `
        + `consistent with standard procedural logic.`
      );
    } else {
      findings.push(
        `Back-edge ratio of ${_val(_pct(backEdgeRatio))} is low, indicating primarily linear control flow `
        + `with minimal looping.`
      );
    }

    // Strongly connected components
    if (sccRatio > 0.4) {
      findings.push(
        `${_val(_pct(sccRatio))} of the graph exists within strongly connected components — `
        + `clusters of mutually reachable nodes. This elevated ratio suggests recursive or `
        + `self-referencing structures that may indicate obfuscation techniques.`
      );
    }

    // Cycle count
    if (cycles > 10) {
      findings.push(
        `${_val(cycles)} distinct cycles detected in the control flow graph. Excessive cycling `
        + `can indicate anti-analysis loops designed to impede static inspection.`
      );
    }

    return `<div class="brief-section">
      <h3 class="brief-section-title">Structural Topology</h3>
      ${findings.map(f => `<p class="brief-text">${f}</p>`).join('')}
    </div>`;
  }

  /**
   * §4 — Intent Signals
   * Answers: "What behavioral patterns were detected?"
   */
  function _intent(r) {
    const composite = r.aise_composite_intent;
    const totalHits = r.aise_total_pattern_hits;
    const categories = r.aise_unique_categories;

    let findings = [];

    // Overall intent
    if (composite > 0.6) {
      findings.push(
        `Composite intent score of ${_val(_pct(composite))} is elevated, indicating that `
        + `${_val(totalHits)} pattern matches were identified across ${_val(categories)} distinct `
        + `behavioral categories. The density and diversity of these signals suggest purposeful, `
        + `coordinated capability embedding.`
      );
    } else if (composite > 0.2) {
      findings.push(
        `Composite intent score of ${_val(_pct(composite))} indicates moderate behavioral signal density. `
        + `${_val(totalHits)} pattern matches detected across ${_val(categories)} categories. `
        + `These patterns may reflect legitimate functionality or low-level suspicious indicators.`
      );
    } else {
      findings.push(
        `Composite intent score of ${_val(_pct(composite))} is low. `
        + `${_val(totalHits)} total pattern matches across ${_val(categories)} categories — `
        + `consistent with minimal or absent behavioral intent signatures.`
      );
    }

    // Top intent dimensions (sorted by score, top 3)
    const dims = Object.entries(INTENT_LABELS)
      .map(([key, label]) => ({ key, label, score: r[key] || 0 }))
      .sort((a, b) => b.score - a.score);

    const top3 = dims.filter(d => d.score > 0.1).slice(0, 3);
    if (top3.length > 0) {
      const topList = top3.map(d =>
        `<span class="brief-intent-dim">${d.label}: ${_val(_pct(d.score))}</span>`
      ).join('');
      findings.push(`<div class="brief-intent-top">Dominant intent vectors: ${topList}</div>`);
    }

    // Compound pattern flags
    const compounds = [];
    if (r.aise_shell_plus_decode) {
      compounds.push('Shell Execution + Data Decoding — suggests staged payload delivery: decode, then execute.');
    }
    if (r.aise_network_plus_filesystem) {
      compounds.push('Network Communication + Filesystem Manipulation — suggests remote command-and-control with local persistence.');
    }
    if (r.aise_eval_plus_obfuscation) {
      compounds.push('Code Evaluation + Obfuscation — suggests dynamically constructed and hidden execution logic.');
    }

    if (compounds.length > 0) {
      findings.push(
        `<div class="brief-compounds"><strong class="brief-alert">Compound Patterns Detected:</strong><ul>`
        + compounds.map(c => `<li>${c}</li>`).join('')
        + `</ul></div>`
      );
    }

    return `<div class="brief-section">
      <h3 class="brief-section-title">Intent Analysis</h3>
      ${findings.map(f => `<p class="brief-text">${f}</p>`).join('')}
    </div>`;
  }

  /**
   * §5 — Threat Decomposition
   * Answers: "Which module raised the most concern?"
   */
  function _decomposition(r) {
    const entropy = r.entropy_threat_score;
    const topology = r.topology_threat_score;
    const intent = r.intent_threat_score;
    const total = entropy + topology + intent;

    // Determine dominant vector
    let dominant = 'Entropy';
    let dominantScore = entropy;
    if (topology > dominantScore) { dominant = 'Topology'; dominantScore = topology; }
    if (intent > dominantScore) { dominant = 'Intent'; dominantScore = intent; }

    const entropyPct = total > 0 ? ((entropy / total) * 100).toFixed(0) : 0;
    const topoPct = total > 0 ? ((topology / total) * 100).toFixed(0) : 0;
    const intentPct = total > 0 ? ((intent / total) * 100).toFixed(0) : 0;

    let narrative = '';
    if (total < 0.15) {
      narrative = `All three threat vectors report minimal signal. No single module identified `
        + `sufficient anomaly to drive the composite score into an actionable range.`;
    } else {
      narrative = `The dominant threat vector is ${_val(dominant)}, contributing `
        + `${_val(dominant === 'Entropy' ? entropyPct : dominant === 'Topology' ? topoPct : intentPct)}% `
        + `of the total threat signal. `;

      if (dominant === 'Entropy') {
        narrative += `This indicates the file's statistical randomness profile is the primary driver of concern.`;
      } else if (dominant === 'Topology') {
        narrative += `This indicates the file's structural control flow complexity is the primary driver of concern.`;
      } else {
        narrative += `This indicates detected behavioral pattern signatures are the primary driver of concern.`;
      }
    }

    return `<div class="brief-section">
      <h3 class="brief-section-title">Threat Decomposition</h3>
      <p class="brief-text">${narrative}</p>
      <div class="brief-bars">
        <div class="brief-bar-row">
          <span class="brief-bar-label">Entropy</span>
          <div class="brief-bar-track"><div class="brief-bar-fill brief-bar-entropy" style="width:${(entropy * 100).toFixed(1)}%"></div></div>
          <span class="brief-bar-val">${_pct(entropy)}</span>
        </div>
        <div class="brief-bar-row">
          <span class="brief-bar-label">Topology</span>
          <div class="brief-bar-track"><div class="brief-bar-fill brief-bar-topology" style="width:${(topology * 100).toFixed(1)}%"></div></div>
          <span class="brief-bar-val">${_pct(topology)}</span>
        </div>
        <div class="brief-bar-row">
          <span class="brief-bar-label">Intent</span>
          <div class="brief-bar-track"><div class="brief-bar-fill brief-bar-intent" style="width:${(intent * 100).toFixed(1)}%"></div></div>
          <span class="brief-bar-val">${_pct(intent)}</span>
        </div>
      </div>
    </div>`;
  }

  /**
   * §6 — Detection Flags
   * Answers: "Were specific threat patterns identified?"
   */
  function _flags(r) {
    const flags = [
      {
        key: 'backdoor_pattern_detected',
        label: 'Backdoor Pattern',
        desc: 'Structural signatures consistent with persistent unauthorized access mechanisms.',
      },
      {
        key: 'dropper_pattern_detected',
        label: 'Dropper Pattern',
        desc: 'Patterns suggesting the file may extract and deploy a secondary payload.',
      },
      {
        key: 'webshell_pattern_detected',
        label: 'Webshell Pattern',
        desc: 'Indicators of web-accessible command execution interfaces.',
      },
      {
        key: 'header_mismatch_detected',
        label: 'Header Mismatch',
        desc: 'File type declared in headers does not match actual content entropy profile.',
      },
    ];

    const active = flags.filter(f => r[f.key]);
    const inactive = flags.filter(f => !r[f.key]);

    if (active.length === 0) {
      return `<div class="brief-section">
        <h3 class="brief-section-title">Detection Flags</h3>
        <p class="brief-text">No specific threat pattern signatures were detected by the AISE module's `
        + `heuristic pattern matcher.</p>
        <div class="brief-flag-row">
          ${inactive.map(f => `<span class="brief-flag brief-flag-off" title="${f.desc}">${f.label}</span>`).join('')}
        </div>
      </div>`;
    }

    return `<div class="brief-section">
      <h3 class="brief-section-title">Detection Flags</h3>
      <div class="brief-flag-row">
        ${active.map(f =>
          `<span class="brief-flag brief-flag-on" title="${f.desc}">⚠ ${f.label}</span>`
        ).join('')}
        ${inactive.map(f =>
          `<span class="brief-flag brief-flag-off" title="${f.desc}">${f.label}</span>`
        ).join('')}
      </div>
      ${active.map(f => `<p class="brief-text brief-flag-detail"><strong>${f.label}:</strong> ${f.desc}</p>`).join('')}
    </div>`;
  }

  // ════════════════════════════════════════════════════════
  // Public API
  // ════════════════════════════════════════════════════════

  function populate(report) {
    const panel = _el('analysis-brief');
    const content = _el('brief-content');
    const timestamp = _el('brief-timestamp');
    if (!panel || !content) return;

    // Generate all sections
    const html = [
      _executive(report),
      _entropy(report),
      _topology(report),
      _intent(report),
      _decomposition(report),
      _flags(report),
    ].join('');

    content.innerHTML = html;

    // Update timestamp
    if (timestamp) {
      const dt = new Date(report.analysis_timestamp * 1000);
      timestamp.textContent = dt.toLocaleString();
    }

    // Reveal panel
    panel.classList.remove('hidden');
    // Trigger slide-in animation
    requestAnimationFrame(() => {
      panel.classList.add('brief-visible');
    });
  }

  function clear() {
    const panel = _el('analysis-brief');
    const content = _el('brief-content');
    if (panel) {
      panel.classList.add('hidden');
      panel.classList.remove('brief-visible');
    }
    if (content) content.innerHTML = '';
  }

  // ─── Expose ───
  return { populate, clear };
})();
