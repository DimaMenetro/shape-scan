/**
 * shape-scan v2.0 — Focus Lens Renderer (Step 2D)
 *
 * 2.5D isometric wireframe heightmap for byte-range detail inspection.
 * Activated by clicking on entropy heatmap spikes or causal graph nodes.
 *
 * Architecture:
 *   - Fetches byte data via `get_byte_range_detail` IPC (max 4096 bytes)
 *   - Renders isometric wireframe where each byte = one column
 *   - Height = byte value (0-255), color = rolling Shannon entropy
 *   - Filled gradient terrain with grid overlay
 *   - Hex-formatted axis labels for forensic readability
 *
 * Design tokens: DS-001-G-D-LGT Liquid Glass (dark mode palette)
 *
 * Usage:
 *   FocusLens.show(path, offset, size)  — fetch + render + reveal panel
 *   FocusLens.hide()                     — dismiss panel
 */

const FocusLens = {

  // ─── State ───
  _currentPath: null,
  _currentOffset: 0,
  _currentLength: 0,
  _isVisible: false,

  // ─── Design Tokens (DS-001 dark palette) ───
  COLORS: {
    bgDeep:       '#0a0c10',
    gridLine:     'rgba(148, 163, 184, 0.06)',
    gridLineHi:   'rgba(148, 163, 184, 0.12)',
    axisLabel:    'rgba(148, 163, 184, 0.55)',
    axisValue:    '#67e8f9',         // --text-mono
    wireDefault:  '#22d3ee',         // --wire-primary
    wireLow:      '#1e40af',         // --heat-low
    wireMid:      '#22d3ee',         // cyan
    wireWarm:     '#f59e0b',         // --heat-mid / amber
    wireHot:      '#ef4444',         // --heat-high / red
    fillAlpha:    0.12,
    zoneMarker:   'rgba(239, 68, 68, 0.08)',
    zoneStroke:   'rgba(239, 68, 68, 0.25)',
    zeroline:     'rgba(34, 211, 238, 0.15)',
  },

  // ─── Layout Constants ───
  MARGIN: { top: 22, right: 14, bottom: 30, left: 52 },

  // ═══════════════════════════════════════════════════
  // Public API
  // ═══════════════════════════════════════════════════

  /**
   * Show the focus lens for a specific byte range.
   * @param {string}  path   — file path (for IPC fetch)
   * @param {number}  offset — byte offset into the file
   * @param {number}  size   — number of bytes to inspect (capped at 4096 by backend)
   */
  async show(path, offset, size) {
    this._currentPath = path;
    this._currentOffset = offset;
    this._currentLength = Math.min(size, 4096);

    const panel = document.getElementById('detail-lens-panel');
    const rangeLabel = document.getElementById('detail-lens-range');
    const canvas = document.getElementById('detail-lens-canvas');
    if (!panel || !canvas) return;

    // Update range label with hex offsets
    const endOffset = offset + this._currentLength;
    if (rangeLabel) {
      rangeLabel.textContent =
        `0x${offset.toString(16).toUpperCase().padStart(8, '0')} — ` +
        `0x${endOffset.toString(16).toUpperCase().padStart(8, '0')} ` +
        `(${this._currentLength.toLocaleString()} bytes)`;
    }

    // Reveal panel (triggers CSS slide-in animation)
    panel.classList.remove('hidden');
    this._isVisible = true;

    // Scroll panel into view smoothly
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    // Fetch byte data via IPC
    try {
      const { invoke } = window.__TAURI__.core;
      const detail = await invoke('get_byte_range_detail', {
        path,
        offset,
        length: this._currentLength,
      });

      if (detail && detail.bytes && detail.bytes.length > 0) {
        this._render(canvas, detail);
      } else {
        this._renderEmpty(canvas, 'No data in range');
      }
    } catch (err) {
      console.warn('[FocusLens] IPC error:', err);
      this._renderEmpty(canvas, 'Fetch error');
    }
  },

  /**
   * Hide the focus lens panel.
   */
  hide() {
    const panel = document.getElementById('detail-lens-panel');
    if (panel) panel.classList.add('hidden');
    this._isVisible = false;
  },

  // ═══════════════════════════════════════════════════
  // Core Renderer
  // ═══════════════════════════════════════════════════

  /**
   * Render the 2.5D wireframe heightmap.
   * @param {HTMLCanvasElement} canvas
   * @param {ByteRangeDetail}   detail — { bytes, offset, length, rolling_entropy }
   */
  _render(canvas, detail) {
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;

    // Size canvas to container, DPR-aware
    const cssW = canvas.clientWidth;
    const cssH = canvas.clientHeight;
    canvas.width = cssW * dpr;
    canvas.height = cssH * dpr;
    ctx.scale(dpr, dpr);

    const { bytes, offset, rolling_entropy } = detail;
    const n = bytes.length;
    if (n === 0) return this._renderEmpty(canvas, 'Empty range');

    const M = this.MARGIN;
    const drawW = cssW - M.left - M.right;
    const drawH = cssH - M.top - M.bottom;

    // ─── Clear ───
    ctx.fillStyle = this.COLORS.bgDeep;
    ctx.fillRect(0, 0, cssW, cssH);

    // ─── Subsample if too many bytes for pixel resolution ───
    // Each byte needs at least 1 pixel; for very large ranges, subsample
    const maxPoints = Math.min(n, Math.floor(drawW));
    const step = n / maxPoints;

    // Build screen-space point array
    const points = [];
    for (let i = 0; i < maxPoints; i++) {
      const srcIdx = Math.min(Math.floor(i * step), n - 1);
      const byteVal = bytes[srcIdx];
      const entropy = rolling_entropy[srcIdx] || 0;

      const x = M.left + (i / (maxPoints - 1 || 1)) * drawW;
      // Height: byte value maps linearly to drawable height
      // 0x00 = bottom, 0xFF = top
      const yNorm = byteVal / 255;
      const y = M.top + drawH - yNorm * drawH * 0.92;
      // Slight isometric X-shift for depth illusion
      const xShift = yNorm * 2.5;

      points.push({
        x: x + xShift,
        y,
        byteVal,
        entropy,
        srcIdx,
        fileOffset: offset + srcIdx,
      });
    }

    // ─── Draw Y-axis grid lines ───
    this._drawGrid(ctx, cssW, cssH, drawW, drawH, M, offset, n);

    // ─── Draw high-entropy zone markers ───
    this._drawEntropyZones(ctx, points, drawH, M);

    // ─── Draw filled terrain ───
    this._drawFilledTerrain(ctx, points, cssH, M);

    // ─── Draw wireframe path ───
    this._drawWirePath(ctx, points);

    // ─── Draw byte dots at key positions ───
    this._drawByteMarkers(ctx, points);

    // ─── Draw axis labels ───
    this._drawAxisLabels(ctx, cssW, cssH, drawW, drawH, M, offset, n);
  },

  // ═══════════════════════════════════════════════════
  // Sub-Renderers
  // ═══════════════════════════════════════════════════

  /**
   * Draw background grid lines (horizontal for byte values, vertical for offsets).
   */
  _drawGrid(ctx, cssW, cssH, drawW, drawH, M, offset, numBytes) {
    ctx.lineWidth = 0.5;

    // Horizontal grid lines at 0x00, 0x40, 0x80, 0xC0, 0xFF
    const ySteps = [0, 0.25, 0.5, 0.75, 1.0];
    for (const frac of ySteps) {
      const y = M.top + drawH - frac * drawH * 0.92;
      ctx.strokeStyle = frac === 0 ? this.COLORS.zeroline : this.COLORS.gridLine;
      ctx.beginPath();
      ctx.moveTo(M.left, y);
      ctx.lineTo(M.left + drawW, y);
      ctx.stroke();
    }

    // Vertical grid lines — adaptive spacing
    const numVLines = Math.min(16, Math.floor(drawW / 40));
    ctx.strokeStyle = this.COLORS.gridLine;
    for (let i = 1; i < numVLines; i++) {
      const x = M.left + (i / numVLines) * drawW;
      ctx.beginPath();
      ctx.moveTo(x, M.top);
      ctx.lineTo(x, M.top + drawH);
      ctx.stroke();
    }
  },

  /**
   * Mark regions where rolling entropy exceeds 6.5 bits (high entropy zones).
   */
  _drawEntropyZones(ctx, points, drawH, M) {
    const threshold = 6.5;
    let inZone = false;
    let zoneStart = 0;

    for (let i = 0; i <= points.length; i++) {
      const isHigh = i < points.length && points[i].entropy > threshold;

      if (isHigh && !inZone) {
        zoneStart = i;
        inZone = true;
      } else if (!isHigh && inZone) {
        // Draw zone band
        const x1 = points[zoneStart].x;
        const x2 = points[i - 1].x;
        ctx.fillStyle = this.COLORS.zoneMarker;
        ctx.fillRect(x1, M.top, x2 - x1 + 1, drawH);
        ctx.strokeStyle = this.COLORS.zoneStroke;
        ctx.lineWidth = 0.5;
        ctx.strokeRect(x1, M.top, x2 - x1 + 1, drawH);
        inZone = false;
      }
    }
  },

  /**
   * Filled gradient terrain below the wire path.
   */
  _drawFilledTerrain(ctx, points, cssH, M) {
    if (points.length < 2) return;

    const baseline = M.top + (cssH - M.top - M.bottom);

    ctx.beginPath();
    ctx.moveTo(points[0].x, baseline);
    for (const pt of points) {
      ctx.lineTo(pt.x, pt.y);
    }
    ctx.lineTo(points[points.length - 1].x, baseline);
    ctx.closePath();

    // Gradient fill from midpoint entropy color to transparent
    const avgEntropy = points.reduce((s, p) => s + p.entropy, 0) / points.length;
    const color = this._entropyToRGBA(avgEntropy, this.COLORS.fillAlpha);
    const grad = ctx.createLinearGradient(0, M.top, 0, baseline);
    grad.addColorStop(0, color);
    grad.addColorStop(1, 'rgba(10, 12, 16, 0)');
    ctx.fillStyle = grad;
    ctx.fill();
  },

  /**
   * Draw the main wireframe path connecting all byte positions.
   * Each segment colored by its local rolling entropy.
   */
  _drawWirePath(ctx, points) {
    if (points.length < 2) return;

    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';

    for (let i = 0; i < points.length - 1; i++) {
      const p0 = points[i];
      const p1 = points[i + 1];

      // Segment color from entropy midpoint
      const midEntropy = (p0.entropy + p1.entropy) / 2;
      ctx.strokeStyle = this._entropyToRGBA(midEntropy, 0.9);

      ctx.beginPath();
      ctx.moveTo(p0.x, p0.y);
      ctx.lineTo(p1.x, p1.y);
      ctx.stroke();
    }
  },

  /**
   * Small dots at every Nth byte position for structural emphasis.
   * High-entropy positions get larger, brighter dots.
   */
  _drawByteMarkers(ctx, points) {
    // Skip for very dense ranges — too many dots
    const dotInterval = Math.max(1, Math.floor(points.length / 80));

    for (let i = 0; i < points.length; i += dotInterval) {
      const pt = points[i];
      const isHot = pt.entropy > 6.5;
      const radius = isHot ? 2.5 : 1.5;

      ctx.fillStyle = this._entropyToRGBA(pt.entropy, isHot ? 1.0 : 0.7);
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, radius, 0, Math.PI * 2);
      ctx.fill();

      // Glow effect for high-entropy dots
      if (isHot) {
        ctx.fillStyle = this._entropyToRGBA(pt.entropy, 0.15);
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 5, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  },

  /**
   * Draw axis labels — hex offsets on X, byte values on Y.
   */
  _drawAxisLabels(ctx, cssW, cssH, drawW, drawH, M, offset, numBytes) {
    ctx.font = '9px "JetBrains Mono", "Cascadia Code", monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';

    // ─── X-axis: Byte offsets (hex) ───
    const numXLabels = Math.min(8, Math.floor(drawW / 80));
    ctx.fillStyle = this.COLORS.axisLabel;
    for (let i = 0; i <= numXLabels; i++) {
      const frac = i / numXLabels;
      const x = M.left + frac * drawW;
      const byteOff = offset + Math.floor(frac * numBytes);
      const label = '0x' + byteOff.toString(16).toUpperCase().padStart(6, '0');
      ctx.fillText(label, x, cssH - M.bottom + 6);
    }

    // ─── Y-axis: Byte values (hex) ───
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    const yLabels = [
      { val: 0x00, label: '0x00' },
      { val: 0x40, label: '0x40' },
      { val: 0x80, label: '0x80' },
      { val: 0xC0, label: '0xC0' },
      { val: 0xFF, label: '0xFF' },
    ];
    for (const { val, label } of yLabels) {
      const frac = val / 255;
      const y = M.top + drawH - frac * drawH * 0.92;
      ctx.fillStyle = this.COLORS.axisValue;
      ctx.fillText(label, M.left - 6, y);
    }

    // ─── Title label ───
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.font = '10px "JetBrains Mono", monospace';
    ctx.fillStyle = this.COLORS.axisLabel;
    ctx.fillText('BYTE VALUE', M.left, 4);

    ctx.textAlign = 'right';
    ctx.fillStyle = 'rgba(239, 68, 68, 0.4)';
    ctx.fillText('■ HIGH ENTROPY ZONE', cssW - M.right, 4);
  },

  // ═══════════════════════════════════════════════════
  // Empty / Error State
  // ═══════════════════════════════════════════════════

  _renderEmpty(canvas, message) {
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const cssW = canvas.clientWidth;
    const cssH = canvas.clientHeight;
    canvas.width = cssW * dpr;
    canvas.height = cssH * dpr;
    ctx.scale(dpr, dpr);

    ctx.fillStyle = this.COLORS.bgDeep;
    ctx.fillRect(0, 0, cssW, cssH);

    ctx.font = '12px "JetBrains Mono", monospace';
    ctx.fillStyle = this.COLORS.axisLabel;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(message, cssW / 2, cssH / 2);
  },

  // ═══════════════════════════════════════════════════
  // Color Helpers
  // ═══════════════════════════════════════════════════

  /**
   * Map entropy value (0-8 bits) to an RGBA color string.
   * Uses the same perceptual gradient as the heatmap for consistency.
   *
   * 0-3 bits   → cool blue/cyan (structured, low entropy)
   * 3-5 bits   → cyan/teal (normal code)
   * 5-6.5 bits → amber/warm (compressed/encoded)
   * 6.5-8 bits → red (encrypted/random — maximum entropy)
   */
  _entropyToRGBA(h, alpha) {
    const t = Math.max(0, Math.min(1, h / 8.0));

    let r, g, b;
    if (t < 0.375) {
      // Deep blue → Cyan
      const f = t / 0.375;
      r = Math.round(30 + f * 4);
      g = Math.round(64 + f * 147);
      b = Math.round(175 + f * 63);
    } else if (t < 0.625) {
      // Cyan → Amber
      const f = (t - 0.375) / 0.25;
      r = Math.round(34 + f * 211);
      g = Math.round(211 - f * 53);
      b = Math.round(238 - f * 227);
    } else if (t < 0.8125) {
      // Amber → Red
      const f = (t - 0.625) / 0.1875;
      r = Math.round(245 - f * 6);
      g = Math.round(158 - f * 90);
      b = Math.round(11 + f * 57);
    } else {
      // Red → Deep red
      const f = (t - 0.8125) / 0.1875;
      r = Math.round(239 - f * 56);
      g = Math.round(68 - f * 40);
      b = Math.round(68 - f * 40);
    }

    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  },
};
