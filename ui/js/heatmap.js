/**
 * shape-scan v2.0 — Entropy Heatmap Renderer
 *
 * Renders per-window Shannon entropy as a color strip.
 * Each pixel column = one entropy window.
 * Color: dark blue (0 bits) → blue → green → yellow → red (8 bits)
 */

const ShapeScanHeatmap = {

  // ─── State (for Focus Lens cross-linking) ───
  _lastWindows: null,
  _lastFileSize: 0,
  _lastCanvasId: null,

  /**
   * Render entropy heatmap to a canvas element.
   * @param {string} canvasId — ID of the canvas element
   * @param {number[]} windows — Per-window entropy values (0-8)
   * @param {number} [fileSize] — Total file size in bytes (for click → offset mapping)
   */
  render(canvasId, windows, fileSize) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !windows || windows.length === 0) return;

    // Store for Focus Lens cross-linking
    this._lastWindows = windows;
    this._lastFileSize = fileSize || 0;
    this._lastCanvasId = canvasId;

    const ctx = canvas.getContext('2d');
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    canvas.width  = w * (window.devicePixelRatio || 1);
    canvas.height = h * (window.devicePixelRatio || 1);
    ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);

    // Clear
    ctx.fillStyle = '#0a0c10';
    ctx.fillRect(0, 0, w, h);

    const numWindows = windows.length;
    const colWidth = Math.max(1, w / numWindows);

    for (let i = 0; i < numWindows; i++) {
      const x = (i / numWindows) * w;
      const entropy = windows[i];
      const color = this.entropyToColor(entropy);

      ctx.fillStyle = color;
      ctx.fillRect(Math.floor(x), 0, Math.ceil(colWidth) + 1, h);
    }

    // Optional: overlay thin grid lines for visual reference
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
    ctx.lineWidth = 1;
    for (let y = h * 0.25; y < h; y += h * 0.25) {
      ctx.beginPath();
      ctx.moveTo(0, Math.round(y) + 0.5);
      ctx.lineTo(w, Math.round(y) + 0.5);
      ctx.stroke();
    }

    // Bind click handler (once)
    this._bindClickHandler(canvas);
  },

  /**
   * Bind the click-to-inspect handler to the heatmap canvas.
   * Maps click X position → entropy window index → byte offset → FocusLens.
   */
  _bindClickHandler(canvas) {
    // Avoid duplicate listeners
    if (canvas._heatmapClickBound) return;
    canvas._heatmapClickBound = true;

    canvas.addEventListener('click', (e) => {
      if (!this._lastWindows || this._lastWindows.length === 0) return;
      if (!this._lastFileSize) return;
      if (typeof FocusLens === 'undefined') return;
      if (typeof currentPath === 'undefined' || !currentPath) return;

      const rect = canvas.getBoundingClientRect();
      const clickX = e.clientX - rect.left;
      const canvasW = rect.width;

      // Map click position to window index
      const windowIdx = Math.floor((clickX / canvasW) * this._lastWindows.length);
      const clampedIdx = Math.max(0, Math.min(windowIdx, this._lastWindows.length - 1));

      // Compute byte offset from window index
      const windowSize = Math.ceil(this._lastFileSize / this._lastWindows.length);
      const byteOffset = clampedIdx * windowSize;
      // Show a region spanning a few windows for context
      const lensSize = Math.min(windowSize * 4, 4096);

      FocusLens.show(currentPath, byteOffset, lensSize);
    });
  },

  /**
   * Map entropy value (0-8) to an RGB color string.
   * Uses a perceptually-tuned gradient:
   *   0   → deep navy     (low entropy, structured)
   *   2   → blue
   *   4   → green          (medium entropy, normal code)
   *   5.5 → yellow
   *   7   → orange-red     (high entropy, compressed/encrypted)
   *   8   → deep red       (maximum entropy)
   */
  entropyToColor(h) {
    const t = Math.max(0, Math.min(1, h / 8.0));

    // Color stops
    const stops = [
      { pos: 0.000, r: 0x1a, g: 0x23, b: 0x7e },  // deep navy
      { pos: 0.250, r: 0x15, g: 0x65, b: 0xc0 },  // blue
      { pos: 0.450, r: 0x21, g: 0x96, b: 0xf3 },  // bright blue
      { pos: 0.550, r: 0x4c, g: 0xaf, b: 0x50 },  // green
      { pos: 0.700, r: 0xff, g: 0xeb, b: 0x3b },  // yellow
      { pos: 0.850, r: 0xff, g: 0x98, b: 0x00 },  // orange
      { pos: 0.925, r: 0xf4, g: 0x43, b: 0x36 },  // red
      { pos: 1.000, r: 0xb7, g: 0x1c, b: 0x1c },  // deep red
    ];

    // Find surrounding stops
    let lo = stops[0];
    let hi = stops[stops.length - 1];
    for (let i = 0; i < stops.length - 1; i++) {
      if (t >= stops[i].pos && t <= stops[i + 1].pos) {
        lo = stops[i];
        hi = stops[i + 1];
        break;
      }
    }

    const range = hi.pos - lo.pos;
    const frac  = range > 0 ? (t - lo.pos) / range : 0;

    const r = Math.round(lo.r + (hi.r - lo.r) * frac);
    const g = Math.round(lo.g + (hi.g - lo.g) * frac);
    const b = Math.round(lo.b + (hi.b - lo.b) * frac);

    return `rgb(${r}, ${g}, ${b})`;
  }
};

