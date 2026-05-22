/**
 * shape-scan v2.0 — Superformula Morphology Engine (Step 2B)
 *
 * Renders the file's "Morphological Mugshot" — a 3D Gielis spherical product
 * surface whose shape is entirely driven by TEM analysis fields.
 *
 * The mugshot is the operator-facing categorical identity view. Unlike the
 * torus fingerprint (which shows microstructural Markov detail), the mugshot
 * should be immediately visually distinctive at a glance.
 *
 * Mathematical Foundation (Gielis Superformula):
 *   2D: r(θ) = [|cos(mθ/4)/a|^n₂ + |sin(mθ/4)/b|^n₃]^(-1/n₁)
 *   3D: Spherical product of two independent 2D evaluations
 *
 * TEM Parameter Bindings (3 Layers):
 *   Layer 1 (Macroscopic — TFEA):
 *     Shannon entropy    → m₁  (symmetry order)
 *     Entropy variance   → m₂  (vertical symmetry)
 *     Compression ratio  → a₁/a₂ (stretch)
 *     Structured fraction → n₁₁/n₂₁ (convexity)
 *   Layer 2 (Microscopic — Markov):
 *     Header mismatch    → bilateral asymmetry (a₁ ≠ a₂)
 *     Row entropy        → equatorial band coloring
 *   Layer 3 (Causal — AISE):
 *     Intent score       → crease angle / flat shading
 *     Intent score       → surface roughness amplification
 *
 * Confidence: [Experimental] — gated by C4 (six-class visual test)
 * Fallback: Torus fingerprint (Step 2A) remains fully functional.
 *
 * Uses Three.js (loaded via CDN in index.html).
 */

const MorphologyEngine = {

  // State
  _renderer: null,
  _scene: null,
  _camera: null,
  _mesh: null,
  _animationId: null,
  _autoRotate: true,
  _autoRotateRPM: 6,
  _container: null,

  // ─── Design Token Colors ───
  COLORS: {
    heatLow:     { r: 0x1e/255, g: 0x40/255, b: 0xaf/255 },
    heatMid:     { r: 0xf5/255, g: 0x9e/255, b: 0x0b/255 },
    heatHigh:    { r: 0xef/255, g: 0x44/255, b: 0x44/255 },
    wirePrimary: { r: 0x22/255, g: 0xd3/255, b: 0xee/255 },
    bgDeep:      { r: 0x0a/255, g: 0x0e/255, b: 0x17/255 },
    benign:      { r: 0x8b/255, g: 0x5c/255, b: 0xf6/255 },
    encrypted:   { r: 0xd9/255, g: 0x77/255, b: 0x06/255 },
  },

  // ─── Mesh Resolution ───
  GRID_THETA: 128,  // θ resolution (horizontal)
  GRID_PHI:   128,  // φ resolution (vertical)

  // ═══════════════════════════════════════════════════
  // Main Entry Point
  // ═══════════════════════════════════════════════════

  /**
   * Render the superformula mugshot into a container element.
   * @param {string}   containerId — DOM element ID for the viewport
   * @param {Object}   report      — Full TEMReport from IPC
   * @param {number[][]} [markovMatrix] — 256×256 probability matrix (optional, for band coloring)
   */
  render(containerId, report, markovMatrix) {
    const container = document.getElementById(containerId);
    if (!container || !report) return;

    this.cleanup();
    this._container = container;

    const w = container.clientWidth;
    const h = container.clientHeight;
    if (w === 0 || h === 0) return;

    // ─── Derive superformula parameters from TEMReport ───
    const params = this._deriveParameters(report);

    // ─── Compute per-row Markov entropy for band coloring ───
    const rowEntropies = markovMatrix
      ? this._computeRowEntropies(markovMatrix)
      : null;

    // ─── Three.js Scene Setup ───
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(
      this.COLORS.bgDeep.r, this.COLORS.bgDeep.g, this.COLORS.bgDeep.b
    );

    const camera = new THREE.PerspectiveCamera(45, w / h, 0.1, 100);
    camera.position.set(0, 1.2, 4.0);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    renderer.setSize(w, h);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    // Re-add viewport label
    const label = document.createElement('span');
    label.className = 'viewport-label';
    label.textContent = 'Morphological Mugshot';
    container.appendChild(label);

    // ─── Build Superformula Geometry ───
    const geometry = this._buildGeometry(params, report, rowEntropies);

    // ─── Material: per-vertex colors + phong shading ───
    const material = new THREE.MeshPhongMaterial({
      vertexColors: true,
      shininess: 50,
      transparent: true,
      opacity: 0.92,
      side: THREE.DoubleSide,
      // Layer 3 binding: high intent → flat shading (sharp, crystalline look)
      flatShading: report.intent_threat_score > 0.45,
    });

    const mesh = new THREE.Mesh(geometry, material);
    scene.add(mesh);

    // ─── Wireframe overlay (cyan structural grid) ───
    const wireMaterial = new THREE.MeshBasicMaterial({
      color: new THREE.Color(
        this.COLORS.wirePrimary.r, this.COLORS.wirePrimary.g, this.COLORS.wirePrimary.b
      ),
      wireframe: true,
      transparent: true,
      opacity: 0.06,
    });
    const wireMesh = new THREE.Mesh(geometry, wireMaterial);
    scene.add(wireMesh);

    // ─── Lighting ───
    scene.add(new THREE.AmbientLight(0x334455, 0.5));

    const mainLight = new THREE.DirectionalLight(0xffffff, 0.9);
    mainLight.position.set(3, 4, 5);
    scene.add(mainLight);

    const fillLight = new THREE.DirectionalLight(0x22d3ee, 0.25);
    fillLight.position.set(-3, -2, -4);
    scene.add(fillLight);

    // Rim light for depth
    const rimLight = new THREE.DirectionalLight(0x8b5cf6, 0.2);
    rimLight.position.set(0, -3, 2);
    scene.add(rimLight);

    // ─── Store references ───
    this._renderer = renderer;
    this._scene = scene;
    this._camera = camera;
    this._mesh = mesh;

    // ─── Animation Loop ───
    const self = this;
    let lastTime = performance.now();

    function animate(now) {
      self._animationId = requestAnimationFrame(animate);
      const dt = (now - lastTime) / 1000;
      lastTime = now;

      if (self._autoRotate) {
        const radsPerSec = (self._autoRotateRPM / 60) * Math.PI * 2;
        mesh.rotation.y += radsPerSec * dt;
        wireMesh.rotation.y = mesh.rotation.y;
      }

      renderer.render(scene, camera);
    }

    animate(performance.now());
  },

  // ═══════════════════════════════════════════════════
  // Parameter Derivation (TEM → Superformula Bindings)
  // ═══════════════════════════════════════════════════

  /**
   * Maps TEMReport fields to superformula coefficients.
   * This is the [Experimental] binding scheme gated by C4.
   */
  _deriveParameters(report) {
    const lerp = (a, b, t) => a + (b - a) * Math.max(0, Math.min(1, t));
    const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

    // Normalize key inputs to [0, 1]
    const entropyNorm = clamp(report.tfea_mean_entropy / 8.0, 0, 1);
    const varianceNorm = clamp(report.tfea_entropy_variance / 4.0, 0, 1);
    const compressionNorm = clamp(report.tfea_compression_ratio, 0, 1);
    const structureNorm = clamp(report.structured_fraction, 0, 1);
    const intentNorm = clamp(report.intent_threat_score, 0, 1);
    const hasMismatch = report.header_mismatch_detected > 0;

    // ─── Layer 1: Macroscopic (TFEA) ───

    // m₁ (symmetry order, θ): low entropy → high m (angular), high entropy → low m (smooth)
    const m1 = lerp(12, 2, entropyNorm);

    // m₂ (symmetry order, φ): entropy variance drives vertical asymmetry
    const m2 = lerp(2, 10, varianceNorm);

    // a₁/a₂ (stretch): compression ratio drives elongation
    const a1 = lerp(1.0, 1.8, compressionNorm);

    // Layer 2: Header mismatch → bilateral asymmetry (a₁ ≠ a₂)
    const a2 = hasMismatch ? a1 * 1.35 : a1;

    // b₁/b₂ (always 1.0 — fixed baseline)
    const b1 = 1.0;
    const b2 = 1.0;

    // n₁ (convexity): structured fraction drives convex/stellated
    // High structure → high n → convex/smooth curves
    // Low structure → low n → stellated/concave
    const n11 = lerp(0.5, 8.0, structureNorm);
    const n12 = n11 * 0.8;  // slight softening
    const n13 = n11 * 0.8;
    const n21 = lerp(0.5, 8.0, structureNorm);
    const n22 = n21 * 0.8;
    const n23 = n21 * 0.8;

    // ─── Layer 3: Causal (AISE) ───

    // Intent → surface roughness amplification
    const roughnessAmp = 1.0 + intentNorm * 0.5;

    // Intent → crease angle (for shading, handled in material)
    const creaseAngle = Math.PI * (1 - intentNorm);

    return {
      m1, m2,
      n11, n12, n13, a1, b1,
      n21, n22, n23, a2, b2,
      roughnessAmp, creaseAngle,
      entropyNorm, intentNorm,
    };
  },

  // ═══════════════════════════════════════════════════
  // Geometry Construction
  // ═══════════════════════════════════════════════════

  /**
   * Builds the BufferGeometry for the 3D spherical product superformula.
   */
  _buildGeometry(params, report, rowEntropies) {
    const NT = this.GRID_THETA;
    const NP = this.GRID_PHI;
    const positions = [];
    const colors = [];
    const indices = [];

    // Equatorial band boundaries (for Markov coloring)
    const bandPhiMin = -Math.PI / 4;
    const bandPhiMax =  Math.PI / 4;

    for (let i = 0; i < NT; i++) {
      const theta = -Math.PI + (2 * Math.PI * i) / NT;

      // r₁(θ) — horizontal cross-section radius
      const r1 = this._superformula(
        theta, params.m1, params.n11, params.n12, params.n13, params.a1, params.b1
      );

      for (let j = 0; j < NP; j++) {
        const phi = -Math.PI / 2 + (Math.PI * j) / (NP - 1);

        // r₂(φ) — vertical cross-section radius
        const r2 = this._superformula(
          phi, params.m2, params.n21, params.n22, params.n23, params.a2, params.b2
        );

        // ─── 3D spherical product ───
        const x = r1 * Math.cos(theta) * r2 * Math.cos(phi);
        const y = r1 * Math.sin(theta) * r2 * Math.cos(phi);
        const z = r2 * Math.sin(phi);

        // Apply roughness amplification from AISE intent
        const scale = params.roughnessAmp;
        positions.push(x * scale, z * scale, y * scale); // swap y/z for upright orientation

        // ─── Per-vertex Color ───
        const color = this._computeColor(
          theta, phi, i, j, NT, NP,
          params, report, rowEntropies,
          bandPhiMin, bandPhiMax
        );
        colors.push(color.r, color.g, color.b);
      }
    }

    // ─── Build index buffer ───
    for (let i = 0; i < NT; i++) {
      const nextI = (i + 1) % NT;
      for (let j = 0; j < NP - 1; j++) {
        const a = i * NP + j;
        const b = nextI * NP + j;
        const c = nextI * NP + (j + 1);
        const d = i * NP + (j + 1);

        indices.push(a, b, d);
        indices.push(b, c, d);
      }
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
    geometry.setIndex(indices);
    geometry.computeVertexNormals();

    return geometry;
  },

  // ═══════════════════════════════════════════════════
  // Superformula Core
  // ═══════════════════════════════════════════════════

  /**
   * Evaluates the 2D Gielis superformula.
   * r(θ) = [|cos(mθ/4)/a|^n₂ + |sin(mθ/4)/b|^n₃]^(-1/n₁)
   *
   * Clamped to [0, 2.0] to prevent geometry explosion at singularities.
   */
  _superformula(theta, m, n1, n2, n3, a, b) {
    // Guard against degenerate parameters
    a = Math.max(a, 0.1);
    b = Math.max(b, 0.1);
    n1 = Math.max(n1, 0.05);

    const angle = m * theta / 4;
    const t1 = Math.abs(Math.cos(angle) / a);
    const t2 = Math.abs(Math.sin(angle) / b);

    const sum = Math.pow(t1, n2) + Math.pow(t2, n3);

    if (sum <= 0 || !isFinite(sum)) return 1.0;

    const r = Math.pow(sum, -1.0 / n1);

    // Clamp to prevent explosion
    return isFinite(r) ? Math.min(r, 2.0) : 1.0;
  },

  // ═══════════════════════════════════════════════════
  // Color Computation
  // ═══════════════════════════════════════════════════

  /**
   * Computes per-vertex color using the hybrid band/cap scheme.
   * Equatorial band: Markov row-entropy coloring
   * Polar caps: Global entropy-based coloring
   */
  _computeColor(theta, phi, i, j, NT, NP, params, report, rowEntropies, bandMin, bandMax) {
    // Seam blending width (π/16 as specified)
    const seamWidth = Math.PI / 16;

    // Determine blend factor: 1.0 = fully in band, 0.0 = fully in cap
    let bandBlend = 0.0;
    if (phi >= bandMin && phi <= bandMax) {
      bandBlend = 1.0;
      // Smooth near seams
      if (phi < bandMin + seamWidth) {
        bandBlend = (phi - bandMin) / seamWidth;
      } else if (phi > bandMax - seamWidth) {
        bandBlend = (bandMax - phi) / seamWidth;
      }
    }

    // ─── Equatorial Band Color (Markov row entropy) ───
    let bandColor;
    if (rowEntropies && rowEntropies.length >= 256) {
      // Map θ ∈ [-π, π] → row index [0, 255]
      const rowIdx = Math.min(255, Math.floor(((theta + Math.PI) / (2 * Math.PI)) * 256));
      const rowH = rowEntropies[rowIdx] / 8.0; // Normalize to [0, 1]
      bandColor = this._entropyToColor(rowH);
    } else {
      // No Markov data — use overall entropy
      bandColor = this._entropyToColor(params.entropyNorm);
    }

    // ─── Polar Cap Color (global properties) ───
    const capColor = this._capColor(params, report);

    // ─── Blend ───
    if (bandBlend >= 0.99) return bandColor;
    if (bandBlend <= 0.01) return capColor;

    return {
      r: capColor.r + (bandColor.r - capColor.r) * bandBlend,
      g: capColor.g + (bandColor.g - capColor.g) * bandBlend,
      b: capColor.b + (bandColor.b - capColor.b) * bandBlend,
    };
  },

  /**
   * Color for polar cap regions — derived from global file properties.
   */
  _capColor(params, report) {
    const intent = params.intentNorm;

    if (intent > 0.5) {
      // High intent → heat-high (red) tones
      const f = (intent - 0.5) * 2;
      return {
        r: this.COLORS.heatMid.r + f * (this.COLORS.heatHigh.r - this.COLORS.heatMid.r),
        g: this.COLORS.heatMid.g + f * (this.COLORS.heatHigh.g - this.COLORS.heatMid.g),
        b: this.COLORS.heatMid.b + f * (this.COLORS.heatHigh.b - this.COLORS.heatMid.b),
      };
    }

    // Low intent → benign (purple-blue) tones
    const f = intent * 2;
    return {
      r: this.COLORS.benign.r * (1 - f) + this.COLORS.heatMid.r * f,
      g: this.COLORS.benign.g * (1 - f) + this.COLORS.heatMid.g * f,
      b: this.COLORS.benign.b * (1 - f) + this.COLORS.heatMid.b * f,
    };
  },

  /**
   * Maps normalized entropy [0,1] to RGB via the v4.0 heat palette.
   */
  _entropyToColor(t) {
    t = Math.max(0, Math.min(1, t));
    const lo = this.COLORS.heatLow;
    const mi = this.COLORS.heatMid;
    const hi = this.COLORS.heatHigh;

    if (t < 0.4) {
      const f = t / 0.4;
      return {
        r: lo.r + f * (0.13 - lo.r),
        g: lo.g + f * (0.83 - lo.g),
        b: lo.b + f * (0.93 - lo.b),
      };
    }
    if (t < 0.7) {
      const f = (t - 0.4) / 0.3;
      return {
        r: 0.13 + f * (mi.r - 0.13),
        g: 0.83 + f * (mi.g - 0.83),
        b: 0.93 + f * (mi.b - 0.93),
      };
    }
    const f = (t - 0.7) / 0.3;
    return {
      r: mi.r + f * (hi.r - mi.r),
      g: mi.g + f * (hi.g - mi.g),
      b: mi.b + f * (hi.b - mi.b),
    };
  },

  // ═══════════════════════════════════════════════════
  // Data Processing
  // ═══════════════════════════════════════════════════

  /**
   * Compute Shannon entropy per row of a probability matrix.
   * @param {number[][]} matrix — 256×256 probability matrix
   * @returns {number[]} — 256 entropy values in [0, 8]
   */
  _computeRowEntropies(matrix) {
    return matrix.map(row => {
      let h = 0;
      for (let j = 0; j < row.length; j++) {
        const p = row[j];
        if (p > 0) h -= p * Math.log2(p);
      }
      return h;
    });
  },

  // ═══════════════════════════════════════════════════
  // Lifecycle
  // ═══════════════════════════════════════════════════

  setAutoRotate(rpm) {
    this._autoRotateRPM = rpm;
    this._autoRotate = rpm > 0;
  },

  cleanup() {
    if (this._animationId) {
      cancelAnimationFrame(this._animationId);
      this._animationId = null;
    }
    if (this._renderer) {
      this._renderer.dispose();
      this._renderer = null;
    }
    if (this._mesh && this._mesh.geometry) {
      this._mesh.geometry.dispose();
    }
    if (this._mesh && this._mesh.material) {
      this._mesh.material.dispose();
    }
    this._scene = null;
    this._camera = null;
    this._mesh = null;
  },

  /**
   * Returns render state for RenderSwap registration.
   */
  getRenderState() {
    if (!this._renderer) return null;
    const self = this;
    return {
      canvas: this._renderer.domElement,
      camera: this._camera,
      renderer: this._renderer,
      scene: this._scene,
      resize(w, h) {
        if (self._renderer) {
          self._renderer.setSize(w, h);
          if (self._camera) {
            self._camera.aspect = w / h;
            self._camera.updateProjectionMatrix();
          }
        }
      },
    };
  },
};
