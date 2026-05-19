/**
 * shape-scan v2.0 — Toroidal Markov Surface Renderer (Step 2A)
 *
 * Renders the 256×256 Markov transition probability matrix as a parametric
 * torus whose geometry is entirely driven by TEM analysis fields.
 *
 * TEM Field Bindings:
 *   P(v|u)           → Minor radius:   r(u,v) = 0.3 + 0.5·P^1.5
 *   Per-row entropy   → Roughness amp:  r_amp  = 1.0 + λ·Hᵢ_norm
 *   Markov gradient   → Displacement:   disp   = κ·(|∂P/∂u|+|∂P/∂v|)
 *   AISE intent       → Crease angle:   θ      = π·(1 - I_AISE)
 *
 * Visual targets (from reference images):
 *   - Clean text (.txt) → smooth blue-violet ring, slight ASCII ridges
 *   - Encrypted (.aes)  → near-perfect amber/gold donut
 *   - PE binary (.exe)  → asymmetric red-orange spikes on cyan wireframe
 *
 * Uses Three.js (loaded via CDN in index.html).
 */

const MarkovTorus = {

  // State
  _renderer: null,
  _scene: null,
  _camera: null,
  _mesh: null,
  _animationId: null,
  _autoRotate: true,
  _autoRotateRPM: 6,
  _container: null,

  // ─── Design Token Colors (from v4.0 spec) ───
  COLORS: {
    heatLow:      { r: 0x1e / 255, g: 0x40 / 255, b: 0xaf / 255 },  // #1e40af deep blue
    heatMid:      { r: 0xf5 / 255, g: 0x9e / 255, b: 0x0b / 255 },  // #f59e0b amber
    heatHigh:     { r: 0xef / 255, g: 0x44 / 255, b: 0x44 / 255 },  // #ef4444 red
    wirePrimary:  { r: 0x22 / 255, g: 0xd3 / 255, b: 0xee / 255 },  // #22d3ee cyan
    bgDeep:       { r: 0x0a / 255, g: 0x0e / 255, b: 0x17 / 255 },  // #0a0e17
  },

  // ─── Constants ───
  GRID_SIZE: 128,       // 128×128 parametric grid → 16,384 vertices
  MAJOR_RADIUS: 1.5,    // R — distance from center of torus to center of tube
  MINOR_BASE: 0.3,      // r_base — minimum tube radius
  MINOR_SCALE: 0.5,     // coefficient for P^1.5 contribution
  ROUGHNESS_LAMBDA: 0.8,// λ — per-row entropy roughness amplification
  GRADIENT_KAPPA: 2.0,  // κ — gradient displacement strength
  PROB_EXPONENT: 1.5,   // exponent on P(v|u) for non-linear minor radius

  /**
   * Main entry point — renders the torus into a container element.
   * @param {string}   containerId — DOM element ID for the viewport
   * @param {number[][]} matrix    — 256×256 probability matrix from IPC
   * @param {Object}   [report]   — TEMReport for AISE intent binding (optional)
   */
  render(containerId, matrix, report) {
    const container = document.getElementById(containerId);
    if (!container || !matrix || matrix.length < 2) return;

    this.cleanup();
    this._container = container;

    const w = container.clientWidth;
    const h = container.clientHeight;
    if (w === 0 || h === 0) return; // Container still hidden

    // ─── Downsample 256×256 → 128×128 ───
    const grid = this._downsampleMatrix(matrix, this.GRID_SIZE);

    // ─── Compute per-row entropy from probability matrix ───
    const rowEntropies = this._computeRowEntropies(matrix);
    const maxRowH = Math.max(...rowEntropies, 0.001);
    const normEntropies = rowEntropies.map(h => h / 8.0); // normalize to [0,1] (max 8 bits)

    // ─── Compute gradient magnitudes ───
    const gradients = this._computeGradients(grid);

    // ─── AISE intent (if available) ───
    const intent = (report && typeof report.intent_threat_score === 'number')
      ? report.intent_threat_score
      : 0.0;

    // ─── Three.js Scene Setup ───
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(
      this.COLORS.bgDeep.r, this.COLORS.bgDeep.g, this.COLORS.bgDeep.b
    );

    const camera = new THREE.PerspectiveCamera(45, w / h, 0.1, 100);
    camera.position.set(0, 1.5, 4.5);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    renderer.setSize(w, h);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // Clear container and insert canvas
    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    // Re-add the viewport label
    const label = document.createElement('span');
    label.className = 'viewport-label';
    label.textContent = 'Toroidal Fingerprint';
    container.appendChild(label);

    // ─── Build Torus Geometry ───
    const geometry = this._buildTorusGeometry(grid, normEntropies, gradients, intent);

    // ─── Material: per-vertex colors + subtle phong shading ───
    const material = new THREE.MeshPhongMaterial({
      vertexColors: true,
      shininess: 60,
      transparent: true,
      opacity: 0.92,
      side: THREE.DoubleSide,
    });

    const mesh = new THREE.Mesh(geometry, material);
    scene.add(mesh);

    // ─── Wireframe overlay for the cyan structural grid ───
    const wireMaterial = new THREE.MeshBasicMaterial({
      color: new THREE.Color(
        this.COLORS.wirePrimary.r, this.COLORS.wirePrimary.g, this.COLORS.wirePrimary.b
      ),
      wireframe: true,
      transparent: true,
      opacity: 0.08,
    });
    const wireMesh = new THREE.Mesh(geometry, wireMaterial);
    scene.add(wireMesh);

    // ─── Lighting ───
    const ambientLight = new THREE.AmbientLight(0x334455, 0.6);
    scene.add(ambientLight);

    const mainLight = new THREE.DirectionalLight(0xffffff, 0.8);
    mainLight.position.set(3, 4, 5);
    scene.add(mainLight);

    const fillLight = new THREE.DirectionalLight(0x22d3ee, 0.3);
    fillLight.position.set(-2, -1, -3);
    scene.add(fillLight);

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

      // Auto-rotation
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
  // Geometry Construction
  // ═══════════════════════════════════════════════════

  /**
   * Builds the BufferGeometry for the parametric torus with TEM bindings.
   */
  _buildTorusGeometry(grid, normEntropies, gradients, intent) {
    const N = this.GRID_SIZE;
    const R = this.MAJOR_RADIUS;
    const positions = [];
    const colors = [];
    const indices = [];

    // Crease factor from AISE intent: higher intent → sharper features
    const creaseAngle = Math.PI * (1 - intent);
    const creaseFactor = 1.0 + intent * 0.5; // Amplifies displacement for high-intent files

    for (let i = 0; i < N; i++) {
      const u = (i / N) * Math.PI * 2; // major angle
      // Map u to row index in the 256-row entropy array
      const rowIdx = Math.min(255, Math.floor((i / N) * 256));
      const rowH = normEntropies[rowIdx];

      // Per-row roughness amplitude
      const rAmp = 1.0 + this.ROUGHNESS_LAMBDA * rowH;

      for (let j = 0; j < N; j++) {
        const v = (j / N) * Math.PI * 2; // minor angle

        // ─── TEM Binding 1: Minor radius from P(v|u) ───
        const P = grid[i][j];
        const rMinor = this.MINOR_BASE + this.MINOR_SCALE * Math.pow(P, this.PROB_EXPONENT);

        // ─── TEM Binding 2: Roughness from per-row entropy ───
        const rModulated = rMinor * rAmp;

        // ─── TEM Binding 3: Gradient displacement ───
        const grad = gradients[i][j];
        const disp = this.GRADIENT_KAPPA * grad * creaseFactor;

        // ─── Final minor radius ───
        const rFinal = rModulated + disp;

        // ─── Parametric torus position ───
        const x = (R + rFinal * Math.cos(v)) * Math.cos(u);
        const y = (R + rFinal * Math.cos(v)) * Math.sin(u);
        const z = rFinal * Math.sin(v);

        positions.push(x, y, z);

        // ─── Per-vertex color from probability ───
        const color = this._probToColor(P);
        colors.push(color.r, color.g, color.b);
      }
    }

    // ─── Build index buffer (wrap around both u and v) ───
    for (let i = 0; i < N; i++) {
      const nextI = (i + 1) % N;
      for (let j = 0; j < N; j++) {
        const nextJ = (j + 1) % N;

        const a = i * N + j;
        const b = nextI * N + j;
        const c = nextI * N + nextJ;
        const d = i * N + nextJ;

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
  // Data Processing
  // ═══════════════════════════════════════════════════

  /**
   * Downsample a 256×256 matrix to targetSize×targetSize using nearest-neighbor.
   */
  _downsampleMatrix(matrix, targetSize) {
    const srcSize = matrix.length;
    const step = srcSize / targetSize;
    const result = [];

    for (let i = 0; i < targetSize; i++) {
      const row = [];
      const si = Math.min(srcSize - 1, Math.floor(i * step));
      for (let j = 0; j < targetSize; j++) {
        const sj = Math.min(srcSize - 1, Math.floor(j * step));
        row.push(matrix[si][sj]);
      }
      result.push(row);
    }
    return result;
  },

  /**
   * Compute Shannon entropy for each row of the probability matrix.
   * H_i = -Σ P(j|i) · log2(P(j|i)) for all j where P > 0
   * @param {number[][]} matrix — 256×256 probability matrix (rows already sum to 1)
   * @returns {number[]} — 256 entropy values in [0, 8]
   */
  _computeRowEntropies(matrix) {
    return matrix.map(row => {
      let h = 0;
      for (let j = 0; j < row.length; j++) {
        const p = row[j];
        if (p > 0) {
          h -= p * Math.log2(p);
        }
      }
      return h;
    });
  },

  /**
   * Compute gradient magnitudes for each cell of a grid.
   * gradient(i,j) = |∂P/∂u| + |∂P/∂v| via finite differences.
   * @param {number[][]} grid — downsampled matrix
   * @returns {number[][]} — gradient magnitudes
   */
  _computeGradients(grid) {
    const N = grid.length;
    const result = [];

    for (let i = 0; i < N; i++) {
      const row = [];
      const nextI = (i + 1) % N;
      for (let j = 0; j < N; j++) {
        const nextJ = (j + 1) % N;
        const dPdu = Math.abs(grid[nextI][j] - grid[i][j]);
        const dPdv = Math.abs(grid[i][nextJ] - grid[i][j]);
        row.push(dPdu + dPdv);
      }
      result.push(row);
    }
    return result;
  },

  // ═══════════════════════════════════════════════════
  // Color Mapping
  // ═══════════════════════════════════════════════════

  /**
   * Maps transition probability P ∈ [0,1] to an RGB color
   * using the v4.0 heat palette: deep blue → amber → red
   */
  _probToColor(P) {
    const t = Math.max(0, Math.min(1, P));

    if (t < 0.005) {
      // Near-zero: dark background tone
      return { r: 0.06, g: 0.08, b: 0.18 };
    }

    const lo = this.COLORS.heatLow;
    const mi = this.COLORS.heatMid;
    const hi = this.COLORS.heatHigh;

    if (t < 0.3) {
      // Low probability: deep blue → cyan blend
      const f = t / 0.3;
      return {
        r: lo.r + f * (0.13 - lo.r),
        g: lo.g + f * (0.83 - lo.g),
        b: lo.b + f * (0.93 - lo.b),
      };
    }

    if (t < 0.6) {
      // Medium: cyan → amber
      const f = (t - 0.3) / 0.3;
      return {
        r: 0.13 + f * (mi.r - 0.13),
        g: 0.83 + f * (mi.g - 0.83),
        b: 0.93 + f * (mi.b - 0.93),
      };
    }

    // High: amber → red
    const f = (t - 0.6) / 0.4;
    return {
      r: mi.r + f * (hi.r - mi.r),
      g: mi.g + f * (hi.g - mi.g),
      b: mi.b + f * (hi.b - mi.b),
    };
  },

  // ═══════════════════════════════════════════════════
  // Lifecycle
  // ═══════════════════════════════════════════════════

  /**
   * Sets the auto-rotation speed.
   * @param {number} rpm — rotations per minute
   */
  setAutoRotate(rpm) {
    this._autoRotateRPM = rpm;
    this._autoRotate = rpm > 0;
  },

  /**
   * Cleans up Three.js resources and stops animation.
   */
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
