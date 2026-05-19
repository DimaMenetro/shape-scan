/**
 * shape-scan v2.0 — Spectral Causal Graph Renderer (Step 3)
 *
 * Renders the file's causal/structural graph as a 3D spectral layout
 * using Laplacian eigenvector embedding.
 *
 * Architecture:
 *   - Spectral layout for graphs ≤512 nodes (edge-energy-minimizing)
 *   - Force-directed fallback for larger or degenerate graphs
 *   - Icosphere node geometry scaled by intent level
 *   - Edge coloring: gray (sequential) / red (back-edge)
 *
 * TEM Bindings:
 *   - Node color:    per-block entropy (blue→cyan→amber→red)
 *   - Node opacity:  AISE composite intent
 *   - Node geometry: intent < 0.3 → smooth sphere,
 *                    intent 0.3–0.6 → faceted icosahedron,
 *                    intent > 0.6 → sharp stellated form
 *   - Node size:     log₂(block_size)
 *   - Edge color:    gray (forward) / red (back-edge)
 *
 * Uses Three.js (loaded via CDN in index.html).
 */

const ShapeScanGraph = {

  // State
  _renderer: null,
  _scene: null,
  _camera: null,
  _animationId: null,
  _autoRotate: true,
  _container: null,
  _nodeMeshes: [],
  _nodeData: [],          // Parallel to _nodeMeshes — stores GraphNode data (offset, size, etc.)
  _group: null,           // The main group containing all nodes + edges
  _raycaster: null,       // For click-to-select node interaction
  _mouse: null,           // NDC mouse coordinates for raycasting

  // Design tokens
  COLORS: {
    bgDeep:    0x0a0e17,
    edgeNorm:  0x3a4155,
    edgeBack:  0xe74444,
    wire:      0x22d3ee,
  },

  // ═══════════════════════════════════════════════════
  // Main Entry Point
  // ═══════════════════════════════════════════════════

  /**
   * @param {string}  containerId — DOM element ID
   * @param {Object}  data — { nodes, links, node_count, edge_count, back_edge_ratio }
   */
  render(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container || !data || !data.nodes || data.nodes.length === 0) return;

    this.cleanup();
    this._container = container;

    const w = container.clientWidth;
    const h = container.clientHeight;
    if (w === 0 || h === 0) return;

    const nodes = data.nodes;
    const links = data.links;

    // ─── Compute Layout ───
    const positions = (nodes.length <= 512 && nodes.length >= 4)
      ? this._spectralLayout(nodes, links)
      : this._forceLayout(nodes, links);

    // ─── Three.js Scene ───
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(this.COLORS.bgDeep);

    const camera = new THREE.PerspectiveCamera(50, w / h, 0.1, 200);
    camera.position.set(0, 1.5, 4.5);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    renderer.setSize(w, h);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    // ─── Lighting ───
    scene.add(new THREE.AmbientLight(0x334466, 0.6));
    const dLight = new THREE.DirectionalLight(0xffffff, 0.8);
    dLight.position.set(4, 6, 5);
    scene.add(dLight);
    const fillLight = new THREE.DirectionalLight(0x22d3ee, 0.15);
    fillLight.position.set(-3, -2, -3);
    scene.add(fillLight);

    // ─── Create Node Meshes ───
    const group = new THREE.Group();
    this._nodeMeshes = [];
    this._nodeData = [];

    for (let i = 0; i < nodes.length; i++) {
      const node = nodes[i];
      const pos = positions[i];

      // Geometry selection based on intent
      let geo;
      if (node.intent > 0.6) {
        // High intent → sharp stellated icosahedron (low subdivision)
        geo = new THREE.IcosahedronGeometry(0.06, 0);
      } else if (node.intent > 0.3) {
        // Medium intent → faceted icosahedron
        geo = new THREE.IcosahedronGeometry(0.05, 1);
      } else {
        // Low intent → smooth sphere
        geo = new THREE.SphereGeometry(0.04, 8, 6);
      }

      // Size scaling from block size
      const sizeScale = Math.max(0.6, Math.min(2.0, Math.log2(node.size + 1) / 10));

      const color = this._entropyToColor(node.entropy);
      const alpha = 0.35 + node.intent * 0.65;

      const mat = new THREE.MeshPhongMaterial({
        color: color,
        transparent: true,
        opacity: alpha,
        flatShading: node.intent > 0.4,
        shininess: 60,
      });

      const mesh = new THREE.Mesh(geo, mat);
      mesh.position.set(pos.x, pos.y, pos.z);
      mesh.scale.setScalar(sizeScale);
      group.add(mesh);
      this._nodeMeshes.push(mesh);
      this._nodeData.push(node);  // Parallel array — same index as mesh
    }

    // ─── Create Edges ───
    const fwdPositions = [];
    const backPositions = [];

    for (const link of links) {
      if (link.source >= positions.length || link.target >= positions.length) continue;
      const ps = positions[link.source];
      const pt = positions[link.target];

      if (link.is_back_edge) {
        backPositions.push(ps.x, ps.y, ps.z, pt.x, pt.y, pt.z);
      } else {
        fwdPositions.push(ps.x, ps.y, ps.z, pt.x, pt.y, pt.z);
      }
    }

    // Forward edges (subtle gray)
    if (fwdPositions.length > 0) {
      const fwdGeo = new THREE.BufferGeometry();
      fwdGeo.setAttribute('position', new THREE.Float32BufferAttribute(fwdPositions, 3));
      const fwdMat = new THREE.LineBasicMaterial({
        color: this.COLORS.edgeNorm,
        transparent: true,
        opacity: 0.15,
      });
      group.add(new THREE.LineSegments(fwdGeo, fwdMat));
    }

    // Back-edges (red, more visible)
    if (backPositions.length > 0) {
      const backGeo = new THREE.BufferGeometry();
      backGeo.setAttribute('position', new THREE.Float32BufferAttribute(backPositions, 3));
      const backMat = new THREE.LineBasicMaterial({
        color: this.COLORS.edgeBack,
        transparent: true,
        opacity: 0.45,
      });
      group.add(new THREE.LineSegments(backGeo, backMat));
    }

    scene.add(group);

    // ─── Store refs ───
    this._renderer = renderer;
    this._scene = scene;
    this._camera = camera;
    this._group = group;
    this._raycaster = new THREE.Raycaster();
    this._mouse = new THREE.Vector2();

    // ─── Interaction ───
    let isDragging = false;
    let lastX = 0, lastY = 0;
    const canvas = renderer.domElement;

    canvas.addEventListener('mousedown', (e) => {
      isDragging = true; lastX = e.clientX; lastY = e.clientY;
      this._autoRotate = false;
    });
    canvas.addEventListener('mousemove', (e) => {
      if (!isDragging) return;
      group.rotation.y += (e.clientX - lastX) * 0.005;
      group.rotation.x += (e.clientY - lastY) * 0.005;
      group.rotation.x = Math.max(-Math.PI/2, Math.min(Math.PI/2, group.rotation.x));
      lastX = e.clientX; lastY = e.clientY;
    });
    canvas.addEventListener('mouseup', () => { isDragging = false; });
    canvas.addEventListener('wheel', (e) => {
      camera.position.z *= e.deltaY > 0 ? 1.08 : 0.92;
      camera.position.z = Math.max(1.5, Math.min(15, camera.position.z));
      e.preventDefault();
    }, { passive: false });
    canvas.addEventListener('dblclick', () => {
      group.rotation.set(0, 0, 0);
      camera.position.set(0, 1.5, 4.5);
      this._autoRotate = true;
    });

    // ─── Click-to-Select (Focus Lens cross-link) ───
    // Distinguishes click from drag by tracking mouse movement distance
    let clickStartX = 0, clickStartY = 0;
    canvas.addEventListener('mousedown', (e) => {
      clickStartX = e.clientX;
      clickStartY = e.clientY;
    });
    canvas.addEventListener('click', (e) => {
      // Ignore if mouse moved >5px (was a drag, not a click)
      const dx = e.clientX - clickStartX;
      const dy = e.clientY - clickStartY;
      if (Math.sqrt(dx*dx + dy*dy) > 5) return;

      if (typeof FocusLens === 'undefined') return;
      if (typeof currentPath === 'undefined' || !currentPath) return;
      if (!this._raycaster || this._nodeMeshes.length === 0) return;

      // Compute NDC coordinates
      const rect = canvas.getBoundingClientRect();
      this._mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      this._mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      this._raycaster.setFromCamera(this._mouse, camera);
      const intersects = this._raycaster.intersectObjects(this._nodeMeshes);

      if (intersects.length > 0) {
        const hitMesh = intersects[0].object;
        const idx = this._nodeMeshes.indexOf(hitMesh);
        if (idx >= 0 && idx < this._nodeData.length) {
          const nodeInfo = this._nodeData[idx];

          // Visual feedback: pulse selected node
          hitMesh.material.emissive = new THREE.Color(0x22d3ee);
          hitMesh.material.emissiveIntensity = 0.6;
          setTimeout(() => {
            hitMesh.material.emissive = new THREE.Color(0x000000);
            hitMesh.material.emissiveIntensity = 0;
          }, 1500);

          // Trigger Focus Lens
          const lensSize = Math.min(Math.max(nodeInfo.size, 256), 4096);
          FocusLens.show(currentPath, nodeInfo.offset, lensSize);
        }
      }
    });

    // ─── Render Loop ───
    const self = this;
    function animate() {
      self._animationId = requestAnimationFrame(animate);
      if (self._autoRotate) group.rotation.y += 0.002;
      renderer.render(scene, camera);
    }
    animate();
  },

  // ═══════════════════════════════════════════════════
  // Spectral Layout (Laplacian Eigenvector Embedding)
  // ═══════════════════════════════════════════════════

  /**
   * Computes 3D coordinates using the 3 Fiedler eigenvectors
   * of the graph Laplacian.
   *
   * Math: L = D - A, find eigenvectors for λ₂, λ₃, λ₄
   * Method: Power iteration on (λ_max·I - L) to convert
   *         smallest eigenvalues to largest.
   */
  _spectralLayout(nodes, links) {
    const n = nodes.length;

    // Build adjacency + degree
    const adj = new Float64Array(n * n);
    const deg = new Float64Array(n);

    for (const link of links) {
      if (link.source >= n || link.target >= n) continue;
      adj[link.source * n + link.target] = 1;
      adj[link.target * n + link.source] = 1;
      deg[link.source]++;
      deg[link.target]++;
    }

    // Build Laplacian L = D - A
    const L = new Float64Array(n * n);
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        if (i === j) {
          L[i * n + j] = deg[i];
        } else {
          L[i * n + j] = -adj[i * n + j];
        }
      }
    }

    // Estimate max eigenvalue (Gershgorin bound)
    let lambdaMax = 0;
    for (let i = 0; i < n; i++) {
      lambdaMax = Math.max(lambdaMax, 2 * deg[i]);
    }
    lambdaMax = Math.max(lambdaMax, 1);

    // Shift matrix M = lambdaMax·I - L
    // Smallest eigenvectors of L → largest eigenvectors of M
    const M = new Float64Array(n * n);
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        M[i * n + j] = -L[i * n + j];
        if (i === j) M[i * n + j] += lambdaMax;
      }
    }

    // Find 4 eigenvectors via power iteration + deflation
    // Skip the first (trivial constant vector)
    const eigenvectors = [];
    for (let ev = 0; ev < 4; ev++) {
      let v = new Float64Array(n);
      // Random initialization (seeded by index for reproducibility)
      for (let i = 0; i < n; i++) {
        v[i] = Math.sin(i * 7.13 + ev * 3.97) + Math.cos(i * 11.3 + ev * 5.11);
      }

      // Power iteration
      const maxIter = Math.min(100, n * 2);
      for (let iter = 0; iter < maxIter; iter++) {
        // Matrix-vector multiply: w = M * v
        const w = new Float64Array(n);
        for (let i = 0; i < n; i++) {
          let sum = 0;
          for (let j = 0; j < n; j++) {
            sum += M[i * n + j] * v[j];
          }
          w[i] = sum;
        }

        // Deflate against previously found eigenvectors
        for (const prev of eigenvectors) {
          let dot = 0;
          for (let i = 0; i < n; i++) dot += w[i] * prev[i];
          for (let i = 0; i < n; i++) w[i] -= dot * prev[i];
        }

        // Normalize
        let norm = 0;
        for (let i = 0; i < n; i++) norm += w[i] * w[i];
        norm = Math.sqrt(norm);
        if (norm < 1e-12) break;
        for (let i = 0; i < n; i++) v[i] = w[i] / norm;
      }

      eigenvectors.push(v);
    }

    // Use eigenvectors 1, 2, 3 (skip 0 = trivial constant)
    // If we don't have enough, fall back to force layout
    if (eigenvectors.length < 4) {
      return this._forceLayout(nodes, links);
    }

    const ex = eigenvectors[1]; // x-coordinate
    const ey = eigenvectors[2]; // y-coordinate
    const ez = eigenvectors[3]; // z-coordinate

    // Scale to fit a [-1.5, 1.5] bounding box
    let maxCoord = 0;
    for (let i = 0; i < n; i++) {
      maxCoord = Math.max(maxCoord, Math.abs(ex[i]), Math.abs(ey[i]), Math.abs(ez[i]));
    }
    const scale = maxCoord > 0 ? 1.5 / maxCoord : 1;

    const positions = [];
    for (let i = 0; i < n; i++) {
      positions.push({
        x: ex[i] * scale,
        y: ey[i] * scale,
        z: ez[i] * scale,
      });
    }

    return positions;
  },

  // ═══════════════════════════════════════════════════
  // Force-Directed Layout (Fallback)
  // ═══════════════════════════════════════════════════

  _forceLayout(nodes, links, iterations = 80) {
    const n = nodes.length;
    const pos = [];

    // Initialize on a Fibonacci sphere
    for (let i = 0; i < n; i++) {
      const phi = Math.acos(1 - 2 * (i + 0.5) / n);
      const theta = Math.PI * (1 + Math.sqrt(5)) * i;
      const r = 0.8;
      pos.push({
        x: r * Math.sin(phi) * Math.cos(theta),
        y: r * Math.sin(phi) * Math.sin(theta),
        z: r * Math.cos(phi),
        vx: 0, vy: 0, vz: 0
      });
    }

    const repulsion = 0.02;
    const attraction = 0.03;
    const damping = 0.85;

    for (let iter = 0; iter < iterations; iter++) {
      const temp = 1.0 - iter / iterations;

      // Repulsion (neighbor window for performance)
      for (let i = 0; i < n; i++) {
        for (let j = i + 1; j < Math.min(i + 40, n); j++) {
          const dx = pos[i].x - pos[j].x;
          const dy = pos[i].y - pos[j].y;
          const dz = pos[i].z - pos[j].z;
          const d2 = dx*dx + dy*dy + dz*dz + 0.001;
          const f = repulsion * temp / d2;
          pos[i].vx += dx*f; pos[i].vy += dy*f; pos[i].vz += dz*f;
          pos[j].vx -= dx*f; pos[j].vy -= dy*f; pos[j].vz -= dz*f;
        }
      }

      // Attraction (springs)
      for (const link of links) {
        if (link.source >= n || link.target >= n) continue;
        const a = pos[link.source], b = pos[link.target];
        const dx = b.x-a.x, dy = b.y-a.y, dz = b.z-a.z;
        const d = Math.sqrt(dx*dx + dy*dy + dz*dz) + 0.001;
        const f = attraction * d * temp;
        a.vx += dx*f/d; a.vy += dy*f/d; a.vz += dz*f/d;
        b.vx -= dx*f/d; b.vy -= dy*f/d; b.vz -= dz*f/d;
      }

      for (let i = 0; i < n; i++) {
        pos[i].x += pos[i].vx; pos[i].y += pos[i].vy; pos[i].z += pos[i].vz;
        pos[i].vx *= damping; pos[i].vy *= damping; pos[i].vz *= damping;
      }
    }

    return pos;
  },

  // ═══════════════════════════════════════════════════
  // Color Helpers
  // ═══════════════════════════════════════════════════

  _entropyToColor(h) {
    const t = Math.max(0, Math.min(1, h));
    // Blue → Cyan → Amber → Red
    if (t < 0.35) {
      const f = t / 0.35;
      return new THREE.Color(0.12 + f*0.01, 0.25 + f*0.58, 0.69 + f*0.24);
    }
    if (t < 0.65) {
      const f = (t - 0.35) / 0.3;
      return new THREE.Color(0.13 + f*0.83, 0.83 - f*0.21, 0.93 - f*0.89);
    }
    const f = (t - 0.65) / 0.35;
    return new THREE.Color(0.96 - f*0.02, 0.62 - f*0.35, 0.04 + f*0.23);
  },

  // ═══════════════════════════════════════════════════
  // Lifecycle
  // ═══════════════════════════════════════════════════

  cleanup() {
    if (this._animationId) {
      cancelAnimationFrame(this._animationId);
      this._animationId = null;
    }
    if (this._renderer) {
      this._renderer.dispose();
      this._renderer = null;
    }
    this._nodeMeshes.forEach(m => {
      if (m.geometry) m.geometry.dispose();
      if (m.material) m.material.dispose();
    });
    this._nodeMeshes = [];
    this._nodeData = [];
    this._scene = null;
    this._camera = null;
    this._group = null;
    this._raycaster = null;
    this._mouse = null;
  },
};
