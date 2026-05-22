/**
 * shape-scan v2.0 — Markov Transition Surface Renderer
 *
 * Renders the 256×256 Markov transition probability matrix as a 3D heightmap.
 * Uses pure WebGL — no Three.js dependency (airgapped compatibility).
 *
 * X axis: source byte value (0-255)
 * Z axis: target byte value (0-255)
 * Y axis: transition probability P(target | source)
 * Color:  probability-mapped (blue=low → yellow=mid → red=high)
 */

const ShapeScanMarkov = {

  animationId: null,

  /**
   * Render the Markov transition matrix as a 3D surface.
   * @param {string} containerId — DOM element ID
   * @param {number[][]} matrix — 256×256 probability matrix
   */
  render(containerId, matrix) {
    const container = document.getElementById(containerId);
    if (!container || !matrix || matrix.length < 2) return;

    this.cleanup();

    const w = container.clientWidth;
    const h = container.clientHeight;

    const canvas = document.createElement('canvas');
    canvas.width  = w * (window.devicePixelRatio || 1);
    canvas.height = h * (window.devicePixelRatio || 1);
    canvas.style.width  = '100%';
    canvas.style.height = '100%';
    container.innerHTML = '';
    container.appendChild(canvas);

    const gl = canvas.getContext('webgl', { antialias: true, alpha: false });
    if (!gl) {
      container.innerHTML = '<div style="color:#8892a8;text-align:center;padding:60px;">WebGL not available</div>';
      return;
    }

    gl.clearColor(0.039, 0.047, 0.063, 1.0);
    gl.enable(gl.DEPTH_TEST);
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

    // ─── Downsample matrix for performance ───
    // 256×256 = 65536 vertices → downsample to 128×128 = 16384 for smooth rendering
    const gridSize = Math.min(128, matrix.length);
    const step = matrix.length / gridSize;

    const heights = [];
    let maxH = 0;

    for (let i = 0; i < gridSize; i++) {
      const row = [];
      for (let j = 0; j < gridSize; j++) {
        const si = Math.min(Math.floor(i * step), matrix.length - 1);
        const sj = Math.min(Math.floor(j * step), matrix[si].length - 1);
        const val = matrix[si][sj];
        row.push(val);
        if (val > maxH) maxH = val;
      }
      heights.push(row);
    }

    // Normalize heights
    const scale = maxH > 0 ? 1.0 / maxH : 1.0;

    // ─── Build Triangle Mesh ───
    const vertices = [];  // x, y, z, r, g, b, a
    const indices  = [];

    for (let i = 0; i < gridSize; i++) {
      for (let j = 0; j < gridSize; j++) {
        const x = (i / gridSize - 0.5) * 2.0;
        const z = (j / gridSize - 0.5) * 2.0;
        const y = heights[i][j] * scale * 0.8;

        const c = this.probToColor(heights[i][j] * scale);
        vertices.push(x, y, z, c.r, c.g, c.b, c.a);
      }
    }

    for (let i = 0; i < gridSize - 1; i++) {
      for (let j = 0; j < gridSize - 1; j++) {
        const tl = i * gridSize + j;
        const tr = tl + 1;
        const bl = (i + 1) * gridSize + j;
        const br = bl + 1;

        indices.push(tl, bl, tr);
        indices.push(tr, bl, br);
      }
    }

    // ─── Shaders ───
    const vs = `
      attribute vec3 aPosition;
      attribute vec4 aColor;
      uniform mat4 uMVP;
      varying vec4 vColor;
      varying float vHeight;
      void main() {
        gl_Position = uMVP * vec4(aPosition, 1.0);
        vColor = aColor;
        vHeight = aPosition.y;
      }
    `;
    const fs = `
      precision mediump float;
      varying vec4 vColor;
      varying float vHeight;
      void main() {
        // Add subtle edge glow based on height
        float glow = smoothstep(0.0, 0.3, vHeight) * 0.3;
        gl_FragColor = vec4(vColor.rgb + glow, vColor.a);
      }
    `;

    const prog = this.createProgram(gl, vs, fs);

    // ─── Buffers ───
    const vertBuf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, vertBuf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(vertices), gl.STATIC_DRAW);

    const idxBuf = gl.createBuffer();
    gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, idxBuf);
    gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, new Uint32Array(indices), gl.STATIC_DRAW);

    // Check for OES_element_index_uint
    gl.getExtension('OES_element_index_uint');

    // ─── Camera ───
    let rotX = -0.5;
    let rotY = 0.3;
    let zoom = 3.5;
    let isDragging = false;
    let lastX = 0, lastY = 0;

    canvas.addEventListener('mousedown', (e) => { isDragging = true; lastX = e.clientX; lastY = e.clientY; });
    canvas.addEventListener('mousemove', (e) => {
      if (!isDragging) return;
      rotY += (e.clientX - lastX) * 0.005;
      rotX += (e.clientY - lastY) * 0.005;
      rotX = Math.max(-Math.PI / 2, Math.min(0.1, rotX));
      lastX = e.clientX; lastY = e.clientY;
    });
    canvas.addEventListener('mouseup', () => { isDragging = false; });
    canvas.addEventListener('wheel', (e) => {
      zoom *= e.deltaY > 0 ? 1.1 : 0.9;
      zoom = Math.max(1.0, Math.min(10, zoom));
      e.preventDefault();
    }, { passive: false });

    // ─── Render Loop ───
    const aspect = w / h;
    const stride = 7 * 4; // 7 floats × 4 bytes
    const numIndices = indices.length;
    const self = this;

    function frame() {
      self.animationId = requestAnimationFrame(frame);

      if (!isDragging) rotY += 0.001;

      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);

      gl.useProgram(prog);

      const mvp = self.buildMVP(rotX, rotY, zoom, aspect);
      gl.uniformMatrix4fv(gl.getUniformLocation(prog, 'uMVP'), false, mvp);

      gl.bindBuffer(gl.ARRAY_BUFFER, vertBuf);

      const posLoc = gl.getAttribLocation(prog, 'aPosition');
      gl.enableVertexAttribArray(posLoc);
      gl.vertexAttribPointer(posLoc, 3, gl.FLOAT, false, stride, 0);

      const colLoc = gl.getAttribLocation(prog, 'aColor');
      gl.enableVertexAttribArray(colLoc);
      gl.vertexAttribPointer(colLoc, 4, gl.FLOAT, false, stride, 12);

      gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, idxBuf);
      gl.drawElements(gl.TRIANGLES, numIndices, gl.UNSIGNED_INT, 0);
    }

    frame();
  },

  // ─── Color Mapping ───
  probToColor(t) {
    t = Math.max(0, Math.min(1, t));

    if (t < 0.01) {
      // Near zero — dark, mostly transparent
      return { r: 0.06, g: 0.08, b: 0.15, a: 0.3 };
    }

    if (t < 0.3) {
      // Low probability — deep blue to cyan
      const f = t / 0.3;
      return {
        r: 0.05 + f * 0.1,
        g: 0.15 + f * 0.4,
        b: 0.5  + f * 0.3,
        a: 0.5  + f * 0.3
      };
    }

    if (t < 0.6) {
      // Medium — cyan to yellow
      const f = (t - 0.3) / 0.3;
      return {
        r: 0.15 + f * 0.8,
        g: 0.55 + f * 0.35,
        b: 0.8  - f * 0.6,
        a: 0.8  + f * 0.1
      };
    }

    // High — yellow to hot red
    const f = (t - 0.6) / 0.4;
    return {
      r: 0.95,
      g: 0.9  - f * 0.7,
      b: 0.2  - f * 0.15,
      a: 0.9  + f * 0.1
    };
  },

  // ─── WebGL Helpers (same as graph.js) ───
  createShader(gl, type, src) {
    const s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    return s;
  },

  createProgram(gl, vsSrc, fsSrc) {
    const p = gl.createProgram();
    gl.attachShader(p, this.createShader(gl, gl.VERTEX_SHADER, vsSrc));
    gl.attachShader(p, this.createShader(gl, gl.FRAGMENT_SHADER, fsSrc));
    gl.linkProgram(p);
    return p;
  },

  buildMVP(rx, ry, zoom, aspect) {
    const f = 1.0 / Math.tan(Math.PI / 8);
    const near = 0.1, far = 100.0;

    const proj = new Float32Array([
      f / aspect, 0, 0, 0,
      0, f, 0, 0,
      0, 0, (far + near) / (near - far), -1,
      0, 0, (2 * far * near) / (near - far), 0
    ]);

    const cx = Math.cos(rx), sx = Math.sin(rx);
    const cy = Math.cos(ry), sy = Math.sin(ry);

    const view = new Float32Array([
      cy,       sx*sy,    -cx*sy,   0,
      0,        cx,       sx,       0,
      sy,       -sx*cy,   cx*cy,    0,
      0,        0,        -zoom,    1
    ]);

    const r = new Float32Array(16);
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) {
        r[i*4+j] = proj[i*4]*view[j] + proj[i*4+1]*view[4+j] + proj[i*4+2]*view[8+j] + proj[i*4+3]*view[12+j];
      }
    }
    return r;
  },

  cleanup() {
    if (this.animationId) {
      cancelAnimationFrame(this.animationId);
      this.animationId = null;
    }
  }
};
