/**
 * controls.js — Shared Viewport Interaction Controls
 * 
 * Phase 2 Step 1: Mouse/trackpad input bindings for 3D viewport.
 * Controls bind dynamically to whichever render currently holds
 * primary status. Thumbnail is explicitly excluded.
 * 
 * Dependencies: Three.js (loaded via CDN in index.html)
 */

const ViewportControls = (() => {
  'use strict';

  let _orbitControls = null;
  let _activeCamera = null;
  let _activeRenderer = null;
  let _domElement = null;

  // Camera change listeners for chrome subsystem (Step 7B)
  const _cameraChangeListeners = [];
  let _lastCameraMatrix = null;
  let _cameraChangePending = false;

  /**
   * Initialize OrbitControls on the given Three.js camera + renderer.
   * Re-calling this re-binds controls to a new target (used by render_swap.js).
   */
  function bind(camera, renderer, domElement) {
    // Dispose previous controls if switching target
    if (_orbitControls) {
      _orbitControls.dispose();
    }

    _activeCamera = camera;
    _activeRenderer = renderer;
    _domElement = domElement;

    // THREE.OrbitControls — standard interaction model
    _orbitControls = new THREE.OrbitControls(camera, domElement);

    // Configuration: smooth, damped controls
    _orbitControls.enableDamping = true;
    _orbitControls.dampingFactor = 0.08;
    _orbitControls.rotateSpeed = 0.6;
    _orbitControls.zoomSpeed = 1.2;
    _orbitControls.panSpeed = 0.8;
    _orbitControls.minDistance = 1.5;
    _orbitControls.maxDistance = 20;

    // Enable all interaction modes
    _orbitControls.enableRotate = true;
    _orbitControls.enableZoom = true;
    _orbitControls.enablePan = true;

    // Mouse button mapping
    _orbitControls.mouseButtons = {
      LEFT: THREE.MOUSE.ROTATE,
      MIDDLE: THREE.MOUSE.DOLLY,
      RIGHT: THREE.MOUSE.PAN,
    };

    // Touch support
    _orbitControls.touches = {
      ONE: THREE.TOUCH.ROTATE,
      TWO: THREE.TOUCH.DOLLY_PAN,
    };

    // Store initial camera matrix for change detection
    _lastCameraMatrix = camera.matrixWorld.clone();

    // Listen for control changes → emit cameraChanged
    _orbitControls.addEventListener('change', _onCameraChange);

    // Double-click to reset camera
    domElement.addEventListener('dblclick', resetCamera);
  }

  /**
   * Called when OrbitControls detects camera movement.
   * Throttled to avoid flooding the chrome subsystem.
   */
  function _onCameraChange() {
    if (!_cameraChangePending) {
      _cameraChangePending = true;
      requestAnimationFrame(() => {
        _cameraChangePending = false;
        // Notify all listeners (annotations, leader lines, etc.)
        for (const listener of _cameraChangeListeners) {
          listener(_activeCamera);
        }
      });
    }
  }

  /**
   * Register a callback for camera change events.
   * Used by the chrome subsystem (Step 7B) for leader-line re-projection.
   */
  function onCameraChange(callback) {
    _cameraChangeListeners.push(callback);
  }

  /**
   * Reset camera to default position with smooth animation.
   */
  function resetCamera() {
    if (!_activeCamera || !_orbitControls) return;

    const startPos = _activeCamera.position.clone();
    const startTarget = _orbitControls.target.clone();
    const endPos = new THREE.Vector3(0, 0, 5);
    const endTarget = new THREE.Vector3(0, 0, 0);

    const duration = 600; // ms
    const startTime = performance.now();

    function animate(now) {
      const elapsed = now - startTime;
      const t = Math.min(elapsed / duration, 1);
      // Ease-out cubic
      const ease = 1 - Math.pow(1 - t, 3);

      _activeCamera.position.lerpVectors(startPos, endPos, ease);
      _orbitControls.target.lerpVectors(startTarget, endTarget, ease);
      _orbitControls.update();

      if (t < 1) {
        requestAnimationFrame(animate);
      }
    }
    requestAnimationFrame(animate);
  }

  /**
   * Must be called in the render loop to apply damping.
   */
  function update() {
    if (_orbitControls) {
      _orbitControls.update();
    }
  }

  /**
   * Dispose controls and clean up event listeners.
   */
  function dispose() {
    if (_orbitControls) {
      _orbitControls.removeEventListener('change', _onCameraChange);
      _orbitControls.dispose();
      _orbitControls = null;
    }
    if (_domElement) {
      _domElement.removeEventListener('dblclick', resetCamera);
      _domElement = null;
    }
    _cameraChangeListeners.length = 0;
  }

  /**
   * Get the current OrbitControls instance (for external configuration).
   */
  function getControls() {
    return _orbitControls;
  }

  return {
    bind,
    update,
    resetCamera,
    onCameraChange,
    dispose,
    getControls,
  };
})();
