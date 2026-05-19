/**
 * render_swap.js — Dual-Render State Machine (Step 2C)
 * 
 * Manages the primary/thumbnail viewport layout with a "Liquid Glass"
 * 300ms swap animation. Clicking the thumbnail promotes it to primary.
 * 
 * State: { primary: 'morphology'|'markov', swapping: bool }
 * 
 * Dependencies: controls.js, Three.js
 */

const RenderSwap = (() => {
  'use strict';

  // State
  let _state = { primary: 'morphology', swapping: false };

  // DOM references (set during init)
  let _primarySlot = null;
  let _thumbSlot = null;
  let _primaryOverlay = null;  // label overlay on primary
  let _thumbOverlay = null;    // label overlay on thumbnail

  // Render instances (set externally via registerRender)
  const _renders = {};

  /**
   * Initialize the swap system.
   * Called once after DOM is ready.
   */
  function init() {
    _primarySlot = document.getElementById('viewport-primary');
    _thumbSlot = document.getElementById('viewport-thumb');

    if (!_primarySlot || !_thumbSlot) {
      console.warn('[RenderSwap] Viewport slots not found in DOM');
      return;
    }

    // Thumbnail click → swap
    _thumbSlot.addEventListener('click', swap);
    _thumbSlot.setAttribute('role', 'button');
    _thumbSlot.setAttribute('tabindex', '0');
    _thumbSlot.setAttribute('aria-label', 'Click to swap viewport');

    // Keyboard accessibility
    _thumbSlot.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        swap();
      }
    });

    _updateLabels();
  }

  /**
   * Register a render instance.
   * @param {string} name - 'morphology' or 'markov'
   * @param {object} render - { canvas, camera, renderer, scene, resize() }
   */
  function registerRender(name, render) {
    _renders[name] = render;

    // Determine target slot
    const targetSlot = (name === _state.primary) ? _primarySlot : _thumbSlot;

    // Only mount if canvas isn't already in the correct slot
    // (renderers mount their own canvases during render())
    if (targetSlot && render.canvas && render.canvas.parentNode !== targetSlot) {
      _mountToSlot(name, targetSlot);
    }
  }

  /**
   * Move a render's canvas into a DOM slot.
   */
  function _mountToSlot(name, slot) {
    const render = _renders[name];
    if (!render || !render.canvas) return;

    // Append canvas to slot
    slot.appendChild(render.canvas);

    // Resize to fit slot
    requestAnimationFrame(() => {
      if (render.resize) {
        render.resize(slot.clientWidth, slot.clientHeight);
      }
    });
  }

  /**
   * Swap primary and thumbnail renders with Liquid Glass animation.
   */
  function swap() {
    if (_state.swapping) return;
    if (Object.keys(_renders).length < 2) return;

    _state.swapping = true;

    const currentPrimary = _state.primary;
    const currentThumb = currentPrimary === 'morphology' ? 'markov' : 'morphology';

    // Phase 1: Fade both slots
    _primarySlot.classList.add('swap-out');
    _thumbSlot.classList.add('swap-out');

    setTimeout(() => {
      // Phase 2: Physically swap canvases
      _state.primary = currentThumb;

      // Phase 2: Remove all canvases from both slots (order-independent)
      const removeCanvases = (slot) => {
        const canvases = Array.from(slot.querySelectorAll('canvas'));
        canvases.forEach(c => c.remove());
      };
      removeCanvases(_primarySlot);
      removeCanvases(_thumbSlot);

      // Re-mount in new positions
      _mountToSlot(_state.primary, _primarySlot);
      _mountToSlot(currentPrimary, _thumbSlot);

      // Re-bind viewport controls to new primary
      const newPrimary = _renders[_state.primary];
      if (newPrimary && ViewportControls) {
        ViewportControls.bind(newPrimary.camera, newPrimary.renderer, _primarySlot);
      }

      _updateLabels();

      // Phase 3: Fade in
      _primarySlot.classList.remove('swap-out');
      _thumbSlot.classList.remove('swap-out');
      _primarySlot.classList.add('swap-in');
      _thumbSlot.classList.add('swap-in');

      setTimeout(() => {
        _primarySlot.classList.remove('swap-in');
        _thumbSlot.classList.remove('swap-in');
        _state.swapping = false;

        // Emit event for chrome subsystem
        document.dispatchEvent(new CustomEvent('renderSwapped', {
          detail: { primary: _state.primary }
        }));
      }, 300);
    }, 150);
  }

  /**
   * Update viewport label overlays.
   */
  function _updateLabels() {
    const primaryLabel = _primarySlot?.querySelector('.viewport-label');
    const thumbLabel = _thumbSlot?.querySelector('.viewport-label');

    const names = {
      'morphology': 'Morphological Mugshot',
      'markov': 'Toroidal Fingerprint',
    };

    if (primaryLabel) primaryLabel.textContent = names[_state.primary] || _state.primary;
    if (thumbLabel) {
      const thumbName = _state.primary === 'morphology' ? 'markov' : 'morphology';
      thumbLabel.textContent = names[thumbName] || thumbName;
    }
  }

  /**
   * Get current state.
   */
  function getState() {
    return { ..._state };
  }

  /**
   * Get the currently primary render name.
   */
  function getPrimary() {
    return _state.primary;
  }

  return {
    init,
    registerRender,
    swap,
    getState,
    getPrimary,
  };
})();
