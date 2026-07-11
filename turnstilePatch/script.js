// Patch MouseEvent screenX/screenY so Turnstile doesn't reject headless/automation.
// Runs at document_start in MAIN world for all frames including Turnstile iframes.
(function () {
  try {
    const rand = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
    const sx = rand(800, 1400);
    const sy = rand(400, 900);
    try {
      Object.defineProperty(MouseEvent.prototype, "screenX", { get: function () { return sx; }, configurable: true });
      Object.defineProperty(MouseEvent.prototype, "screenY", { get: function () { return sy; }, configurable: true });
    } catch (e) {}
    // Mark environment for debugging
    window.__tp_loaded = true;
  } catch (e) {}
})();
