(() => {
  const rand = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
  const sx = rand(900, 1600);
  const sy = rand(500, 1000);

  try {
    Object.defineProperty(MouseEvent.prototype, "screenX", { get() { return sx; }, configurable: true });
    Object.defineProperty(MouseEvent.prototype, "screenY", { get() { return sy; }, configurable: true });
  } catch (e) {}

  // Reduce automation signals early
  try {
    Object.defineProperty(navigator, "webdriver", { get: () => undefined, configurable: true });
  } catch (e) {}
  try {
    if (!window.chrome) window.chrome = { runtime: {} };
  } catch (e) {}
  try {
    Object.defineProperty(navigator, "languages", { get: () => ["en-US", "en"], configurable: true });
  } catch (e) {}
  try {
    Object.defineProperty(navigator, "plugins", {
      get: () => [1, 2, 3, 4, 5],
      configurable: true,
    });
  } catch (e) {}

  // Hook turnstile.render to capture sitekey / force interactive
  const hook = () => {
    try {
      if (!window.turnstile || window.__tp_hooked) return;
      window.__tp_hooked = true;
      const originalRender = window.turnstile.render.bind(window.turnstile);
      window.turnstile.render = (el, opts = {}) => {
        try {
          window.__tp_sitekey = opts.sitekey || opts["sitekey"];
          // Prefer managed/non-invisible so checkbox can be clicked
          if (opts.appearance === "execute") opts.appearance = "always";
          if (opts.size === "invisible" || opts.size === "compact") opts.size = "normal";
          const cb = opts.callback;
          opts.callback = (token) => {
            try {
              window.__tp_token = token;
              const input = document.querySelector('input[name="cf-turnstile-response"]');
              if (input) {
                input.value = token;
                input.dispatchEvent(new Event("input", { bubbles: true }));
                input.dispatchEvent(new Event("change", { bubbles: true }));
              }
            } catch (e) {}
            if (typeof cb === "function") cb(token);
          };
        } catch (e) {}
        return originalRender(el, opts);
      };
    } catch (e) {}
  };

  const iv = setInterval(hook, 50);
  setTimeout(() => clearInterval(iv), 30000);
  document.addEventListener("DOMContentLoaded", hook);
})();
