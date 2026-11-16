"use strict";
(() => {
  const THEME_KEY = "wg-basic-theme";
  const applyTheme = (choice) => {
    const root = document.documentElement;
    if (choice === "light" || choice === "dark") root.setAttribute("data-theme", choice);
    else root.removeAttribute("data-theme");
  };
  const readStoredTheme = () => {
    try {
      const value = localStorage.getItem(THEME_KEY);
      return value === "light" || value === "dark" || value === "system" ? value : "system";
    } catch (_) {
      return "system";
    }
  };
  const persistTheme = (choice) => {
    try {
      if (choice === "system") localStorage.removeItem(THEME_KEY);
      else localStorage.setItem(THEME_KEY, choice);
    } catch (_) { /* theme preference is best-effort */ }
  };
  applyTheme(readStoredTheme());
  const select = document.getElementById("theme-select");
  if (select) {
    select.value = readStoredTheme();
    select.addEventListener("change", () => {
      const choice = select.value === "light" || select.value === "dark" ? select.value : "system";
      persistTheme(choice);
      applyTheme(choice);
    });
  }
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  const onSystemChange = () => { if (readStoredTheme() === "system") applyTheme("system"); };
  if (typeof media.addEventListener === "function") media.addEventListener("change", onSystemChange);
  else if (typeof media.addListener === "function") media.addListener(onSystemChange);

  const status = document.getElementById("status");
  const link = document.getElementById("download");
  const token = new URLSearchParams(location.hash.slice(1)).get("token");
  history.replaceState(null, "", location.pathname);
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) { status.textContent = "This enrollment link is invalid or unavailable."; return; }
  const match = /^\/enroll\/([0-9a-f-]{36})$/.exec(location.pathname);
  if (!match) { status.textContent = "This enrollment link is invalid or unavailable."; return; }
  const capability = match[1];
  addEventListener("pagehide", () => { document.body.replaceChildren(); }, { once: true });
  fetch(`/api/v1/enroll/${capability}/consume`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }), credentials: "same-origin", cache: "no-store", referrerPolicy: "no-referrer" })
    .then(async (response) => { if (!response.ok) throw new Error(); return response.text(); })
    .then((config) => { const url = URL.createObjectURL(new Blob([config], { type: "text/plain" })); link.href = url; link.download = "wireguard.conf"; link.hidden = false; status.textContent = "Your configuration is ready. Download it now."; })
    .catch(() => { status.textContent = "This enrollment link is invalid or unavailable."; });
})();
