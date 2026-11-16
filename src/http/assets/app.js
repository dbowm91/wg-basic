(() => {
  "use strict";
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

  let csrf = null;
  let totpPreSession = null;
  let generation = 0;
  let clients = [];
  let telemetry = new Map();
  let telemetryStatus = "idle";
  let telemetryHistory = new Map();
  let telemetryHistoryStatus = "idle";
  let auditCursor = null;
  let poll = null;
  let artifactUrl = null;

  const $ = (id) => document.getElementById(id);
  const form = (id) => Object.fromEntries(new FormData($(id)).entries());
  const setVisible = (id, value) => { $(id).hidden = !value; };
  const banner = () => $("banner");
  const clearBanner = () => { const el = banner(); el.textContent = ""; el.hidden = true; };
  const message = (text, level = "info") => {
    const el = banner();
    el.dataset.level = level;
    el.setAttribute("aria-live", level === "danger" ? "assertive" : "polite");
    el.textContent = text;
    el.hidden = false;
  };
  // The status banner follows the operator's attention: while the client editor
  // is open it lives inside the dialog, so a conflict or a pending-enforcement
  // notice is read where it was raised rather than behind the modal backdrop.
  const moveBanner = (host) => { const el = banner(); if (el.parentElement !== host) host.insertBefore(el, host.firstElementChild); };
  const json = (response) => response.json().catch(() => ({}));

  async function api(method, path, body) {
    const headers = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (csrf) headers["x-wg-basic-csrf"] = csrf;
    const response = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin", redirect: "error" });
    if (response.status === 401 && csrf && path !== "/api/v1/login") void showSignedOut();
    return response;
  }

  function familyRoutes(data, family) {
    const mode = data[`routes_${family}_mode`];
    if (mode === "full") return [family === "v4" ? "0.0.0.0/0" : "::/0"];
    if (mode === "split") return data[`routes_${family}_prefixes`].split(",").map((value) => value.trim()).filter(Boolean);
    return [];
  }

  function routePolicy(data) {
    return { prefixes: [...familyRoutes(data, "v4"), ...familyRoutes(data, "v6")] };
  }

  function setRouteFields(formElement, policy) {
    for (const family of ["v4", "v6"]) {
      const full = family === "v4" ? "0.0.0.0/0" : "::/0";
      const matching = policy.prefixes.filter((prefix) => family === "v4" ? prefix.includes(".") : prefix.includes(":"));
      const hasFull = matching.includes(full);
      formElement.elements[`routes_${family}_mode`].value = hasFull && matching.length === 1 ? "full" : matching.length ? "split" : "none";
      formElement.elements[`routes_${family}_prefixes`].value = hasFull && matching.length === 1 ? "" : matching.join(", ");
    }
  }

  function explainMutation(response, result, removing) {
    if (response.status === 409) {
      void loadConsole().then(() => message("Configuration changed elsewhere. Current state has been refreshed; review it and try again.", "warning"));
      return false;
    }
    if (!response.ok) { message("The change could not be saved. Check the values and try again.", "danger"); return false; }
    if (response.status === 202 || result.enforcement !== "converged") {
      message(removing
        ? "Saved, but network access has not been confirmed revoked. The server is still applying this change."
        : "Saved; network application is pending or degraded. The server is still applying this change.", "warning");
    } else clearBanner();
    generation = result.generation;
    return true;
  }

  async function refreshAfterMutation(response, result, removing) {
    if (!explainMutation(response, result, removing)) return false;
    const pending = response.status === 202 || result.enforcement !== "converged";
    const notice = pending ? banner().textContent : "";
    const level = pending ? banner().dataset.level : "info";
    await loadConsole();
    if (notice) message(notice, level);
    return true;
  }

  function stopPolling() {
    if (poll !== null) window.clearInterval(poll);
    poll = null;
  }

  function startPolling() {
    stopPolling();
    poll = window.setInterval(() => { if (!document.hidden && csrf) void loadTelemetry(); }, 7000);
  }

  function resetLoginPane() {
    totpPreSession = null;
    setVisible("login-totp-form", false);
    setVisible("login-form", true);
    $("login-totp-form").reset();
  }

  function parseAutoLaunchEscape() {
    const params = new URLSearchParams(window.location.search);
    return params.get("auto_launch") === "false";
  }

  async function refreshIdpLogin() {
    const buttons = $("idp-provider-buttons");
    if (buttons) buttons.replaceChildren();
    setVisible("idp-provider-buttons", false);
    setVisible("idp-recovery-note", false);
    try {
      const response = await fetch("/api/v1/auth/public", {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) return;
      const view = await json(response);
      setVisible("login-form", Boolean(view.password_auth_enabled));
      if (view.recovery_only) {
        setVisible("login-form", false);
        setVisible("idp-recovery-note", true);
        return;
      }
      const providers = (view.providers || []).filter((entry) => entry.login_enabled);
      for (const entry of providers) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "secondary";
        button.textContent = entry.display_name || entry.key;
        button.addEventListener("click", () => { window.location.assign(entry.login_path); });
        buttons.append(button);
      }
      setVisible("idp-provider-buttons", providers.length > 0);
      if (!parseAutoLaunchEscape() && view.auto_launch && providers.some((p) => p.key === view.auto_launch)) {
        const target = providers.find((p) => p.key === view.auto_launch);
        if (target) window.location.assign(target.login_path);
      }
    } catch (_) {
      setVisible("idp-provider-buttons", false);
    }
  }

  async function showSignedOut() {
    csrf = null;
    totpPreSession = null;
    resetLoginPane();
    void refreshIdpLogin();
    stopPolling();
    setVisible("logout", false); setVisible("account", false); setVisible("account-pane", false);
    setVisible("login-pane", true);
    setVisible("setup-pane", false); setVisible("app-pane", false);
    telemetryStatus = "idle";
    telemetry = new Map();
    telemetryHistoryStatus = "idle";
    telemetryHistory = new Map();
    closeClientDialog();
  }

  function wireThemeSwitcher() {
    const select = $("theme-select");
    if (!select || select.dataset.wired === "1") return;
    select.dataset.wired = "1";
    select.value = readStoredTheme();
    select.addEventListener("change", () => {
      const choice = select.value === "light" || select.value === "dark" ? select.value : "system";
      persistTheme(choice);
      applyTheme(choice);
    });
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onSystemChange = () => { if (readStoredTheme() === "system") applyTheme("system"); };
    if (typeof media.addEventListener === "function") media.addEventListener("change", onSystemChange);
    else if (typeof media.addListener === "function") media.addListener(onSystemChange);
  }

  async function loadSession() {
    const response = await api("GET", "/api/v1/session");
    if (!response.ok) { await showSignedOut(); return false; }
    const session = await json(response);
    csrf = session.csrf_token;
    setVisible("logout", true); setVisible("account", true); setVisible("login-pane", false);
    return true;
  }

  function renderTotpAccount(account) {
    const enabled = Boolean(account.totp_enabled);
    $("totp-status").textContent = enabled
      ? "Authenticator app second factor is enabled."
      : "Authenticator app second factor is not enabled.";
    setVisible("totp-disabled-controls", !enabled);
    setVisible("totp-enroll-controls", false);
    setVisible("totp-disable-form", enabled);
    $("totp-qr").replaceChildren();
    if ($("totp-confirm-code")) $("totp-confirm-code").value = "";
  }

  async function loadOidcSettings() {
    const response = await api("GET", "/api/v1/auth/oidc/settings");
    if (!response.ok) {
      $("oidc-settings-note").textContent = "OIDC settings could not be loaded.";
      return;
    }
    const settings = await json(response);
    $("oidc-issuer").value = settings.issuer || "";
    $("oidc-client-id").value = settings.client_id || "";
    $("oidc-display-name").value = settings.display_name || "";
    $("oidc-enabled").checked = Boolean(settings.enabled);
    $("oidc-client-secret").value = "";
    const secretNote = settings.client_secret_configured
      ? "A client secret is stored. Enter a new value to replace it."
      : "No client secret is stored yet.";
    $("oidc-settings-note").textContent = secretNote;
  }

  async function saveOidcSettings(event) {
    event.preventDefault();
    clearBanner();
    const data = form("oidc-settings-form");
    const patch = {
      issuer: data.issuer,
      client_id: data.client_id,
      display_name: data.display_name,
      enabled: $("oidc-enabled").checked,
    };
    if (data.set_client_secret) patch.set_client_secret = data.set_client_secret;
    const response = await api("PATCH", "/api/v1/auth/oidc/settings", patch);
    if (!response.ok) {
      message("OIDC settings could not be saved. Check values and HTTPS canonical origin.", "danger");
      return;
    }
    $("oidc-client-secret").value = "";
    await loadOidcSettings();
    message("OIDC settings saved.", "info");
  }

  async function loadAccount() {
    const response = await api("GET", "/api/v1/account");
    if (!response.ok) { message("Account settings could not be loaded.", "danger"); return; }
    const account = await json(response);
    const totpNote = account.totp_enabled ? " TOTP is enabled." : "";
    $("account-summary").textContent = `Signed in as ${account.username}. Password authentication is enabled.${totpNote}`;
    renderTotpAccount(account);
    await loadOidcSettings();
  }

  async function openAccount() {
    clearBanner();
    setVisible("account-pane", true);
    await loadAccount();
  }

  function closeAccount() {
    setVisible("account-pane", false);
    $("password-form").reset();
    $("totp-disable-form").reset();
    setVisible("totp-enroll-controls", false);
    $("totp-qr").replaceChildren();
  }

  async function beginTotpEnroll() {
    clearBanner();
    const response = await api("POST", "/api/v1/account/totp/begin", {});
    const payload = await json(response);
    if (!response.ok) {
      message("TOTP enrollment could not be started.", "danger");
      return;
    }
    setVisible("totp-disabled-controls", false);
    setVisible("totp-enroll-controls", true);
    const shell = $("totp-qr");
    shell.replaceChildren();
    shell.insertAdjacentHTML("beforeend", payload.qr_svg);
  }

  async function confirmTotpEnroll() {
    clearBanner();
    const code = $("totp-confirm-code").value.trim();
    const response = await api("POST", "/api/v1/account/totp/confirm", { code });
    if (response.status === 204) {
      message("Authenticator second factor is enabled.", "info");
      await loadAccount();
      return;
    }
    message("The verification code was not accepted.", "danger");
  }

  async function disableTotp(event) {
    event.preventDefault();
    clearBanner();
    const data = form("totp-disable-form");
    const response = await api("POST", "/api/v1/account/totp/disable", data);
    if (response.status === 204) {
      $("totp-disable-form").reset();
      message("Authenticator second factor is disabled.", "info");
      await loadAccount();
      return;
    }
    if (response.status === 401) {
      message("The password or authenticator code was not accepted.", "danger");
      return;
    }
    message("TOTP could not be disabled right now.", "danger");
  }

  async function changePassword(event) {
    event.preventDefault();
    clearBanner();
    const data = form("password-form");
    if (data.new_password !== data.confirm_password) {
      message("New password and confirmation do not match.", "danger");
      return;
    }
    const response = await api("POST", "/api/v1/account/password", {
      current_password: data.current_password,
      new_password: data.new_password,
    });
    if (response.status === 204) {
      $("password-form").reset();
      message("Password changed. Other signed-in sessions were signed out.", "info");
      return;
    }
    if (response.status === 401) {
      message("The current password was not accepted.", "danger");
      return;
    }
    message("The password could not be changed right now.", "danger");
  }

  async function loadConsole() {
    if (!await loadSession()) return;
    clearBanner();
    const healthResponse = await api("GET", "/api/v1/health");
    const serverResponse = await api("GET", "/api/v1/server");
    if (!serverResponse.ok) { message("The server settings could not be loaded.", "danger"); return; }
    const summary = await json(serverResponse);
    generation = summary.generation;
    if (!summary.server) {
      setVisible("setup-pane", true); setVisible("app-pane", false); stopPolling();
      await applySetupDefaults();
      return;
    }
    setVisible("setup-pane", false); setVisible("app-pane", true);
    await renderServer(summary.server, healthResponse.ok ? await json(healthResponse) : {});
    await Promise.all([loadClients(), loadAudit(true), loadTelemetry()]);
    startPolling();
  }

  function renderServer(server, health) {
    const container = $("health-summary");
    container.replaceChildren();
    const values = [
      ["Backend", health.backend?.answered ? "reachable" : "unavailable"],
      ["Endpoint", server.advertised_endpoint],
      ["Listen port", String(server.listen_port)],
      ["Generation", String(generation)],
      ["Network", `${server.name} · ${server.tunnel_prefix}`],
    ];
    if (server.ipv6_tunnel_prefix) {
      values.push(["IPv6 tunnel", `${server.ipv6_server_address} · ${server.ipv6_tunnel_prefix}`]);
    }
    for (const [label, value] of values) {
      const card = document.createElement("div"); card.className = "card";
      const title = document.createElement("span"); title.className = "card-label"; title.textContent = label;
      const output = document.createElement("strong"); output.textContent = value;
      card.append(title, output); container.append(card);
    }
    const healthNote = $("health-note");
    healthNote.textContent = health.health?.convergence && health.health.convergence !== "converged"
      ? "The saved network settings have not been confirmed on the server yet."
      : "Server settings are saved. Client connection details are only shown when you request an export.";
  }

  async function loadClients() {
    const response = await api("GET", "/api/v1/clients");
    if (!response.ok) { message("Clients could not be loaded.", "danger"); return; }
    const data = await json(response); generation = data.generation; clients = data.clients;
    renderClients();
  }

  function clientCell(text, className) {
    const cell = document.createElement("td");
    if (className) cell.className = className;
    cell.textContent = text;
    return cell;
  }

  function renderClients() {
    const tbody = $("client-rows"); tbody.replaceChildren();
    const filters = form("client-filters");
    const query = filters.query.trim().toLowerCase();
    const visible = clients.filter((client) => {
      const addresses = [client.assigned_address, client.assigned_ipv6_address].filter(Boolean).join(" ");
      const haystack = `${client.settings.label} ${addresses}`.toLowerCase();
      if (query && !haystack.includes(query)) return false;
      if (filters.enabled === "enabled" && client.settings.enabled !== "enabled") return false;
      if (filters.enabled === "disabled" && client.settings.enabled === "enabled") return false;
      if (filters.expiry !== "all" && client.expiry_state !== filters.expiry) return false;
      return true;
    });
    const hasClients = clients.length > 0;
    const hasVisible = visible.length > 0;
    setVisible("empty-clients", !hasClients);
    setVisible("empty-clients-filtered", hasClients && !hasVisible);
    setVisible("client-table-wrap", hasVisible);
    setVisible("empty-telemetry", hasClients && telemetryStatus === "ok" && telemetry.size === 0);
    const counts = $("health-summary");
    counts.querySelectorAll("[data-product-count]").forEach((item) => item.remove());
    for (const [label, value] of [
      ["Enabled clients", clients.filter((row) => row.settings.enabled === "enabled").length],
      ["Disabled clients", clients.filter((row) => row.settings.enabled !== "enabled").length],
      ["Observed clients", telemetry.size],
    ]) {
      const card = document.createElement("div"); card.className = "card"; card.dataset.productCount = "true";
      const title = document.createElement("span"); title.className = "card-label"; title.textContent = label;
      const output = document.createElement("strong"); output.textContent = String(value); card.append(title, output); counts.append(card);
    }
    for (const client of visible) {
      const row = document.createElement("tr");
      const live = telemetry.get(client.client_id);
      const expiry = client.expiry_state && client.expiry_state !== "none" ? ` · ${client.expiry_state}` : "";
      const state = (client.settings.enabled === "enabled" ? (live?.observation ?? "unknown") : "disabled") + expiry;
      const drift = live?.drift ? " · needs attention" : "";
      const handshake = live?.latest_handshake_age_seconds == null ? "Never" : `${live.latest_handshake_age_seconds}s ago`;
      const addresses = [client.assigned_address, client.assigned_ipv6_address].filter(Boolean).join(" · ");
      const trafficCell = document.createElement("td");
      trafficCell.className = "col-metric";
      const trafficSummary = document.createElement("span");
      trafficSummary.textContent = live?.rx_bytes == null ? "—" : `↓ ${bytes(live.rx_bytes)} · ↑ ${bytes(live.tx_bytes)}`;
      trafficCell.append(trafficSummary);
      const sparkHost = document.createElement("div");
      sparkHost.className = "sparkline";
      if (telemetryHistoryStatus === "ok" && globalThis.wgBasicSparkline) {
        globalThis.wgBasicSparkline.render(sparkHost, telemetryHistory.get(client.client_id) ?? []);
      } else if (telemetryHistoryStatus === "unavailable") {
        const empty = document.createElement("span");
        empty.className = "sparkline-empty";
        empty.textContent = "History unavailable";
        sparkHost.append(empty);
      }
      if (sparkHost.childElementCount > 0) trafficCell.append(sparkHost);
      row.append(
        clientCell(client.settings.label, "col-name"),
        clientCell(addresses, "col-address"),
        clientCell(state + drift, live?.drift ? "col-state state-warn" : "col-state"),
        clientCell(handshake, "col-metric"),
        trafficCell,
      );
      const actions = document.createElement("td"); actions.className = "actions col-actions";
      actions.append(action("Edit", "edit", client.client_id, client.settings.label));
      actions.append(action(client.settings.enabled === "enabled" ? "Disable" : "Enable", "toggle", client.client_id, client.settings.label));
      actions.append(action("Delete", "delete", client.client_id, client.settings.label)); row.append(actions); tbody.append(row);
    }
  }

  function action(label, actionName, id, clientName) {
    const button = document.createElement("button"); button.type = "button"; button.className = "small secondary";
    button.textContent = label; button.setAttribute("aria-label", `${label} ${clientName}`); button.dataset.action = actionName; button.dataset.id = id; return button;
  }

  function bytes(value) {
    if (value < 1024) return `${value} B`;
    const units = ["KiB", "MiB", "GiB", "TiB"]; let size = value;
    for (const unit of units) { size /= 1024; if (size < 1024) return `${size.toFixed(1)} ${unit}`; }
    return `${size.toFixed(1)} PiB`;
  }

  async function loadTelemetry() {
    if (!csrf || document.hidden) return;
    const [response, historyResponse] = await Promise.all([
      api("GET", "/api/v1/clients/telemetry"),
      api("GET", "/api/v1/clients/telemetry-history"),
    ]);
    if (!response.ok) {
      telemetryStatus = "unavailable";
      telemetry = new Map();
      $("health-note").textContent = "Live network status is unavailable; saved client settings are unchanged.";
    } else {
      telemetryStatus = "ok";
      const snapshot = await json(response);
      telemetry = new Map(snapshot.clients.map((row) => [row.client_id, row]));
      $("health-note").textContent = snapshot.truncated
        ? `Live status refreshed. ${snapshot.unassociated_peer_count} unassociated peers; client list is truncated.`
        : `Live status refreshed · ${snapshot.unassociated_peer_count} unassociated peers.`;
    }
    if (!historyResponse.ok) {
      telemetryHistoryStatus = historyResponse.status === 503 ? "unavailable" : "empty";
      telemetryHistory = new Map();
    } else {
      telemetryHistoryStatus = "ok";
      const history = await json(historyResponse);
      telemetryHistory = new Map(history.clients.map((row) => [row.client_id, row.points]));
    }
    renderClients();
  }

  async function loadAudit(reset) {
    if (reset) { auditCursor = null; $("audit-list").replaceChildren(); }
    const path = auditCursor ? `/api/v1/audit/${auditCursor.occurred_at}/${auditCursor.event_id}` : "/api/v1/audit";
    const response = await api("GET", path);
    if (!response.ok) return;
    const page = await json(response); auditCursor = page.next_cursor;
    setVisible("more-audit", Boolean(auditCursor));
    setVisible("empty-audit", $("audit-list").childElementCount === 0 && page.events.length === 0);
    for (const event of page.events) {
      const item = document.createElement("li");
      const title = document.createElement("strong"); title.textContent = event.action.replaceAll("_", " ");
      const detail = document.createElement("span"); detail.textContent = ` · ${event.resource_kind} ${event.resource_id ?? ""} · ${new Date(event.occurred_at * 1000).toLocaleString()}`;
      item.append(title, detail); $("audit-list").append(item);
    }
  }

  async function submitSetup(event) {
    event.preventDefault(); clearBanner(); const data = form("setup-form");
    const body = {
      expected_generation: generation, interface_name: data.interface_name,
      tunnel_prefix: data.tunnel_prefix, server_address: data.server_address,
      listen_port: Number(data.listen_port), advertised_endpoint: data.advertised_endpoint,
      egress_interface: data.egress_interface, ipv4_forwarding_required: $("setup-form").elements.ipv4_forwarding_required.checked,
      ipv6_forwarding_required: $("setup-form").elements.ipv6_forwarding_required.checked,
      masquerade: $("setup-form").elements.masquerade.checked,
      default_client_route_policy: routePolicy(data),
    };
    if (data.ipv6_tunnel_prefix.trim()) body.ipv6_tunnel_prefix = data.ipv6_tunnel_prefix.trim();
    if (data.ipv6_server_address.trim()) body.ipv6_server_address = data.ipv6_server_address.trim();
    // The routing intent is only stated when it is the one that cannot be
    // derived: everything else follows from the forwarding and masquerade
    // settings, exactly as it did before the routed-LAN mode existed.
    if (data.network_mode === "gateway") body.mode = "gateway";
    if (data.network_mode === "routed_lan") {
      body.mode = "routed_lan";
      body.destination_prefixes = data.destination_prefixes.split(",").map((value) => value.trim()).filter(Boolean);
    }
    const response = await api("POST", "/api/v1/setup", body); const result = await json(response);
    await refreshAfterMutation(response, result, false);
  }

  async function submitCreate(event) {
    event.preventDefault(); clearBanner(); const data = form("create-form");
    const serverResponse = await api("GET", "/api/v1/server");
    if (!serverResponse.ok) { message("The configured server could not be loaded; try again.", "danger"); return; }
    const server = await json(serverResponse);
    const body = { expected_generation: generation, interface_id: server.server.interface_id, label: data.label };
    if (data.ipv6_address.trim()) body.ipv6_address = data.ipv6_address.trim();
    if (data.dns_servers.trim()) body.dns_servers = data.dns_servers.split(",").map((x) => x.trim()).filter(Boolean);
    const createdDeadline = deadlineSeconds(data.expires_at);
    if (createdDeadline != null) body.expires_at = createdDeadline;
    if (data.mtu.trim()) body.mtu = Number(data.mtu);
    if ($("create-form").elements.preshared_key.checked) body.preshared_key = "generate";
    const response = await api("POST", "/api/v1/clients", body); const result = await json(response);
    if (await refreshAfterMutation(response, result, false)) { $("create-form").reset(); setVisible("create-form", false); }
  }

  function openClient(client) {
    const edit = $("edit-form"); edit.elements.client_id.value = client.client_id;
    edit.elements.label.value = client.settings.label; edit.elements.address.value = client.assigned_address.split("/")[0];
    edit.elements.ipv6_address.value = client.assigned_ipv6_address?.split("/")[0] ?? "";
    setRouteFields(edit, client.route_policy); edit.elements.dns_servers.value = client.dns_servers.join(", ");
    edit.elements.client_keepalive_seconds.value = client.settings.client_keepalive_seconds ?? "";
    edit.elements.expires_at.value = deadlineLocal(client.expires_at);
    edit.elements.mtu.value = client.mtu ?? "";
    $("preshared-note").textContent = client.preshared_key_configured
      ? "A preshared key is configured. Generating or clearing it changes the exported configuration. Devices must re-import it. The key is not shown on this page."
      : "No preshared key is configured. Generating one changes the exported configuration. Devices must re-import it. The key is not shown on this page.";
    $("artifact").replaceChildren(); setVisible("artifact", false); moveBanner($("client-dialog")); $("client-dialog").showModal();
  }

  function clearArtifact() {
    if (artifactUrl) URL.revokeObjectURL(artifactUrl);
    artifactUrl = null; $("artifact").replaceChildren(); setVisible("artifact", false);
  }

  function closeClientDialog() {
    const dialog = $("client-dialog"); if (dialog.open) dialog.close(); clearArtifact();
  }

  async function submitEdit(event) {
    event.preventDefault(); clearBanner(); const data = form("edit-form");
    const body = { expected_generation: generation, label: data.label, address: data.address, route_policy: routePolicy(data), dns_servers: data.dns_servers.split(",").map((x) => x.trim()).filter(Boolean), client_keepalive_seconds: data.client_keepalive_seconds === "" ? null : Number(data.client_keepalive_seconds), expires_at: deadlineSeconds(data.expires_at), mtu: data.mtu.trim() ? Number(data.mtu) : null };
    if (data.ipv6_address.trim()) body.ipv6_address = data.ipv6_address.trim();
    const response = await api("PATCH", `/api/v1/clients/${data.client_id}`, body); const result = await json(response);
    await refreshAfterMutation(response, result, false);
  }

  async function mutateClient(button) {
    const client = clients.find((item) => item.client_id === button.dataset.id); if (!client) return;
    if (button.dataset.action === "edit") { openClient(client); return; }
    if (button.dataset.action === "delete" && !window.confirm(`Delete ${client.settings.label}? Network access will be removed when the server applies the change.`)) return;
    const deleting = button.dataset.action === "delete";
    const disabling = button.dataset.action === "toggle" && client.settings.enabled === "enabled";
    const path = deleting ? `/api/v1/clients/${client.client_id}` : `/api/v1/clients/${client.client_id}/${disabling ? "disable" : "enable"}`;
    const payload = { expected_generation: generation };
    if (!deleting && !disabling && client.expiry_state === "expired") payload.expires_at = null;
    const response = await api(deleting ? "DELETE" : "POST", path, payload);
    const result = await json(response);
    await refreshAfterMutation(response, result, deleting || disabling);
  }

  function revealArtifact(target) {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    target.scrollIntoView({ block: "center", behavior: reduced ? "auto" : "smooth" });
  }

  async function artifact(kind) {
    const id = $("edit-form").elements.client_id.value; if (!id) return;
    clearBanner(); clearArtifact(); const target = $("artifact"); setVisible("artifact", true);
    if (kind === "config") {
      const response = await api("GET", `/api/v1/clients/${id}/config`);
      if (!response.ok) { message("Configuration export is unavailable.", "danger"); return; }
      artifactUrl = URL.createObjectURL(await response.blob());
      const link = document.createElement("a"); link.href = artifactUrl; link.download = `wg-client-${id}.conf`; link.textContent = "Download client configuration"; target.append(link);
      revealArtifact(target);
    } else if (kind === "qr") {
      const image = document.createElement("img"); image.src = `/api/v1/clients/${id}/qr`; image.alt = "WireGuard client configuration QR code"; image.className = "qr-image";
      image.addEventListener("load", () => revealArtifact(target), { once: true });
      image.addEventListener("error", () => { image.remove(); message("QR export is unavailable.", "danger"); }, { once: true }); target.append(image);
      if (image.complete && image.naturalWidth > 0) revealArtifact(target);
    } else {
      const response = await api("POST", `/api/v1/clients/${id}/enrollment-links`, { expires_in_seconds: 600 });
      const link = await json(response);
      if (!response.ok) { message("A one-time link could not be created.", "danger"); return; }
      const heading = document.createElement("p"); heading.textContent = `Share this link once. It reveals VPN credentials and expires ${new Date(link.expires_at * 1000).toLocaleString()}.`;
      const value = document.createElement("code"); value.className = "share-link"; value.textContent = link.share_url;
      const copy = document.createElement("button"); copy.type = "button"; copy.textContent = "Copy link"; copy.addEventListener("click", async () => { await navigator.clipboard.writeText(link.share_url); copy.textContent = "Copied"; });
      const revoke = document.createElement("button"); revoke.type = "button"; revoke.className = "secondary"; revoke.textContent = "Revoke link";
      revoke.addEventListener("click", async () => { const result = await api("DELETE", `/api/v1/enrollment-links/${link.capability_id}`); if (result.ok) { value.textContent = "Link revoked"; copy.disabled = true; revoke.disabled = true; } });
      target.append(heading, value, copy, revoke);
      revealArtifact(target);
    }
  }

  async function login(event) {
    event.preventDefault(); clearBanner(); const data = form("login-form");
    const response = await api("POST", "/api/v1/login", { username: data.username, password: data.password });
    $("login-form").elements.password.value = "";
    if (!response.ok) { message("Those credentials were not accepted.", "danger"); return; }
    const payload = await json(response);
    if (payload.totp_required) {
      totpPreSession = payload.pre_session_token;
      setVisible("login-form", false);
      setVisible("login-totp-form", true);
      return;
    }
    await loadConsole();
  }

  async function loginTotp(event) {
    event.preventDefault();
    clearBanner();
    if (!totpPreSession) { resetLoginPane(); return; }
    const data = form("login-totp-form");
    const response = await api("POST", "/api/v1/login/totp", {
      pre_session_token: totpPreSession,
      code: data.code,
    });
    if (!response.ok) {
      message("The authenticator code was not accepted.", "danger");
      return;
    }
    resetLoginPane();
    await loadConsole();
  }

  async function logout() {
    await api("POST", "/api/v1/logout"); await showSignedOut(); message("You have signed out.", "info");
  }

  let setupTouched = false;
  let prerequisites = null;

  function deadlineSeconds(value) {
    if (!value) return null;
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return null;
    return Math.floor(parsed.getTime() / 1000);
  }

  function deadlineLocal(seconds) {
    if (seconds == null) return "";
    const date = new Date(seconds * 1000);
    const pad = (part) => String(part).padStart(2, "0");
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  function renderAttachment() {
    const box = $("setup-attachment");
    box.replaceChildren();
    if (!prerequisites || prerequisites.host_platform !== "macos") return;
    const mode = $("setup-form").elements.network_mode.value;
    if (mode !== "gateway" && mode !== "routed_lan") return;
    const note = document.createElement("p");
    note.textContent = "The product will not write these lines. An administrator has to add them.";
    box.append(note);
    if (mode === "gateway" && prerequisites.attachment) {
      for (const line of [prerequisites.attachment.nat_anchor, prerequisites.attachment.filter_anchor, prerequisites.attachment.load_anchor]) {
        const row = document.createElement("code");
        row.textContent = line;
        box.append(row);
      }
    }
    if (mode === "routed_lan") {
      for (const rule of prerequisites.required_filter_rules || []) {
        const row = document.createElement("code");
        row.textContent = rule;
        box.append(row);
      }
    }
  }

  async function applySetupDefaults() {
    if (setupTouched) return;
    const response = await api("GET", "/api/v1/network-prerequisites");
    if (!response.ok) return;
    prerequisites = await json(response);
    const setup = $("setup-form");
    const note = $("setup-platform-note");
    note.textContent = "";
    if (prerequisites.host_platform === "linux") {
      setup.elements.ipv4_forwarding_required.checked = true;
      setup.elements.masquerade.checked = true;
      if (!setup.elements.egress_interface.value) setup.elements.egress_interface.value = "eth0";
    } else {
      setup.elements.ipv4_forwarding_required.checked = false;
      setup.elements.masquerade.checked = false;
      setup.elements.egress_interface.value = "";
      if (prerequisites.host_platform === "macos") setup.elements.egress_interface.placeholder = "en0";
      else if (prerequisites.host_platform !== "windows") note.textContent = "This host platform is unknown, so setup starts with no forwarding and no masquerade.";
    }
    renderAttachment();
  }

  async function setPreshared(verb) {
    const id = $("edit-form").elements.client_id.value;
    if (!id) return;
    clearBanner();
    const response = await api("PATCH", `/api/v1/clients/${id}`, { expected_generation: generation, preshared_key: verb });
    const result = await json(response);
    await refreshAfterMutation(response, result, false);
  }

  function main() {
    wireThemeSwitcher();
    $("login-form").addEventListener("submit", login);
    $("login-totp-form").addEventListener("submit", loginTotp);
    $("login-totp-cancel").addEventListener("click", () => { resetLoginPane(); clearBanner(); });
    $("totp-begin").addEventListener("click", () => { void beginTotpEnroll(); });
    $("totp-confirm").addEventListener("click", () => { void confirmTotpEnroll(); });
    $("totp-cancel-enroll").addEventListener("click", () => {
      setVisible("totp-enroll-controls", false);
      $("totp-qr").replaceChildren();
      void loadAccount();
    });
    $("totp-disable-form").addEventListener("submit", disableTotp);
    $("setup-form").addEventListener("submit", submitSetup);
    $("setup-form").addEventListener("input", () => { setupTouched = true; });
    $("setup-form").elements.network_mode.addEventListener("change", renderAttachment);
    $("client-filters").addEventListener("input", renderClients);
    $("generate-preshared").addEventListener("click", () => setPreshared("generate"));
    $("clear-preshared").addEventListener("click", () => setPreshared("clear"));
    $("create-form").addEventListener("submit", submitCreate);
    $("edit-form").addEventListener("submit", submitEdit);
    $("account").addEventListener("click", () => { void openAccount(); });
    document.querySelectorAll(".close-account").forEach((button) => button.addEventListener("click", closeAccount));
    $("password-form").addEventListener("submit", changePassword);
    $("logout").addEventListener("click", logout);
    $("oidc-settings-form").addEventListener("submit", saveOidcSettings);
    $("refresh").addEventListener("click", loadConsole);
    $("new-client").addEventListener("click", () => setVisible("create-form", true));
    $("cancel-create").addEventListener("click", () => setVisible("create-form", false));
    $("client-rows").addEventListener("click", (event) => { const button = event.target.closest("button[data-action]"); if (button) void mutateClient(button); });
    $("more-audit").addEventListener("click", () => loadAudit(false));
    document.querySelectorAll(".close-dialog").forEach((button) => button.addEventListener("click", closeClientDialog));
    $("client-dialog").addEventListener("close", () => { clearArtifact(); moveBanner($("banner-slot")); });
    document.querySelectorAll("[data-artifact]").forEach((button) => button.addEventListener("click", () => artifact(button.dataset.artifact)));
    document.addEventListener("visibilitychange", () => { if (document.hidden) stopPolling(); else if (csrf) { void loadTelemetry(); startPolling(); } });
    window.addEventListener("focus", () => { if (!csrf) void loadConsole(); });
    void loadConsole().catch(() => message("The management service could not be reached.", "danger"));
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", main); else main();
})();
