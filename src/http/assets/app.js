(() => {
  "use strict";
  let csrf = null;
  let generation = 0;
  let clients = [];
  let telemetry = new Map();
  let auditCursor = null;
  let poll = null;
  let artifactUrl = null;

  const $ = (id) => document.getElementById(id);
  const form = (id) => Object.fromEntries(new FormData($(id)).entries());
  const setVisible = (id, value) => { $(id).hidden = !value; };
  const clearBanner = () => { $("banner").textContent = ""; setVisible("banner", false); };
  const message = (text) => { $("banner").textContent = text; setVisible("banner", true); };
  const json = (response) => response.json().catch(() => ({}));

  async function api(method, path, body) {
    const headers = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (csrf) headers["x-wg-basic-csrf"] = csrf;
    const response = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin", redirect: "error" });
    if (response.status === 401 && csrf && path !== "/api/v1/login") void showSignedOut();
    return response;
  }

  function routes(text) {
    return { prefixes: text.split(",").map((value) => value.trim()).filter(Boolean) };
  }

  function explainMutation(response, result, removing) {
    if (response.status === 409) {
      void loadConsole().then(() => message("Configuration changed elsewhere. Current state has been refreshed; review it and try again."));
      return false;
    }
    if (!response.ok) { message("The change could not be saved. Check the values and try again."); return false; }
    if (response.status === 202 || result.enforcement !== "converged") {
      message(removing
        ? "Saved, but network access has not been confirmed revoked. The server is still applying this change."
        : "Saved; network application is pending or degraded. The server is still applying this change.");
    } else clearBanner();
    generation = result.generation;
    return true;
  }

  async function refreshAfterMutation(response, result, removing) {
    if (!explainMutation(response, result, removing)) return false;
    const pending = response.status === 202 || result.enforcement !== "converged";
    const notice = pending ? $("banner").textContent : "";
    await loadConsole();
    if (notice) message(notice);
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

  async function showSignedOut() {
    csrf = null;
    stopPolling();
    setVisible("logout", false); setVisible("login-pane", true);
    setVisible("setup-pane", false); setVisible("app-pane", false);
    closeClientDialog();
  }

  async function loadSession() {
    const response = await api("GET", "/api/v1/session");
    if (!response.ok) { await showSignedOut(); return false; }
    const session = await json(response);
    csrf = session.csrf_token;
    setVisible("logout", true); setVisible("login-pane", false);
    return true;
  }

  async function loadConsole() {
    if (!await loadSession()) return;
    clearBanner();
    const healthResponse = await api("GET", "/api/v1/health");
    const serverResponse = await api("GET", "/api/v1/server");
    if (!serverResponse.ok) { message("The server settings could not be loaded."); return; }
    const summary = await json(serverResponse);
    generation = summary.generation;
    if (!summary.server) {
      setVisible("setup-pane", true); setVisible("app-pane", false); stopPolling();
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
    if (!response.ok) { message("Clients could not be loaded."); return; }
    const data = await json(response); generation = data.generation; clients = data.clients;
    renderClients();
  }

  function renderClients() {
    const tbody = $("client-rows"); tbody.replaceChildren();
    setVisible("empty-clients", clients.length === 0);
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
    for (const client of clients) {
      const row = document.createElement("tr");
      const live = telemetry.get(client.client_id);
      const state = client.settings.enabled === "enabled" ? (live?.observation ?? "unknown") : "disabled";
      const drift = live?.drift ? " · needs attention" : "";
      const handshake = live?.latest_handshake_age_seconds == null ? "Never" : `${live.latest_handshake_age_seconds}s ago`;
      const traffic = live?.rx_bytes == null ? "—" : `↓ ${bytes(live.rx_bytes)} · ↑ ${bytes(live.tx_bytes)}`;
      const addresses = [client.assigned_address, client.assigned_ipv6_address].filter(Boolean).join(" · ");
      for (const value of [client.settings.label, addresses, state + drift, handshake, traffic]) {
        const cell = document.createElement("td"); cell.textContent = value; row.append(cell);
      }
      const actions = document.createElement("td"); actions.className = "actions";
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
    const response = await api("GET", "/api/v1/clients/telemetry");
    if (!response.ok) { telemetry = new Map(); renderClients(); $("health-note").textContent = "Live network status is unavailable; saved client settings are unchanged."; return; }
    const snapshot = await json(response); telemetry = new Map(snapshot.clients.map((row) => [row.client_id, row]));
    $("health-note").textContent = snapshot.truncated
      ? `Live status refreshed. ${snapshot.unassociated_peer_count} unassociated peers; client list is truncated.`
      : `Live status refreshed · ${snapshot.unassociated_peer_count} unassociated peers.`;
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
      default_client_route_policy: routes(data.routes),
    };
    if (data.ipv6_tunnel_prefix.trim()) body.ipv6_tunnel_prefix = data.ipv6_tunnel_prefix.trim();
    if (data.ipv6_server_address.trim()) body.ipv6_server_address = data.ipv6_server_address.trim();
    const response = await api("POST", "/api/v1/setup", body); const result = await json(response);
    await refreshAfterMutation(response, result, false);
  }

  async function submitCreate(event) {
    event.preventDefault(); clearBanner(); const data = form("create-form");
    const serverResponse = await api("GET", "/api/v1/server");
    if (!serverResponse.ok) { message("The configured server could not be loaded; try again."); return; }
    const server = await json(serverResponse);
    const body = { expected_generation: generation, interface_id: server.server.interface_id, label: data.label };
    if (data.ipv6_address.trim()) body.ipv6_address = data.ipv6_address.trim();
    if (data.dns_servers.trim()) body.dns_servers = data.dns_servers.split(",").map((x) => x.trim()).filter(Boolean);
    const response = await api("POST", "/api/v1/clients", body); const result = await json(response);
    if (await refreshAfterMutation(response, result, false)) { $("create-form").reset(); setVisible("create-form", false); }
  }

  function openClient(client) {
    const edit = $("edit-form"); edit.elements.client_id.value = client.client_id;
    edit.elements.label.value = client.settings.label; edit.elements.address.value = client.assigned_address.split("/")[0];
    edit.elements.ipv6_address.value = client.assigned_ipv6_address?.split("/")[0] ?? "";
    edit.elements.routes.value = client.route_policy.prefixes.join(", "); edit.elements.dns_servers.value = client.dns_servers.join(", ");
    edit.elements.client_keepalive_seconds.value = client.settings.client_keepalive_seconds ?? "";
    $("artifact").replaceChildren(); setVisible("artifact", false); $("client-dialog").showModal();
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
    const body = { expected_generation: generation, label: data.label, address: data.address, route_policy: routes(data.routes), dns_servers: data.dns_servers.split(",").map((x) => x.trim()).filter(Boolean), client_keepalive_seconds: data.client_keepalive_seconds === "" ? null : Number(data.client_keepalive_seconds) };
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
    const response = await api(deleting ? "DELETE" : "POST", path, { expected_generation: generation });
    const result = await json(response);
    await refreshAfterMutation(response, result, deleting || disabling);
  }

  async function artifact(kind) {
    const id = $("edit-form").elements.client_id.value; if (!id) return;
    clearArtifact(); const target = $("artifact"); setVisible("artifact", true);
    if (kind === "config") {
      const response = await api("GET", `/api/v1/clients/${id}/config`);
      if (!response.ok) { target.textContent = "Configuration export is unavailable."; return; }
      artifactUrl = URL.createObjectURL(await response.blob());
      const link = document.createElement("a"); link.href = artifactUrl; link.download = `wg-client-${id}.conf`; link.textContent = "Download client configuration"; target.append(link);
    } else if (kind === "qr") {
      const image = document.createElement("img"); image.src = `/api/v1/clients/${id}/qr`; image.alt = "WireGuard client configuration QR code"; image.className = "qr-image";
      image.addEventListener("error", () => { image.remove(); target.textContent = "QR export is unavailable."; }, { once: true }); target.append(image);
    } else {
      const response = await api("POST", `/api/v1/clients/${id}/enrollment-links`, { expires_in_seconds: 600 });
      const link = await json(response);
      if (!response.ok) { target.textContent = "A one-time link could not be created."; return; }
      const heading = document.createElement("p"); heading.textContent = `Share this link once. It reveals VPN credentials and expires ${new Date(link.expires_at * 1000).toLocaleString()}.`;
      const value = document.createElement("code"); value.className = "share-link"; value.textContent = link.share_url;
      const copy = document.createElement("button"); copy.type = "button"; copy.textContent = "Copy link"; copy.addEventListener("click", async () => { await navigator.clipboard.writeText(link.share_url); copy.textContent = "Copied"; });
      const revoke = document.createElement("button"); revoke.type = "button"; revoke.className = "secondary"; revoke.textContent = "Revoke link";
      revoke.addEventListener("click", async () => { const result = await api("DELETE", `/api/v1/enrollment-links/${link.capability_id}`); if (result.ok) { value.textContent = "Link revoked"; copy.disabled = true; revoke.disabled = true; } });
      target.append(heading, value, copy, revoke);
    }
  }

  async function login(event) {
    event.preventDefault(); clearBanner(); const data = form("login-form");
    const response = await api("POST", "/api/v1/login", { username: data.username, password: data.password });
    $("login-form").elements.password.value = "";
    if (!response.ok) { message("Those credentials were not accepted."); return; }
    await loadConsole();
  }

  async function logout() {
    await api("POST", "/api/v1/logout"); await showSignedOut(); message("You have signed out.");
  }

  function main() {
    $("login-form").addEventListener("submit", login);
    $("setup-form").addEventListener("submit", submitSetup);
    $("create-form").addEventListener("submit", submitCreate);
    $("edit-form").addEventListener("submit", submitEdit);
    $("logout").addEventListener("click", logout);
    $("refresh").addEventListener("click", loadConsole);
    $("new-client").addEventListener("click", () => setVisible("create-form", true));
    $("cancel-create").addEventListener("click", () => setVisible("create-form", false));
    $("client-rows").addEventListener("click", (event) => { const button = event.target.closest("button[data-action]"); if (button) void mutateClient(button); });
    $("more-audit").addEventListener("click", () => loadAudit(false));
    document.querySelectorAll(".close-dialog").forEach((button) => button.addEventListener("click", closeClientDialog));
    $("client-dialog").addEventListener("close", clearArtifact);
    document.querySelectorAll("[data-artifact]").forEach((button) => button.addEventListener("click", () => artifact(button.dataset.artifact)));
    document.addEventListener("visibilitychange", () => { if (document.hidden) stopPolling(); else if (csrf) { void loadTelemetry(); startPolling(); } });
    window.addEventListener("focus", () => { if (!csrf) void loadConsole(); });
    void loadConsole().catch(() => message("The management service could not be reached."));
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", main); else main();
})();
