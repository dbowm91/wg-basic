/*
 * This file is embedded in the wg-basic binary at compile time.
 *
 * It deliberately has no build step, no bundler, no transpiler, and no
 * dependency graph. That is not minimalism for its own sake: a management UI
 * that an operator has to build before it runs is a UI that will eventually be
 * served from somewhere other than the binary it ships in, which is exactly the
 * boundary Phase 7 is supposed to hold.
 */
/*
 * The operator console.
 *
 * What it does: asks the service who it is, and if the answer is "nobody",
 * asks for a password. If the answer is "someone", it shows the appliance
 * health and offers a logout.
 *
 * What it deliberately does not do: manage peers, clients, or interfaces.
 * Those are Phase 8. The absence is the point -- this shell proves the
 * substrate holds, and a shell that grows CRUD would be Phase 8 shipping
 * without Phase 8's plan.
 */
(() => {
  "use strict";

  // The CSRF token the service issued for this session. Held in memory only:
  // it is useless without the HttpOnly session cookie the page cannot read, so
  // persisting it in the browser would only widen its exposure for no gain.
  let csrfToken = null;

  const byId = (id) => document.getElementById(id);

  const show = (id, visible) => {
    byId(id).hidden = !visible;
  };

  /**
   * Every fetch carries the session cookie the browser already holds, and —
   * for anything unsafe — the CSRF token. Both are sent explicitly so that a
   * failure names which one was missing.
   */
  const call = async (method, path, body) => {
    const headers = { Accept: "application/json" };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (csrfToken !== null) {
      headers["x-wg-basic-csrf"] = csrfToken;
    }
    return fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      // Same-origin only. This shell must never be able to read a response the
      // service did not intend it to, and 'no-cors' would only hide the error.
      credentials: "same-origin",
      redirect: "error",
    });
  };

  /** Renders the error banner. Never renders an internal detail. */
  const fail = (message) => {
    byId("banner").textContent = message;
    show("banner", true);
  };

  const clearFailure = () => {
    byId("banner").textContent = "";
    show("banner", false);
  };

  /**
   * The signed-in view.
   *
   * `health` is the safe projection the service chose to publish. This renders
   * the fields it has and does not go looking for others: the boundary is the
   * service's decision, not the page's.
   */
  const renderSession = (session, health) => {
    byId("principal").textContent = session.principal_id;
    byId("session").textContent = session.session_id;
    byId("expires").textContent = new Date(
      session.expires_at * 1000
    ).toLocaleString();
    csrfToken = session.csrf_token;

    byId("netd-state").textContent = health.netd_state ?? "unknown";
    byId("convergence").textContent = health.convergence ?? "unknown";
    byId("desired-generation").textContent = String(
      health.desired_generation ?? "?"
    );

    show("login-pane", false);
    show("console-pane", true);
    show("health-pane", true);
  };

  const renderSignedOut = () => {
    csrfToken = null;
    show("console-pane", false);
    show("health-pane", false);
    show("login-pane", true);
  };

  /** Fetches health and renders the console, or falls back to signed-out. */
  const showConsole = async () => {
    const sessionResponse = await call("GET", "/api/v1/session");
    if (!sessionResponse.ok) {
      renderSignedOut();
      return;
    }
    const session = await sessionResponse.json();
    const healthResponse = await call("GET", "/api/v1/health");
    if (!healthResponse.ok) {
      fail("The session is valid but the appliance health could not be read.");
      renderSignedOut();
      return;
    }
    renderSession(session, await healthResponse.json());
  };

  const submitLogin = async (event) => {
    event.preventDefault();
    clearFailure();
    const username = byId("username").value;
    const password = byId("password").value;
    if (username === "" || password === "") {
      fail("Both a username and a password are required.");
      return;
    }
    // The service refuses a wrong password, an unknown user, and an outage
    // with the same 401 and the same body, so there is nothing here to guess
    // from -- and nothing this page should try to guess.
    const response = await call("POST", "/api/v1/login", {
      username: username,
      password: password,
    });
    if (!response.ok) {
      byId("password").value = "";
      fail("Those credentials were not accepted.");
      return;
    }
    byId("password").value = "";
    await showConsole();
  };

  const logout = async () => {
    clearFailure();
    const response = await call("POST", "/api/v1/logout");
    if (!response.ok && response.status !== 403) {
      fail("The session could not be revoked.");
      return;
    }
    renderSignedOut();
  };

  const main = () => {
    byId("login-form").addEventListener("submit", submitLogin);
    byId("logout").addEventListener("click", logout);
    // A session that expired while the tab was open shows up here, not as a
    // mysteriously failing page.
    window.addEventListener("focus", () => {
      void showConsole();
    });
    void showConsole();
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", main);
  } else {
    main();
  }
})();