// Clerk administration interface.
//
// The page is a shell; everything about applications is loaded into it as
// HTML fragments the server renders (and escapes) with html/template. This
// script only fetches, caches and swaps those fragments, and keeps any area
// that is loading disabled until its data arrives.
//
//   - The list loads in the background, disabled while it does.
//   - An application's panel is requested the first time it is unfolded, and
//     never again: folding and unfolding reuses what was loaded. While it loads
//     only the panel is disabled — the application can still be folded.
//   - Forms post in the background and swap in the refreshed panel, so the
//     address bar never leaves /admin.
(() => {
  "use strict";

  const list = document.getElementById("applications");
  if (!list) return;

  const SIGN_IN = "/admin/signin";

  // appId -> { state: "idle" | "loading" | "loaded" | "error", node }
  // The node outlives list reloads, so a loaded panel is reattached, not refetched.
  const panels = new Map();

  class SignedOut extends Error {}

  function setBusy(element, busy) {
    if (busy) {
      element.setAttribute("aria-busy", "true");
    } else {
      element.removeAttribute("aria-busy");
    }
    element.inert = busy;
  }

  // Fragments come only from this server, which has already escaped every
  // value in them.
  function parse(html) {
    const template = document.createElement("template");
    template.innerHTML = html;
    return template.content;
  }

  function alertNode(message) {
    const node = document.createElement("div");
    node.className = "alert alert-danger";
    node.setAttribute("role", "alert");
    node.textContent = message;
    return node;
  }

  async function request(url, init = {}) {
    const response = await fetch(url, {
      ...init,
      credentials: "same-origin",
      headers: { "X-Clerk-Fragment": "1", ...init.headers },
    });
    if (response.status === 401) {
      location.assign(SIGN_IN);
      throw new SignedOut();
    }
    return response;
  }

  function post(form) {
    return request(form.action, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(new FormData(form)),
    });
  }

  function detailsFor(id) {
    return list.querySelector(`details[data-app="${CSS.escape(id)}"]`);
  }

  function entryFor(id) {
    let entry = panels.get(id);
    if (!entry) {
      const node = document.createElement("div");
      node.className = "panel-host";
      node.dataset.app = id;
      entry = { state: "idle", node };
      panels.set(id, entry);
    }
    return entry;
  }

  function mount(details, entry) {
    const slot = details.querySelector("[data-panel]");
    if (slot && entry.node.parentNode !== slot) slot.replaceChildren(entry.node);
  }

  // The folded summary shows the user count, which panel changes can alter.
  function syncUserCount(id, host) {
    const count = host.querySelector(".panel")?.dataset.userCount;
    const badge = detailsFor(id)?.querySelector(".badge[data-user-count]");
    if (count === undefined || !badge) return;
    badge.dataset.userCount = count;
    badge.textContent = `${count} test ${count === "1" ? "user" : "users"}`;
  }

  async function loadList() {
    setBusy(list, true);
    try {
      const response = await request("/admin/applications");
      const content = parse(await response.text());
      if (!response.ok) {
        list.replaceChildren(content);
        return;
      }

      const wasOpen = new Set(
        [...list.querySelectorAll("details[data-app][open]")].map((d) => d.dataset.app),
      );
      list.replaceChildren(content);

      const present = new Set();
      for (const details of list.querySelectorAll("details[data-app]")) {
        const id = details.dataset.app;
        present.add(id);
        const entry = panels.get(id);
        if (!entry) continue;
        mount(details, entry);
        syncUserCount(id, entry.node);
        if (wasOpen.has(id)) details.open = true;
      }
      for (const id of panels.keys()) {
        if (!present.has(id)) panels.delete(id);
      }
    } catch (error) {
      if (error instanceof SignedOut) return;
      list.replaceChildren(alertNode("The applications could not be loaded. Reload the page to try again."));
    } finally {
      setBusy(list, false);
    }
  }

  async function loadPanel(details) {
    const id = details.dataset.app;
    const entry = entryFor(id);
    mount(details, entry);
    if (entry.state === "loading" || entry.state === "loaded") return;

    entry.state = "loading";
    setBusy(entry.node, true);
    try {
      const response = await request(`/admin/applications/${encodeURIComponent(id)}`);
      entry.node.replaceChildren(parse(await response.text()));
      entry.state = response.ok ? "loaded" : "error";
      if (response.ok) syncUserCount(id, entry.node);
    } catch (error) {
      entry.state = "error";
      if (error instanceof SignedOut) return;
      entry.node.replaceChildren(alertNode("This application could not be loaded. Fold and unfold it to try again."));
    } finally {
      setBusy(entry.node, false);
    }
  }

  // A failure that leaves the panel as it was is reported above it.
  function notify(host, node) {
    host.querySelector(":scope > .panel-notice")?.remove();
    const notice = document.createElement("div");
    notice.className = "panel-notice";
    notice.append(node);
    host.prepend(notice);
  }

  // A secret is only ever in the response that generated it, so a later change
  // to the same panel must not wipe it before the administrator has copied it.
  // A response carrying a new secret replaces it.
  function keepRevealedSecret(host, content) {
    const shown = host.querySelector(".secret-alert");
    if (!shown || content.querySelector(".secret-alert")) return;
    content.querySelector(".credentials")?.before(shown);
  }

  async function submitPanelForm(form, host) {
    const id = host.dataset.app;
    setBusy(host, true);
    try {
      const response = await post(form);
      const content = parse(await response.text());
      if (response.ok || response.status === 422) {
        keepRevealedSecret(host, content);
        host.replaceChildren(content);
        syncUserCount(id, host);
        host.querySelector(".is-invalid")?.focus();
      } else {
        notify(host, content);
      }
    } catch (error) {
      if (error instanceof SignedOut) return;
      notify(host, alertNode("The change could not be saved. Try again."));
    } finally {
      setBusy(host, false);
    }
  }

  function showDialogError(form, node) {
    const body = form.querySelector(".modal-body");
    body.querySelectorAll(":scope > .alert").forEach((alert) => alert.remove());
    body.prepend(node);
  }

  async function submitDelete(form, host) {
    const dialog = form.closest("dialog");
    setBusy(form, true);
    try {
      const response = await post(form);
      // Not found means it is already gone — deleted elsewhere — which is the
      // outcome that was asked for.
      if (response.status === 204 || response.status === 404) {
        dialog.close();
        panels.delete(host.dataset.app);
        await loadList();
        return;
      }
      showDialogError(form, parse(await response.text()));
    } catch (error) {
      if (error instanceof SignedOut) return;
      showDialogError(form, alertNode("The application could not be deleted. Try again."));
    } finally {
      setBusy(form, false);
    }
  }

  const register = document.getElementById("register");

  function resetRegister() {
    const form = register.querySelector("form");
    form.querySelectorAll(".alert").forEach((node) => node.remove());
    const input = form.querySelector("input[name=name]");
    input.value = "";
    input.classList.remove("is-invalid");
  }

  async function submitRegister(form) {
    setBusy(form, true);
    try {
      const response = await post(form);
      const content = parse(await response.text());

      if (response.status === 201) {
        // The create response is the new application's panel, secret and all,
        // so unfolding it needs no further request.
        const id = response.headers.get("X-Clerk-Application");
        const entry = entryFor(id);
        entry.node.replaceChildren(content);
        entry.state = "loaded";

        register.close();
        await loadList();
        const details = detailsFor(id);
        if (details) {
          details.open = true;
          details.scrollIntoView({ block: "start", behavior: "smooth" });
        }
        return;
      }

      if (response.status === 422) {
        const fresh = content.querySelector("form");
        form.replaceWith(fresh);
        fresh.querySelector("input[name=name]").focus();
        return;
      }

      showDialogError(form, content);
    } catch (error) {
      if (error instanceof SignedOut) return;
      showDialogError(form, alertNode("The application could not be registered. Try again."));
    } finally {
      setBusy(form, false);
    }
  }

  // <details> toggle events do not bubble, so listen during capture.
  list.addEventListener("toggle", (event) => {
    const details = event.target;
    if (details instanceof HTMLDetailsElement && details.matches("[data-app]") && details.open) {
      loadPanel(details);
    }
  }, true);

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;

    if (form.matches("[data-register]")) {
      event.preventDefault();
      submitRegister(form);
      return;
    }

    const host = form.closest(".panel-host");
    if (!host) return;
    event.preventDefault();
    if (form.matches("[data-delete]")) {
      submitDelete(form, host);
    } else {
      submitPanelForm(form, host);
    }
  });

  register.addEventListener("close", resetRegister);

  // Buttons open and close dialogs declaratively (commandfor/command). Where a
  // browser predates invoker commands, do the same thing here.
  if (!("command" in HTMLButtonElement.prototype)) {
    document.addEventListener("click", (event) => {
      const button = event.target.closest("button[commandfor]");
      const dialog = button && document.getElementById(button.getAttribute("commandfor"));
      if (!(dialog instanceof HTMLDialogElement)) return;
      const command = button.getAttribute("command");
      if (command === "show-modal" && !dialog.open) dialog.showModal();
      if (command === "close" && dialog.open) dialog.close();
    });
  }

  loadList();
})();
