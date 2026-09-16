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

  // The folded summary shows the name and the user count, both of which panel
  // changes can alter.
  function syncSummary(id, host) {
    const panel = host.querySelector(".panel");
    const details = detailsFor(id);
    if (!panel || !details) return;

    const badge = details.querySelector(".badge[data-user-count]");
    const count = panel.dataset.userCount;
    if (badge && count !== undefined) {
      badge.dataset.userCount = count;
      badge.textContent = `${count} test ${count === "1" ? "user" : "users"}`;
    }

    const name = details.querySelector(".app-name");
    if (name && panel.dataset.appName) name.textContent = panel.dataset.appName;
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
        syncSummary(id, entry.node);
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
      if (response.ok) syncSummary(id, entry.node);
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

  // A client secret is never part of a panel: it arrives beside one, in a
  // dialog shown once. Lifting it out here keeps it out of the page's markup,
  // and closing the dialog removes it from the document altogether.
  function takeSecretDialog(content) {
    const dialog = content.querySelector("dialog[data-secret]");
    if (!dialog) return null;
    dialog.remove();

    dialog.querySelector("[data-copy]").addEventListener("click", (event) => {
      copySecret(event.currentTarget, dialog);
    });
    dialog.querySelector("[data-close]").addEventListener("click", () => dialog.close());
    dialog.addEventListener("close", () => dialog.remove());
    return dialog;
  }

  function showSecret(dialog) {
    if (!dialog) return;
    document.body.append(dialog);
    dialog.showModal();
  }

  async function copySecret(button, dialog) {
    const text = dialog.querySelector(".secret").textContent.trim();
    const copied = dialog.querySelector("[data-copied]");

    // Clerk is routinely run over plain http on a LAN address, where the
    // clipboard API does not exist, so fall back to a selection-based copy and
    // finally to leaving it selected for the reader to copy themselves.
    let done = false;
    try {
      await navigator.clipboard.writeText(text);
      done = true;
    } catch {
      done = selectAndCopy(button);
    }
    copied.textContent = done ? "Copied" : "Press Ctrl+C to copy";
    copied.hidden = false;
  }

  function selectAndCopy(button) {
    const range = document.createRange();
    range.selectNodeContents(button.querySelector(".secret"));
    const selection = getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    try {
      return document.execCommand("copy");
    } catch {
      return false;
    }
  }

  async function submitPanelForm(form, host) {
    const id = host.dataset.app;
    const keepFocus = form.dataset.keepFocus;
    let refocus = null;
    setBusy(host, true);
    try {
      const response = await post(form);
      const content = parse(await response.text());
      if (response.ok || response.status === 422) {
        // A confirmation the form lives in has served its purpose, and is about
        // to be replaced along with the rest of the panel.
        form.closest("dialog")?.close();

        const secret = takeSecretDialog(content);
        host.replaceChildren(content);
        syncSummary(id, host);
        showSecret(secret);

        // Adding another user or URI is the common next step, so the field that
        // was just used keeps the focus — empty on success, still holding the
        // rejected value on a refusal. It has to wait until the panel is no
        // longer inert, or the focus would go nowhere.
        // Scoped to the add form: the table above it holds hidden inputs of the
        // same name, one per row.
        const field = keepFocus &&
          host.querySelector(`[data-keep-focus="${keepFocus}"] [name="${keepFocus}"]`);
        refocus = host.querySelector(".is-invalid") || field || null;
      } else {
        notify(host, content);
      }
    } catch (error) {
      if (error instanceof SignedOut) return;
      notify(host, alertNode("The change could not be saved. Try again."));
    } finally {
      setBusy(host, false);
      refocus?.focus();
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

  // A dialog that was cancelled must not reopen holding the last attempt: it
  // goes back to the name the application actually has (nothing, when
  // registering), with no message and nothing to submit.
  function resetNameForm(dialog) {
    const form = dialog.querySelector("[data-name-form]");
    if (!form) return;
    form.querySelectorAll(".alert").forEach((node) => node.remove());
    const input = form.querySelector("input[name=name]");
    input.value = input.dataset.original || "";
    input.classList.remove("is-invalid");
    form.querySelector("[data-name-message]").textContent = "";
    form.querySelector("[data-submit]").disabled = true;
  }

  // The name is checked while it is typed, so a duplicate is known before
  // anything is pressed. The message slot is always in the markup, so filling
  // it never resizes the dialog.
  let nameCheck = null;
  let nameTimer = 0;

  function checkNameSoon(input) {
    const form = input.closest("form");
    const message = form.querySelector("[data-name-message]");
    const submit = form.querySelector("[data-submit]");

    clearTimeout(nameTimer);
    nameCheck?.abort();
    input.classList.remove("is-invalid");

    // An empty box, or one still holding the name it already has, has nothing
    // to submit and nothing to check.
    if (!input.value.trim() || input.value === input.dataset.original) {
      message.textContent = "";
      submit.disabled = true;
      return;
    }

    nameTimer = setTimeout(async () => {
      const controller = new AbortController();
      nameCheck = controller;
      const query = new URLSearchParams({ name: input.value, exclude: form.dataset.exclude || "0" });
      try {
        const response = await request(`/admin/applications/name-check?${query}`, { signal: controller.signal });
        if (nameCheck !== controller) return;
        const taken = response.status === 409;
        message.textContent = taken ? (await response.text()).trim() : "";
        input.classList.toggle("is-invalid", taken);
        submit.disabled = taken;
      } catch {
        // A check aborted by the next keystroke has already been superseded:
        // that keystroke decided the state, and this one must not undo it.
        if (nameCheck !== controller) return;
        // An unreachable check must not stop anyone working; the server still
        // refuses a duplicate on submit.
        message.textContent = "";
        submit.disabled = false;
      }
    }, 250);
  }

  async function submitNameForm(form) {
    const dialog = document.getElementById(form.dataset.dialog);
    setBusy(form, true);
    try {
      const response = await post(form);
      const content = parse(await response.text());

      // Registering: the response is the new application's panel, secret and
      // all, so unfolding it needs no further request.
      if (response.status === 201) {
        const id = response.headers.get("X-Clerk-Application");
        const entry = entryFor(id);
        const secret = takeSecretDialog(content);
        entry.node.replaceChildren(content);
        entry.state = "loaded";

        dialog.close();
        await loadList();
        const details = detailsFor(id);
        if (details) {
          details.open = true;
          details.scrollIntoView({ block: "start", behavior: "smooth" });
        }
        showSecret(secret);
        return;
      }

      // Renaming: the response is that application's refreshed panel.
      if (response.ok) {
        const host = dialog.closest(".panel-host");
        dialog.close();
        host.replaceChildren(content);
        syncSummary(host.dataset.app, host);
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
      showDialogError(form, alertNode("The name could not be saved. Try again."));
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

    if (form.matches("[data-name-form]")) {
      event.preventDefault();
      submitNameForm(form);
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

  document.addEventListener("input", (event) => {
    const input = event.target;
    if (input instanceof HTMLInputElement && input.name === "name" && input.closest("[data-name-form]")) {
      checkNameSoon(input);
    }
  });

  document.addEventListener("close", (event) => {
    if (event.target instanceof HTMLDialogElement) resetNameForm(event.target);
  }, true);

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
