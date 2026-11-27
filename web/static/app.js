// Passkeys and confirmations. The options come from the server with binary
// fields in base64url; the browser wants ArrayBuffers. Texts come from the
// data-* attributes of <body>, in the page's language.
(() => {
  const text = (k) => document.body.dataset[k] || "";
  const fromB64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const toB64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const showError = (t) => {
    const p = document.getElementById("error");
    p.textContent = t;
    p.hidden = false;
    p.scrollIntoView({ block: "center" });
  };

  const call = async (path, body) => {
    const r = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.message || "error " + r.status);
    return data;
  };

  const common = (c) => ({
    id: c.id,
    rawId: toB64(c.rawId),
    type: c.type,
    authenticatorAttachment: c.authenticatorAttachment || undefined,
    clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
  });

  const sign = async (options) => {
    const pk = options.publicKey;
    pk.challenge = fromB64(pk.challenge);
    (pk.allowCredentials || []).forEach((c) => (c.id = fromB64(c.id)));
    const c = await navigator.credentials.get({ publicKey: pk });
    return JSON.stringify({
      ...common(c),
      response: {
        clientDataJSON: toB64(c.response.clientDataJSON),
        authenticatorData: toB64(c.response.authenticatorData),
        signature: toB64(c.response.signature),
        userHandle: c.response.userHandle ? toB64(c.response.userHandle) : undefined,
      },
    });
  };

  const create = async (options) => {
    const pk = options.publicKey;
    pk.challenge = fromB64(pk.challenge);
    pk.user.id = fromB64(pk.user.id);
    (pk.excludeCredentials || []).forEach((c) => (c.id = fromB64(c.id)));
    // The server already asks for the PRF extension, which opens the vault.
    const c = await navigator.credentials.create({ publicKey: pk });
    return JSON.stringify({
      ...common(c),
      response: {
        clientDataJSON: toB64(c.response.clientDataJSON),
        attestationObject: toB64(c.response.attestationObject),
        transports: c.response.getTransports ? c.response.getTransports() : undefined,
      },
    });
  };

  const go = (path, notice) => (location.href = path + "?notice=" + encodeURIComponent(notice));

  // Notices: the one in the URL ("?notice=") fades away and leaves the URL,
  // so a reload does not bring it back; each is kept in this browser's
  // history, collapsed, with its time and page.
  const HISTORY_KEY = "notices";
  const readHistory = () => {
    try {
      return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
    } catch (e) {
      return [];
    }
  };
  const notice = document.getElementById("notice");
  if (notice) {
    const list = readHistory();
    list.unshift({ t: Date.now(), text: notice.textContent, page: location.pathname });
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, 100)));
    } catch (e) {}
    const url = new URL(location.href);
    url.searchParams.delete("notice");
    history.replaceState(null, "", url.pathname + url.search + url.hash);
    setTimeout(() => {
      notice.classList.add("fading");
      setTimeout(() => notice.remove(), 700);
    }, 8000);
  }

  // "Copy" buttons put their text on the clipboard (the authenticator
  // search, the command that reads a code, a query).
  document.addEventListener("click", async (ev) => {
    const button = ev.target.closest("button.copy");
    if (!button) return;
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      const before = button.textContent;
      button.textContent = text("copied");
      setTimeout(() => (button.textContent = before), 1500);
    } catch (e) {
      showError(text("copyFailed") + " " + e.message);
    }
  });

  // "View query": the client's SQL full screen, to review it whole.
  document.addEventListener("click", (ev) => {
    const open = ev.target.closest("button.view-query");
    if (open) open.parentElement.querySelector("dialog.query-full").showModal();
    const close = ev.target.closest("button.close-query");
    if (close) close.closest("dialog").close();
  });

  const historyBox = document.getElementById("history");
  if (historyBox) {
    const list = readHistory();
    if (list.length) {
      const ol = historyBox.querySelector("ol");
      const two = (n) => String(n).padStart(2, "0");
      list.forEach((a) => {
        const d = new Date(a.t);
        const li = document.createElement("li");
        const when = document.createElement("time");
        when.dateTime = d.toISOString();
        when.textContent = two(d.getDate()) + "/" + two(d.getMonth() + 1) + " " + two(d.getHours()) + ":" + two(d.getMinutes());
        li.append(when, document.createTextNode((a.text || a.texto) + (a.page && a.page !== "/" ? " · " + a.page : "")));
        ol.append(li);
      });
      historyBox.hidden = false;
    }
  }

  // While a passkey is being asked for, the live list is not replaced.
  let busy = false;

  // Request page: choosing a duration only marks it; the "Approve" button
  // grants, saying for how long, before asking for the passkey.
  const approve = document.getElementById("approve");
  if (approve) {
    const durations = [...document.querySelectorAll("button.duration")];
    // A request with several credentials has a "grant" box for each: an
    // unchecked one is refused, and its one-time code is not asked for.
    const boxes = [...document.querySelectorAll("input.grant")];
    const checked = () => boxes.filter((c) => c.checked).map((c) => c.dataset.credential);
    const why = document.getElementById("why");
    const update = () => {
      boxes.forEach((c) => {
        const card = c.closest(".req-secret");
        card.classList.toggle("left-out", !c.checked);
        card.querySelectorAll("input.code").forEach((i) => (i.disabled = !c.checked));
      });
      const label = approve.dataset.label;
      const n = checked().length;
      // A refusal text with nothing unchecked means a refusal: "Approve"
      // is locked so it is not tapped by mistake. With something unchecked
      // the text is for what is left out.
      const refusing = why && why.value.trim() && (!boxes.length || n === boxes.length);
      if (refusing) {
        approve.textContent = text("hasWhy");
        approve.disabled = true;
      } else if (boxes.length && n === 0) {
        approve.textContent = text("markOne");
        approve.disabled = true;
      } else if (!label) {
        approve.textContent = text("chooseDuration");
        approve.disabled = true;
      } else {
        approve.textContent =
          boxes.length && n < boxes.length
            ? text("approveSome").replace("%d", n).replace("%d", boxes.length).replace("%s", label)
            : text("approveLabel").replace("%s", label);
        approve.disabled = false;
      }
    };
    boxes.forEach((c) => c.addEventListener("change", update));
    if (why) why.addEventListener("input", update);
    const choose = (button) => {
      durations.forEach((b) => b.classList.toggle("chosen", b === button));
      approve.dataset.seconds = button.dataset.seconds;
      approve.dataset.label = button.dataset.label;
      update();
    };
    durations.forEach((b) => b.addEventListener("click", () => choose(b)));
    const suggested = durations.find((b) => b.classList.contains("chosen"));
    if (suggested) choose(suggested);
    else update();

    approve.addEventListener("click", async () => {
      if (busy || !approve.dataset.seconds) return;
      busy = true;
      approve.disabled = true;
      try {
        // One-time codes typed for this request, by credential.
        const codes = {};
        document.querySelectorAll("input.code").forEach((i) => {
          if (!i.disabled) codes[i.dataset.credential] = i.value.trim();
        });
        const body = { request: approve.dataset.request, seconds: Number(approve.dataset.seconds), codes };
        // The list goes only when something was left out.
        if (boxes.length && checked().length < boxes.length) {
          body.only = checked();
          // The refusal text is for those left out.
          if (why && why.value.trim()) body.why = why.value.trim();
        }
        const begin = await call("/approve/begin", body);
        const signature = await sign(begin.options);
        const end = await call("/approve/finish?token=" + encodeURIComponent(begin.token), signature);
        go("/", end.notice);
      } catch (e) {
        showError(text("notApproved") + " " + e.message);
        update();
      } finally {
        busy = false;
      }
    });
  }

  // Live: waiting requests, grants in force and cooldowns. The part is
  // fetched every 3 seconds, also with the tab in the background, and
  // replaced when it changes.
  const live = document.getElementById("live");
  if (live) {
    // The server already sends the title with the count; the base has none.
    const title = document.title.replace(/^(\(\d+\) )?(\[[^\]]*\] )?/, "");
    let last = null;
    const mark = () => {
      const n = live.querySelectorAll(".pending.summary-card").length;
      const sealed = !!live.querySelector(".notice-sealed");
      document.title = (n ? "(" + n + ") " : "") + (sealed ? "[" + text("sealedTag") + "] " : "") + title;
    };
    const refresh = async () => {
      // Also in the background: that is when the title matters.
      if (busy) return;
      // A one-time code being typed must not vanish with the list.
      const typing = [...live.querySelectorAll("input.code")].some((i) => i.value || i === document.activeElement);
      if (typing) return;
      try {
        const r = await fetch("/live", { headers: { Accept: "text/plain" } });
        if (r.status === 401) return location.reload(); // the login expired
        if (!r.ok) return;
        const part = await r.text();
        if (busy || part === last) return;
        last = part;
        // What was open for reading stays open after the swap.
        const open = [...live.querySelectorAll("details[open][data-key]")].map((d) => d.dataset.key);
        live.innerHTML = part;
        live.querySelectorAll("details[data-key]").forEach((d) => {
          if (open.includes(d.dataset.key)) d.open = true;
        });
        mark();
      } catch (e) {
        // No network: try again next time.
      }
    };
    mark();
    // The tick comes from a worker, which the browser does not slow down in
    // a background tab; without a worker, a plain timer.
    try {
      new Worker("/static/tick.js").onmessage = refresh;
    } catch (e) {
      setInterval(refresh, 3000);
    }
    document.addEventListener("visibilitychange", refresh);
  }

  // Passkey registration, on /passkey.
  const register = document.getElementById("register");
  if (register)
    register.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const button = register.querySelector("button");
      button.disabled = true;
      try {
        const begin = await call("/passkey/register/begin", { code: register.code.value.trim() });
        const created = await create(begin.options);
        const end = await call(
          "/passkey/register/finish?token=" + encodeURIComponent(begin.token) + "&name=" + encodeURIComponent(register.name.value),
          created
        );
        go("/passkey", end.notice);
      } catch (e) {
        showError(text("notRegistered") + " " + e.message);
        button.disabled = false;
      }
    });

  document.addEventListener("submit", (ev) => {
    const f = ev.target.closest("form[data-confirm]");
    if (f && !confirm(f.dataset.confirm)) ev.preventDefault();
  });
})();
