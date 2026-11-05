const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let S = null, timer = null, lastShows = "";

async function api(path, body) {
  let r;
  try { r = await fetch(path, body ? {method: "POST", headers: {"Content-Type": "application/json", "X-Podburrow": "1"}, body: JSON.stringify(body)} : {}); }
  catch (e) { throw new Error("can\u2019t reach the server"); }
  const j = await r.json().catch(() => ({error: "HTTP " + r.status}));
  if (!r.ok) {
    if (r.status === 401 && j && j.signin) location.href = "/login";
    const err = new Error(j.error || "HTTP " + r.status);
    err.status = r.status;
    throw err;
  }
  return j;
}
function toast(msg, bad) {
  document.querySelectorAll(".toast").forEach(x => x.remove());
  const t = document.createElement("div"); t.className = "toast" + (bad ? " bad" : ""); t.textContent = msg;
  t.setAttribute("role", "status"); t.setAttribute("aria-live", "polite");
  (document.querySelector("dialog[open]") || document.body).append(t); setTimeout(() => t.remove(), bad ? 6000 : 3000);
}
const gb = b => !b ? "0 MB" : b >= 2 ** 40 ? (b / 2 ** 40).toFixed(1) + " TB" : b >= 2 ** 30 ? (b / 2 ** 30).toFixed(b >= 100 * 2 ** 30 ? 0 : 1) + " GB" : Math.max(1, Math.round(b / 2 ** 20)) + " MB";
const day = iso => iso ? esc(iso.slice(0, 10)) : "—";
const when = t => {
  if (t === null || t === undefined || t === "") return "—";
  const d = typeof t === "number" || /^\d+$/.test(String(t)) ? new Date(+t * 1000) : new Date(t);
  return isNaN(d.getTime()) ? String(t) : d.toLocaleString();
};
function ago(t) {
  if (!t) return "never";
  const s = Math.max(0, (S ? S.now : Date.now() / 1000) - t);
  return s < 90 ? "just now" : s < 5400 ? Math.round(s / 60) + " min ago" : s < 129600 ? Math.round(s / 3600) + " h ago" : Math.round(s / 86400) + " days ago";
}
function retryIn(e) {
  if (!S || !e.next_try || !["failed", "queued"].includes(e.status)) return "";
  const s = e.next_try - S.now;
  if (s <= 0) return "";
  return " · retrying in " + (s < 5400 ? Math.max(1, Math.round(s / 60)) + " min" : s < 172800 ? Math.round(s / 3600) + " h" : Math.round(s / 86400) + " days");
}
const initials = t => esc((t.match(/\b\w/g) || ["?"]).slice(0, 2).join("").toUpperCase());

async function load() {
  try { S = await api("/api/state"); render(); }
  catch (e) { $("#activity").innerHTML = '<span class="dot"></span>can’t reach the server'; }
}
function render() {
  const sum = k => S.shows.reduce((a, s) => a + (s.counts[k] || 0), 0);
  const total = S.shows.reduce((a, s) => a + Object.values(s.counts).reduce((x, y) => x + y, 0), 0);
  $("#stats").innerHTML = [
    ["Shows", S.shows.length, "", "--p"], ["Episodes", total, "", "--c"], ["Downloaded", sum("downloaded"), "grad", "--g"],
    ["In queue", sum("queued"), "", "--c"], ["Failed", sum("failed"), "", "--red"], ["Free space", gb(S.free), "", "--y"]
  ].map(([l, v, cls, c]) => `<div class="card stat ${cls}"><div class="label" style="--lc:var(${c})">${l}</div><b>${esc(v)}</b></div>`).join("");
  const st = S.status, busy = st.state !== "idle";
  $("#activity").className = "activity" + (busy ? " busy" : "");
  const act = busy ? st.state + (st.progress ? " " + Math.round(st.progress * 100) + "%" : "") + " · " + st.detail
                   : "idle · checks every " + S.settings.check_minutes + " min";
  $("#activity").innerHTML = '<span class="dot"></span>' + esc(act);
  $("#activity").title = act;
  const html = S.shows.length ? S.shows.map(showCard).join("") : '<div class="card empty">No podcasts yet. Search above or paste a feed link.</div>';
  if (html !== lastShows && !$("#dlg").open) {          // never swap the buttons out from under an open dialog
    const f = document.activeElement && document.activeElement.dataset ? {...document.activeElement.dataset} : {};
    $("#shows").innerHTML = lastShows = html;
    if (f.act && f.id) { const b = document.querySelector(`#shows [data-act="${f.act}"][data-id="${f.id}"]`); if (b) b.focus(); }
  }
}
function showCard(s) {
  const c = s.counts, pill = (n, cls, txt) => n ? `<span class="pill ${cls}">${n} ${txt}</span>` : "";
  const cover = s.has_cover ? `<img class="cover" src="/api/cover/${s.id}?v=${Math.floor(s.last_check)}" alt="">` : `<div class="cover">${initials(s.title)}</div>`;
  return `<article class="card show">${cover}<div>
    <h3>${esc(s.title)}</h3><div class="by">${esc(s.author || s.folder)}</div>
    <div class="pills">${s.paused ? '<span class="pill off">paused</span>' : ""}${pill(c.downloaded, "ok", "downloaded")}${pill(c.downloading, "q", "downloading")}${pill(c.queued, "q", "queued")}${pill(c.pending, "skip", "waiting for migration")}${pill(c.failed, "bad", "failed")}${pill(c.skipped, "skip", "not downloaded")}${pill(c.missing, "off", "deleted from disk")}</div>
    <div class="meta">newest ${day(s.latest)} · ${gb(s.size)}<br>checked ${ago(s.last_check)}</div>
    ${s.last_error ? `<div class="err">⚠ ${esc(s.last_error)}</div>` : ""}
    <div class="acts">
      <button class="btn sm" data-act="eps" data-id="${s.id}">Episodes</button>
      <button class="btn sm" data-act="pause" data-id="${s.id}" data-paused="${s.paused ? 0 : 1}">${s.paused ? "▶ Resume" : "⏸ Pause"}</button>
      ${c.failed ? `<button class="btn sm" data-act="retry_all" data-id="${s.id}">Retry failed</button>` : ""}
      ${c.skipped ? `<button class="btn sm" data-act="get_all" data-id="${s.id}">Get older episodes</button>` : ""}
      <button class="btn sm warn" data-act="remove" data-id="${s.id}">Unfollow</button>
    </div></div></article>`;
}

$("#shows").addEventListener("click", async e => {
  const b = e.target.closest("button[data-act]"); if (!b) return;
  const id = +b.dataset.id, act = b.dataset.act, s = S.shows.find(x => x.id === id);
  if (act === "eps") return episodes(s);
  if (act === "remove") return confirmRemove(s);
  b.disabled = true;
  try { await api("/api/act", {action: act, id, paused: b.dataset.paused === "1"}); await load(); }
  catch (err) { toast(err.message, true); } finally { b.disabled = false; }
});

function confirmRemove(s) {
  $("#dlg").className = "small"; $("#dlg").tok = null;
  $("#dlgBody").innerHTML = `<div><h2 id="dlgTitle">Unfollow ${esc(s.title)}?</h2><div class="sub">No new episodes will download. The ${esc(gb(s.size))} already on disk stays where it is (and in Plex). Its episode list is forgotten: following it again starts fresh.</div></div>
    <div class="row-end"><button class="btn" data-close>Cancel</button><button class="btn danger" id="doRemove">Unfollow</button></div>`;
  $("#doRemove").onclick = async () => {
    $("#doRemove").disabled = true;
    try { await api("/api/act", {action: "remove", id: s.id}); $("#dlg").close(); toast("Unfollowed " + s.title); await load(); $("#q").focus(); }
    catch (err) { toast(err.message, true); $("#doRemove").disabled = false; }
  };
  $("#dlg").showModal();
}

async function episodes(s) {
  $("#dlg").className = "";
  $("#dlgBody").innerHTML = `<div><h2 id="dlgTitle">${esc(s.title)}</h2><div class="sub">${esc(s.feed_url)}</div></div><div class="eps"><div class="empty">loading…</div></div>`;
  $("#dlg").showModal();
  const tok = Symbol(); $("#dlg").tok = tok;
  let eps;
  try { eps = await api("/api/episodes?id=" + s.id); }
  catch (err) { if ($("#dlg").tok === tok) $(".eps").innerHTML = `<div class="empty">couldn\u2019t load: ${esc(err.message)}</div>`; return; }
  if ($("#dlg").tok !== tok || !$("#dlg").open) return;
  const cls = {downloaded: "ok", queued: "q", downloading: "q", failed: "bad", skipped: "skip", missing: "off", pending: "skip"};
  const label = {skipped: "not downloaded", missing: "deleted from disk", pending: "waiting for migration"};
  $("#dlgBody").innerHTML = `<div><h2 id="dlgTitle">${esc(s.title)}</h2><div class="sub">${esc(s.feed_url)}</div></div>
    <input class="search" id="epq" placeholder="Filter ${eps.length} episodes" aria-label="Filter episodes">
    <div class="eps" id="eplist"></div><div class="row-end"><button class="btn" data-close>Close</button></div>`;
  const draw = f => {
    const list = f ? eps.filter(e => e.title.toLowerCase().includes(f)) : eps;
    $("#eplist").innerHTML = list.slice(0, 600).map(e => `<div class="ep">
      <span class="n">#${esc(e.num)}</span><span class="d">${day(e.pub)}</span>
      <span class="t"><span title="${esc(e.title)}">${esc(e.title)}</span>${e.error ? `<small title="${esc(e.error)}">${esc(e.error)}${retryIn(e)}</small>` : ""}</span>
      <span class="s">${e.size ? gb(e.size) : ""}</span>
      <span>${["failed", "skipped", "missing"].includes(e.status) ? `<button class="btn sm" data-retry="${e.id}">Download</button>` : `<span class="pill ${cls[e.status] || "skip"}">${esc(label[e.status] || e.status)}</span>`}</span>
    </div>`).join("") + (list.length > 600 ? `<div class="empty">showing the newest 600 of ${list.length}: type above to find older ones</div>` : "")
      || '<div class="empty">nothing matches</div>';
  };
  draw("");
  $("#epq").oninput = e => draw(e.target.value.trim().toLowerCase());
  $("#eplist").onclick = async e => {
    const b = e.target.closest("[data-retry]"); if (!b) return;
    b.disabled = true;
    try { await api("/api/act", {action: "retry", id: +b.dataset.retry}); const ep = eps.find(x => x.id === +b.dataset.retry); if (ep) { ep.status = "queued"; ep.error = ""; } b.outerHTML = '<span class="pill q">queued</span>'; load(); }
    catch (err) { toast(err.message, true); b.disabled = false; }
  };
}

$("#dlg").addEventListener("close", () => {
  $("#dlgBody").textContent = "";
  ACC = null;
  lastShows = ""; if (S) render();
});
$("#dlg").addEventListener("click", e => {
  if (e.target.closest("[data-close]")) return $("#dlg").close();
  if (e.target !== $("#dlg")) return;
  const once = $("#acOnce");
  if (once && once.textContent.trim()) return;
  $("#dlg").close();
});

$("#addForm").addEventListener("submit", async e => {
  e.preventDefault();
  const q = $("#q").value.trim(); if (!q) return;
  const res = $("#results");
  if (/^https?:\/\//i.test(q)) return follow(q, q);
  res.innerHTML = '<div class="meta">searching…</div>';
  try {
    const found = await api("/api/search?q=" + encodeURIComponent(q));
    res.innerHTML = found.length ? found.map((r, i) => `<div class="res">
      ${r.image ? `<img src="${esc(r.image)}" alt="" referrerpolicy="no-referrer">` : `<img alt="">`}
      <div><b>${esc(r.title)}</b><small>${esc(r.author)}${r.episodes ? " · " + esc(r.episodes) + " episode" + (r.episodes === 1 ? "" : "s") : ""}</small></div>
      <button class="btn sm pri" data-i="${i}">Follow</button></div>`).join("") : '<div class="meta">nothing found; try the feed link instead</div>';
    res.onclick = ev => { const b = ev.target.closest("[data-i]"); if (b) { const r = found[+b.dataset.i]; follow(r.feed_url, r.title, r.episodes); } };
  } catch (err) { res.innerHTML = ""; toast(err.message, true); }
});

function follow(url, title, count) {
  if (!S) return toast("Still loading, try again in a second", true);
  $("#dlg").className = "small"; $("#dlg").tok = null;
  $("#dlgBody").innerHTML = `<div><h2 id="dlgTitle">Follow ${esc(title)}?</h2><div class="sub">${esc(url)}</div></div>
    <label>Episodes to download<select class="search" id="mode">
      <option value="all" ${S.settings.new_show === "all" ? "selected" : ""}>Every episode${count ? " (" + esc(count) + ")" : ""}</option>
      <option value="new" ${S.settings.new_show === "new" ? "selected" : ""}>Only new episodes from now on</option></select></label>
    <div class="sub">"Every episode" downloads the whole back catalog, one at a time.</div>
    <div class="row-end"><button class="btn" data-close>Cancel</button><button class="btn pri" id="doFollow">Follow</button></div>`;
  $("#doFollow").onclick = async () => {
    $("#doFollow").disabled = true; $("#doFollow").textContent = "Following\u2026";
    try { await api("/api/act", {action: "add", feed_url: url, mode: $("#mode").value}); $("#dlg").close();
          $("#results").innerHTML = ""; $("#q").value = ""; toast("Following " + title); await load(); $("#q").focus(); }
    catch (err) { toast(err.message, true); $("#doFollow").disabled = false; $("#doFollow").textContent = "Follow"; }
  };
  $("#dlg").showModal();
}

$("#results").addEventListener("error", e => { if (e.target.tagName === "IMG") e.target.style.visibility = "hidden"; }, true);
$("#checkBtn").onclick = async () => { try { await api("/api/act", {action: "check"}); toast("Checking every feed now"); setTimeout(poll, 800); } catch (e) { toast(e.message, true); } };
$("#setBtn").onclick = () => {
  if (!S) return toast("Still loading, try again in a second", true);
  $("#dlg").className = "small"; $("#dlg").tok = null;
  $("#dlgBody").innerHTML = `<div><h2 id="dlgTitle">Settings</h2><div class="sub">Files go to &lt;Show&gt;/&lt;Show&gt; &lt;Year&gt;/ with Plex-friendly tags</div></div>
    <label>Check feeds every (minutes, 30–1440)<input class="search" id="mins" type="number" min="30" max="1440" value="${esc(S.settings.check_minutes)}"></label>
    <label>When following a new show<select class="search" id="nshow">
      <option value="all" ${S.settings.new_show === "all" ? "selected" : ""}>Download every episode</option>
      <option value="new" ${S.settings.new_show === "new" ? "selected" : ""}>Only new episodes</option></select></label>
    <div class="row-end"><button class="btn" data-close>Cancel</button><button class="btn pri" id="saveSet">Save</button></div>`;
  $("#mins").onkeydown = e => { if (e.key === "Enter") $("#saveSet").click(); };
  $("#saveSet").onclick = async () => {
    try { await api("/api/act", {action: "settings", check_minutes: +$("#mins").value, new_show: $("#nshow").value}); $("#dlg").close(); toast("Saved"); load(); }
    catch (err) { toast(err.message, true); }
  };
  $("#dlg").showModal();
};

let ACC = null;

async function openAccount(codes, codesNote) {
  $("#dlg").className = ""; $("#dlg").tok = null;
  if (!$("#dlg").open) {
    $("#dlgBody").innerHTML = '<div><h2 id="dlgTitle">Account</h2><div class="sub">loading…</div></div>';
    $("#dlg").showModal();
  }
  try { ACC = await api("/api/account"); }
  catch (err) {
    if (err.status === 404) { $("#accBtn").style.display = "none"; $("#dlg").close(); return; }
    $("#dlgBody").innerHTML = `<div><h2 id="dlgTitle">Account</h2></div><div id="acOnce"></div><div class="empty">couldn\u2019t load: ${esc(err.message)}</div><div class="row-end"><button class="btn" data-close>Close</button></div>`;
    if (codes && codes.length) showCodes(codes, codesNote);
    return;
  }
  drawAccount(codes, codesNote);
}

function sessHtml(list) {
  return (list && list.length ? list.map((s, i) => `<div class="res">
    <div><b>${esc(s.ip || "unknown address")}${s.current ? ' <span class="pill ok">current</span>' : ""}</b>
      <small>${esc(s.ua || "unknown browser")}</small>
      <small>started ${esc(when(s.created))} · last seen ${esc(when(s.seen))}</small></div>
    ${s.current ? "" : `<button class="btn sm warn" data-end="${i}">End</button>`}</div>`).join("") : '<div class="empty">no sessions</div>');
}
function eventsHtml(list) {
  return (list && list.length ? list.map(e => `<div class="meta">${esc(when(e.t))} · ${esc(e.kind)} · ${esc(e.ip || "—")}</div>`).join("") : '<div class="meta">nothing yet</div>');
}
function showCodes(codes, note) {
  const box = $("#acOnce"); if (!box) return;
  const c = document.createElement("div"); c.className = "card";
  const h = document.createElement("div"); h.className = "label"; h.textContent = "Recovery codes";
  const p = document.createElement("div"); p.className = "sub";
  p.textContent = note || "Save these recovery codes now. They are shown only once and each works one time.";
  const l = document.createElement("div"); l.className = "meta"; l.style.marginTop = "10px"; l.style.whiteSpace = "pre";
  l.textContent = codes.join("\n");
  c.append(h, p, l); box.append(c);
}

function drawAccount(codes, codesNote) {
  const a = ACC;
  const noticeCode = a.notice && typeof a.notice === "object" && +a.notice.code > 0 ? +a.notice.code : 0;
  const fails = Array.isArray(a.fails) ? a.fails : [];
  $("#dlgBody").innerHTML = `
  <div><h2 id="dlgTitle">Account</h2><div class="sub">${esc(a.user)}</div></div>
  <div class="pills">
    ${a.totp ? '<span class="pill ok">two-factor on</span>' : '<span class="pill off">two-factor off</span>'}
    <span class="pill q">${esc(a.recovery_left)} recovery code${+a.recovery_left === 1 ? "" : "s"} left</span>
    ${fails.length ? `<span class="pill bad">${esc(fails.length)} failed sign-in${fails.length === 1 ? "" : "s"}</span>` : ""}
  </div>
  <div id="acOnce"></div>
  ${noticeCode ? `<section class="card">
    <div class="label">Warning</div>
    <div class="sub">${esc(noticeCode)} wrong two-step codes were entered with your correct password. If that was not you, change your password now.</div>
    <label>Password<input class="search" type="password" id="acNoticePw" autocomplete="current-password"></label>
    <label>Code from your authenticator app<input class="search" id="acNoticeCode" inputmode="numeric" autocomplete="one-time-code"></label>
    <div class="err" id="acNoticeErr"></div>
    <div class="row-end"><button class="btn" id="acNoticeDone">That was me</button></div>
  </section>` : ""}
  ${fails.length ? `<section class="card"><div class="label">Failed sign-ins</div>${eventsHtml(fails)}</section>` : ""}

  <section class="card">
    <div class="label">Change password</div>
    <label>Current password<input class="search" type="password" id="acPwOld" autocomplete="current-password"></label>
    <label>New password<input class="search" type="password" id="acPwNew" autocomplete="new-password" minlength="${esc(a.min_length)}" placeholder="at least ${esc(a.min_length)} characters"></label>
    ${a.totp ? '<label>Code from your authenticator app<input class="search" id="acPwCode" inputmode="numeric" autocomplete="one-time-code"></label>' : ""}
    <div class="err" id="acPwErr"></div>
    <div class="row-end"><button class="btn pri" id="acPwGo">Change password</button></div>
  </section>

  <section class="card">
    <div class="label">Two-factor authentication</div>
    ${a.totp ? `
      <div class="sub">Enter your password and a current code to turn it off.</div>
      <label>Password<input class="search" type="password" id="acOffPw" autocomplete="current-password"></label>
      <label>Code from your authenticator app<input class="search" id="acOffCode" inputmode="numeric" autocomplete="one-time-code"></label>
      <div class="err" id="acOffErr"></div>
      <div class="row-end"><button class="btn warn" id="acTotpOff">Turn off two-factor</button></div>` : `
      <div class="sub">Protect sign-in with a code from an authenticator app.</div>
      <label>Password<input class="search" type="password" id="acTotpPw" autocomplete="current-password"></label>
      <div class="err" id="acTotpErr"></div>
      <div class="row-end"><button class="btn pri" id="acTotpStart">Set up two-factor</button></div>
      <div id="acTotpBox"></div>`}
  </section>

  <section class="card">
    <div class="label">Recovery codes</div>
    <div class="sub">Use one of these instead of an authenticator code if you lose access to your app.</div>
    <label>Password<input class="search" type="password" id="acRecPw" autocomplete="current-password"></label>
    <label>Code from your authenticator app<input class="search" id="acRecCode" inputmode="numeric" autocomplete="one-time-code"></label>
    <div class="err" id="acRecErr"></div>
    <div class="row-end"><button class="btn" id="acRecGo">Generate new recovery codes</button></div>
  </section>

  <section class="card">
    <div class="label">Signed-in sessions</div>
    <div class="results" id="acSess">${sessHtml(a.sessions)}</div>
    <label>Password<input class="search" type="password" id="acSessPw" autocomplete="current-password"></label>
    <label>Code from your authenticator app<input class="search" id="acSessCode" inputmode="numeric" autocomplete="one-time-code"></label>
    <div class="err" id="acSessErr"></div>
    <div class="row-end"><button class="btn warn" id="acEndAll">End all sessions</button></div>
  </section>

  <section class="card">
    <div class="label">Recent security events</div>
    ${eventsHtml(a.events)}
  </section>

  <div class="err" id="acLogErr"></div>
  <div class="row-end"><button class="btn" data-close>Close</button><button class="btn danger" id="acLogout">Sign out</button></div>`;

  if (codes && codes.length) showCodes(codes, codesNote);

  const nBtn = $("#acNoticeDone");
  if (nBtn) nBtn.onclick = async () => {
    const e1 = $("#acNoticeErr"); e1.textContent = ""; nBtn.disabled = true;
    try {
      await api("/api/account/notice/dismiss", {password: $("#acNoticePw").value, code: $("#acNoticeCode").value.trim(), seen: noticeCode});
      toast("Notice dismissed"); await openAccount();
    } catch (err) { e1.textContent = err.message; nBtn.disabled = false; }
  };

  $("#acPwGo").onclick = async () => {
    const e1 = $("#acPwErr"), b = $("#acPwGo"); e1.textContent = ""; b.disabled = true;
    const body = {password: $("#acPwOld").value, new: $("#acPwNew").value};
    if ($("#acPwCode")) body.code = $("#acPwCode").value.trim();
    try { await api("/api/account/password", body); toast("Password changed"); b.disabled = false; await openAccount(); }
    catch (err) { e1.textContent = err.message; b.disabled = false; }
  };

  const tStart = $("#acTotpStart");
  if (tStart) tStart.onclick = async () => {
    const e1 = $("#acTotpErr"); e1.textContent = ""; tStart.disabled = true;
    try {
      const r = await api("/api/account/totp/start", {password: $("#acTotpPw").value});
      $("#acTotpBox").innerHTML = `<div class="sub">Scan this with your authenticator app.</div>
        <img alt="Two-factor QR code" width="220" height="220" style="background:#fff;border-radius:12px;padding:8px" src="data:image/svg+xml;utf8,${encodeURIComponent(r.qr)}">
        <div class="sub">Or enter this secret by hand: <b id="acSecret"></b></div>
        <label>Code from the app<input class="search" id="acTotpCode" inputmode="numeric" autocomplete="one-time-code"></label>
        <div class="err" id="acTotpCErr"></div>
        <div class="row-end"><button class="btn pri" id="acTotpConfirm">Turn on two-factor</button></div>`;
      $("#acSecret").textContent = r.secret;
      $("#acTotpConfirm").onclick = async () => {
        const ce = $("#acTotpCErr"), cb = $("#acTotpConfirm"); ce.textContent = ""; cb.disabled = true;
        try {
          const c = await api("/api/account/totp/confirm", {code: $("#acTotpCode").value.trim()});
          toast("Two-factor is on");
          await openAccount(c.recovery, "Save these recovery codes now: they are shown only once and each works one time.");
        } catch (err) { ce.textContent = err.message; cb.disabled = false; }
      };
    } catch (err) { e1.textContent = err.message; tStart.disabled = false; }
  };

  const tOff = $("#acTotpOff");
  if (tOff) tOff.onclick = async () => {
    const e1 = $("#acOffErr"); e1.textContent = ""; tOff.disabled = true;
    try { await api("/api/account/totp/off", {password: $("#acOffPw").value, code: $("#acOffCode").value.trim()}); toast("Two-factor turned off"); await openAccount(); }
    catch (err) { e1.textContent = err.message; tOff.disabled = false; }
  };

  $("#acRecGo").onclick = async () => {
    const e1 = $("#acRecErr"), b = $("#acRecGo"); e1.textContent = ""; b.disabled = true;
    try {
      const r = await api("/api/account/recovery", {password: $("#acRecPw").value, code: $("#acRecCode").value.trim()});
      toast("New recovery codes");
      await openAccount(r.recovery, "New recovery codes. The old ones no longer work. Save these now.");
    } catch (err) { e1.textContent = err.message; b.disabled = false; }
  };

  $("#acSess").onclick = async ev => {
    const b = ev.target.closest("[data-end]"); if (!b) return;
    const e1 = $("#acSessErr"); e1.textContent = ""; b.disabled = true;
    try {
      await api("/api/account/sessions/end", {password: $("#acSessPw").value, code: $("#acSessCode").value.trim(), id: ACC.sessions[+b.dataset.end].id});
      toast("Session ended"); await openAccount();
    } catch (err) { e1.textContent = err.message; b.disabled = false; }
  };
  $("#acEndAll").onclick = async () => {
    const e1 = $("#acSessErr"), b = $("#acEndAll"); e1.textContent = ""; b.disabled = true;
    try { await api("/api/account/sessions/end", {password: $("#acSessPw").value, code: $("#acSessCode").value.trim(), all: true}); toast("All sessions ended"); await openAccount(); }
    catch (err) { e1.textContent = err.message; b.disabled = false; }
  };

  $("#acLogout").onclick = async () => {
    const e1 = $("#acLogErr"), b = $("#acLogout"); e1.textContent = ""; b.disabled = true;
    try { await api("/api/logout", {}); location.href = "/login"; }
    catch (err) { e1.textContent = err.message; b.disabled = false; }
  };
}

$("#accBtn").onclick = () => openAccount();
api("/api/account").catch(e => { if (e.status === 404) { const b = $("#accBtn"); if (b) b.style.display = "none"; } });
if (location.hash === "#account") openAccount();

function poll() { clearTimeout(timer); if (!document.hidden) load(); timer = setTimeout(poll, S && S.status.state !== "idle" ? 3000 : 15000); }
document.addEventListener("visibilitychange", () => { if (!document.hidden) poll(); });
poll();
