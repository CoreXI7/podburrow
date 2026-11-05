// The sign-in page: create the account (first run, with the setup code), sign in, then the authenticator code if on.
// Nothing here is trusted by the server: it checks everything again; this only shows the right form and messages.
const $ = id => document.getElementById(id);
// where to go afterwards: one of our pages with a plain query (?wall, ?security=fw), as the server allows
const NEXT = (() => { const n = new URLSearchParams(location.search).get("next") || "/";
  return /^\/(?:settings)?(?:\?[A-Za-z0-9_=&-]{1,100})?$/.test(n) ? n : "/"; })();
const FORMS = ["f-signin", "f-code", "f-setup", "f-notice", "f-broken"];
let waitTimer = 0, waiting = false;

// background motion as on the app: this browser's choice (M / 🫧 there), else the site's default
(() => {
  let m = ""; try { m = localStorage.getItem("motion") || ""; } catch (e) { /* storage off */ }
  const mode = ["on", "off"].includes(m) ? m : (document.documentElement.dataset.siteMotion || "auto");
  const still = mode === "off" || (mode === "auto" && matchMedia("(prefers-reduced-motion: reduce)").matches);
  document.documentElement.dataset.motion = still ? "still" : "move";
})();

const TITLES = {"f-setup": ["Set up Podburrow", "Set up · Podburrow"], "f-notice": ["Since you last signed in", "Signed in · Podburrow"]};
function show(form) {
  for (const id of FORMS) $(id).hidden = id !== form;
  $("login-loading").hidden = true;
  const [heading, title] = TITLES[form] || ["Podburrow", "Sign in · Podburrow"];
  $("login-heading").textContent = heading; document.title = title;
  const first = $(form) && $(form).querySelector("#notice-text, input:not([type=checkbox]), button.login-go");
  if (first) first.focus();
}

function say(text, field) {
  const box = $("login-msg");
  document.querySelectorAll("[aria-invalid]").forEach(el => el.removeAttribute("aria-invalid"));
  box.hidden = !text;
  box.textContent = text || "";
  if (field && $(field)) { $(field).setAttribute("aria-invalid", "true"); $(field).focus(); }
}

async function call(path, body) {
  const r = await fetch(path, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body),
                               credentials: "same-origin", cache: "no-store"});
  let d = {};
  try { d = await r.json(); } catch (e) { /* not JSON: keep {} */ }
  return {status: r.status, d};
}

const fmt = s => s >= 60 ? `${Math.floor(s / 60)} min ${s % 60} s` : `${s} s`;

// after a 429: the buttons stay off until the wait is over. The message is announced once; the ticking time next to
// it is hidden from screen readers (an alert rewritten every second would be read out every second).
function wait(seconds, text) {
  clearInterval(waitTimer);
  const buttons = document.querySelectorAll(".login-go");
  let left = Math.max(1, Math.min(900, seconds | 0));
  waiting = true;
  buttons.forEach(b => b.disabled = true);
  say(text || `Too many tries. You can try again in ${fmt(left)}.`);
  const tick = () => { $("login-wait").textContent = `${fmt(left)} left`; };
  $("login-wait").hidden = false;
  tick();
  waitTimer = setInterval(() => {
    left -= 1;
    if (left > 0) return tick();
    clearInterval(waitTimer);
    waiting = false;
    buttons.forEach(b => b.disabled = false);
    $("login-wait").hidden = true;
    say("You can try again now.");
  }, 1000);
}

async function submit(form, path, body, onOk) {
  const go = form.querySelector(".login-go");
  let refocus = null;   // after an answer that names no field: back to the form's main box (the button is still off now)
  go.disabled = true;
  say("");
  try {
    const {status, d} = await call(path, body);
    if (status === 200) return onOk(d);
    if (status === 429) { wait(d.retry || 60, d.busy || d.hint ? d.error : null); refocus = form.querySelector("input:not([type=checkbox]):not([type=hidden])"); return; }
    if (status === 503) { await init(); return $("f-broken").hidden ? say(d.error) : undefined; }   // re-read: show what's true now
    if (d.setup) { show("f-setup"); return say(d.error); }
    if (d.restart) { $("c-code").value = ""; show("f-signin"); return say(d.error || "Sign in again."); }
    const field = d.field ? form.querySelector(`[data-field="${d.field}"]`) : null;
    say(d.error || `Something went wrong (${status}).`, field ? field.id : null);
    if (!field) refocus = form.querySelector("input[type=password], input:not([type=checkbox])");
  } catch (e) {
    say("Couldn't reach the app. Check your connection and try again.");
    refocus = form.querySelector("input[type=password], input:not([type=checkbox])");
  } finally {
    if (!waiting) go.disabled = false;
    if (refocus) refocus.focus();
  }
}

// once after signing in: what happened since the last sign-in (wrong tries, a recovery code used)
function signedIn(d) {
  const n = d && d.notice;
  if (!n) return location.replace(NEXT);
  const times = k => k > 1 ? `${k} times` : "Once", acct = '<a href="/#account">Settings → Account</a>';
  const lines = [];   // (this browser's own typos just before aren't counted: the server leaves them out)
  if (n.code) lines.push(`<p><b>${times(n.code)}, someone typed your password right but not the right code (a wrong one, or none).</b>
    If that wasn't you, your password is known: change it in ${acct}.</p>`);
  if (n.password) lines.push(`<p>${n.password} wrong name or password tr${n.password > 1 ? "ies" : "y"} since your last sign-in.</p>`);
  if (n.settings) lines.push(`<p>${n.settings} wrong password${n.settings > 1 ? "s or codes were" : " or code was"} typed in
    ${acct} since your last sign-in.</p>`);
  if (n.recovery_left !== undefined) lines.push(`<p>You used a recovery code: ${n.recovery_left} left.
    ${n.recovery_left < 3 ? `Make new ones in ${acct}.` : ""}</p>`);
  $("notice-text").innerHTML = lines.join("");   // numbers only: nothing from outside goes in here
  show("f-notice");
}

$("f-signin").addEventListener("submit", e => {
  e.preventDefault();
  submit($("f-signin"), "/api/login", {user: $("si-user").value, password: $("si-pw").value, keep: $("si-keep").checked},
         d => { $("si-pw").value = ""; if (d.code_due) show("f-code"); else signedIn(d); });
});
$("f-code").addEventListener("submit", e => {
  e.preventDefault();
  submit($("f-code"), "/api/login/code", {code: $("c-code").value.trim()}, d => { $("c-code").value = ""; signedIn(d); });
});
$("c-restart").addEventListener("click", async () => {
  $("c-code").value = ""; say(""); show("f-signin");
  try { await call("/api/logout", {}); } catch (e) { /* the half-finished sign-in also runs out by itself */ }
});
$("f-setup").addEventListener("submit", e => {
  e.preventDefault();
  if ($("su-pw").value !== $("su-pw2").value) return say("The two passwords aren't the same.", "su-pw2");
  submit($("f-setup"), "/api/setup-account", {code: $("su-code").value.trim(), user: $("su-user").value,
                                               password: $("su-pw").value, keep: $("su-keep").checked}, signedIn);
});
$("notice-go").addEventListener("click", () => location.replace(NEXT));
document.querySelectorAll(".pw-show").forEach(b => b.addEventListener("click", () => {
  const input = $(b.dataset.show), showing = input.type === "text";
  input.type = showing ? "password" : "text";
  b.textContent = showing ? "Show" : "Hide";
  b.setAttribute("aria-label", showing ? "Show the password" : "Hide the password");
}));
// the server's field names -> this page's inputs
for (const [id, field] of [["si-user", "user"], ["si-pw", "password"], ["c-code", "code"], ["su-code", "code"], ["su-user", "user"], ["su-pw", "password"]])
  $(id).dataset.field = field;

// which form to show: asked at load, and again when an answer says things changed (a reset on the host, say)
async function init() {
  try {
    const r = await fetch("/api/auth/state", {credentials: "same-origin", cache: "no-store"});
    const s = await r.json();
    if (s.mode !== "login" || s.signed_in) return location.replace(NEXT);
    document.querySelectorAll(".pw-min").forEach(el => el.textContent = s.min_length || 15);
    const onHttps = location.protocol === "https:", warn = text => {
      $("login-http").hidden = !text; if (text) $("login-http").textContent = "⚠ " + text; };
    // what's in the way, worded by the server (s.gap_hint), else by what this page can see
    warn(s.gap_hint || (!onHttps ? "This page isn't using HTTPS: your password travels unencrypted. Reach the app "
                                   + "through your reverse proxy's https address."
                        : s.https === false ? "Your reverse proxy tells Podburrow this connection is plain HTTP, although "
                                   + "this page uses https. Make it send X-Forwarded-Proto: https." : ""));
    $("login-proxy").hidden = !s.proxy_asked;
    if (s.broken) return show("f-broken");
    if (!s.http_ok) {   // a password from here would be refused: say why instead of showing the form
      show("");
      if (!s.gap_hint && !onHttps)
        warn("This page isn't using HTTPS, and you're not on the server's own network, so signing in is turned off here. "
             + "Open the app through your reverse proxy's https address.");
      return;
    }
    show(s.setup ? "f-setup" : s.code_due ? "f-code" : "f-signin");
  } catch (e) {
    $("login-loading").hidden = false;
    $("login-loading").textContent = "Couldn't reach the app. Reload the page to try again.";
  }
}
init();
