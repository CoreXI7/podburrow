"""signin-core: the sign-in web layer shared by Fishbowl, Podburrow and Subplot (contract: SPEC.md).

Moved unchanged in behaviour from Fishbowl's app.py (commit 549fb7f, class Handler); the app-specific parts are Config
fields and hooks the app's handler provides: send, https, client_ip, plain_http_ok, log, refuse_page, public_extra,
transport_refusal, auth_state_extra. New: failure alerts at ALERT_AT wrong tries in a row (one log line each).
The app calls setup(config) once at start, before serving, in every mode: setup touches no file, and in proxy/off mode
nothing calls into the mixin beyond gate()'s first line, so data_dir is never opened.
"""
import dataclasses, hashlib, hmac, re, secrets, threading, time

from . import auth

ALERT_AT = (10, 50, 90)
_COOKIE = re.compile(r"[a-z][a-z0-9-]{0,30}")


@dataclasses.dataclass(frozen=True)
class Config:
    auth: str                    # "login", "proxy", or "off" (a demo without sign-in)
    app: str                     # display name and authenticator issuer
    cookie: str                  # base cookie name
    error_key: str               # "error" or "why": the reply field for messages
    settings_label: str          # "Settings" or "Account"
    service_noun: str            # "the dashboard", "the app", "the page's service" (in "...ends when X restarts")
    signin_first: str            # the 401 text for an API call without a session
    open_noun: str               # "the dashboard", "the app", "the page" (in "Open X and create the account")
    banned_words: tuple          # words a password may not contain (besides the user name)
    cli_hint: str                # how to run auth.py's command line on this install (unlock/reset hints build on it)
    reset_keeps: str             # what a reset leaves alone ("settings and keys stay")
    setup_code_hint: str         # the sign-in page's advice on finding the newest setup code
    setup_code_where: str        # the command line's "a setup code exists: <where>"
    run_as_hint: str             # the command line's "run it as ..." sentence
    data_dir: str                # auth.json, sessions.json, setup-code
    public_get: frozenset
    public_post: frozenset
    pages: frozenset

    def __post_init__(self):
        def fail(field):
            raise ValueError(f"signin_core Config: bad {field}")
        for f in ("auth", "app", "cookie", "error_key", "settings_label", "service_noun", "open_noun", "signin_first",
                  "cli_hint", "reset_keeps", "setup_code_hint", "setup_code_where", "run_as_hint", "data_dir"):
            if not isinstance(getattr(self, f), str) or not getattr(self, f):
                fail(f)
        if self.auth not in ("login", "proxy", "off"):   # off: Fishbowl's public demo (no sign-in at all)
            fail("auth")
        if not _COOKIE.fullmatch(self.cookie):
            fail("cookie")
        if self.error_key not in ("error", "why"):
            fail("error_key")
        if not self.data_dir.startswith("/"):
            fail("data_dir")
        for f in ("public_get", "public_post", "pages", "banned_words"):
            v = getattr(self, f)
            if not isinstance(v, (list, tuple, set, frozenset)):     # (a string, a dict or a one-shot generator: no)
                fail(f)
            v = tuple(v) if f == "banned_words" else frozenset(v)   # converted first, then checked: what is kept is what was checked
            if f == "banned_words":
                ok = all(isinstance(w, str) for w in v)
            else:
                ok = all(isinstance(p, str) and p.startswith("/") for p in v)
            if not ok:
                fail(f)
            object.__setattr__(self, f, v)

    @property
    def unlock_hint(self):
        return self.cli_hint + " unlock"

    @property
    def reset_hint(self):
        return f"{self.cli_hint} reset ({self.reset_keeps})."


CFG = None
ACCOUNT = SESSIONS = THROTTLE = None


def setup(config):
    """Once at start (any mode). Touches no file: the data folder is opened on first use."""
    global CFG, ACCOUNT, SESSIONS, THROTTLE
    if not isinstance(config, Config):
        raise TypeError("signin_core.web.setup needs a Config")
    CFG = config
    auth.configure(config)
    ACCOUNT, SESSIONS, THROTTLE = auth.Account(), auth.Sessions(), auth.Throttle()


_pending = {}                 # sha256(pre-sign-in token) -> {"t", "keep", "tries", "wrong", "dev", "epoch", "tls", "from"}: the password was right, a code is due
_ran_out = []                 # half-finished sign-ins that ran out, until they're noted as failures (tell_ran_out)
_pending_totp = {}            # sha256(session token) -> {"t", "secret", "epoch"}: an authenticator being set up, not confirmed yet
_recent_fails = {}            # trusted-device hash -> [(time, "password" | "code", address)]: typos in that browser, forgiven at its next sign-in
_session_tries = {}           # sha256(session token) -> (wrong tries, last): re-confirming the password in Settings/Account
SESSION_FAILS = 10            # wrong tries a signed-in browser gets before it's signed out
_pending_lock = threading.RLock()
_try_lock = threading.Lock()  # counting a try, and using up a code, happen one at a time
PENDING_FOR = 300             # seconds to type the code after the password
CODE_USED = "That code was just used. Wait for the next one in your app (a new one every 30 seconds)."
TOO_LATE = {"error": "The password or two-step sign-in changed meanwhile: reload the page (sign in again if asked) and "
                     "try again.", "restart": True}

def ended_unfinished(steps, why):
    """Half-finished sign-ins ended without the right code ("Start over", tries used up, cleared): told to the owner
    like one that ran out, unless a wrong code in them already was. Call with _pending_lock held."""
    _ran_out.extend({**p, "ended": why} for p in steps if not p.get("wrong"))
    del _ran_out[:-200]

def fmt_wait(sec):
    return f"{sec // 60} min {sec % 60} s" if sec >= 60 else f"{sec} s"


class SignIn:
    """Mixed into the app's request handler. The app provides the hooks named in the module docstring."""

    def _reply(self, code, body, extra=None, cookies=()):
        """Every reply of the sign-in goes through here: the message field takes the app's name, then the app sends it."""
        if isinstance(body, dict) and CFG.error_key != "error" and "error" in body:
            body = {(CFG.error_key if k == "error" else k): v for k, v in body.items()}
        return self.send(code, body, extra=extra, cookies=cookies)

    def cookie_values(self, base):
        """Every value sent for one of our cookies that has our tokens' shape, read by hand (http.cookies drops every
        cookie when one is odd). All of them, in any position: a site that can set cookies for a parent domain could
        otherwise push ours out by sending junk ones first. Over HTTPS only the __Host- name counts, which no other
        site or subdomain can set."""
        name = ("__Host-" + base) if self.https() else base
        vals, seen = [], set()
        for part in "; ".join(self.headers.get_all("Cookie") or []).split(";"):   # (a header line is at most 64 KB)
            k, sep, v = part.strip(" \t").partition("=")
            v = v.strip(" \t")
            if sep and k == name and v not in seen and auth.TOKEN.fullmatch(v):
                seen.add(v)
                vals.append(v)
                if len(vals) >= 300:   # a browser keeps at most ~180 cookies per site: more can only come from a script
                    break
        return vals

    def make_cookie(self, base, value, max_age=None, clear=False):
        """HttpOnly (scripts can't read it), SameSite=Strict (never sent on a request another site starts; a link from
        elsewhere bounces through /login, which sees the session and comes straight back), and over HTTPS Secure with
        the __Host- name (no other site or subdomain can set or read it)."""
        secure = self.https()
        parts = [f"{'__Host-' + base if secure else base}={'' if clear else value}", "Path=/", "HttpOnly", "SameSite=Strict",
                 "Priority=High"]   # (Chrome evicts lower-priority cookies first when a sibling site floods the jar)
        if secure:
            parts.append("Secure")
        if clear:
            parts.append("Max-Age=0")
        elif max_age:
            parts.append(f"Max-Age={int(max_age)}")
        return "; ".join(parts)

    def account(self):
        """The account, or None when there's none or its file is damaged (then nobody is signed in)."""
        try:
            return ACCOUNT.get()
        except auth.Broken:
            return None

    def session_token(self):
        """This request's session token if it's valid (looked up once per request). Sessions from before the last
        password change or two-step change (an older epoch) don't count."""
        if self._token is None:
            d = self.account()
            tls = self.https()
            # a plain-HTTP session counts only on your own network, and only over plain HTTP (it was exposed there)
            ok = d and (tls or self.plain_http_ok())
            self._token = next((t for t in self.cookie_values(CFG.cookie) if SESSIONS.check(t, d["epoch"], self.client_ip(), tls)), "") if ok else ""
            if self._token and self.session_spent(hashlib.sha256(self._token.encode()).hexdigest()):
                SESSIONS.end(self._token)   # its 10 wrong tries are used up, whichever reply used the last one
                self._token = ""
        return self._token or None

    def device(self, acct):
        """This browser's trusted-device token hash (it signed in here before), or None."""
        tls = self.https()
        return next((h for h in (auth.device_of(acct, t, tls) for t in self.cookie_values(CFG.cookie + "-device")) if h), None) if acct else None

    def gate(self, p, post=False, q=""):
        """AUTH=login: everything except the public paths needs a session. Pages are answered by the app's
        refuse_page (a redirect to its sign-in page); the API answers 401. Public paths are matched exactly, after the
        app's own path checks."""
        if CFG.auth != "login" or p in (CFG.public_post if post else CFG.public_get):
            return True
        if not post and self.public_extra(p):
            return True
        refusal = self.transport_refusal(p, post, "gate")
        if refusal:
            self._reply(*refusal)
            return False
        if self.session_token():
            return True
        if not post and p in CFG.pages:
            self.refuse_page(p, q)
        else:
            self._reply(401, {"error": CFG.signin_first, "signin": True})
        return False

    def auth_state(self):
        """What the sign-in page needs to know (nothing about the account itself)."""
        if CFG.auth != "login":
            return {"mode": CFG.auth}
        try:
            broken, setup = False, ACCOUNT.get() is None
        except auth.Broken:
            broken, setup = True, False
        return {"mode": "login", "setup": setup, "broken": broken, "signed_in": bool(self.session_token()),
                "code_due": bool(self.pending()), "https": self.https(), "min_length": auth.PW_MIN, **self.auth_state_extra()}

    def pending(self, consume=False):
        """The half-finished sign-in for this browser (the password was right; the authenticator code is due). One that
        ran out without the right code is told to the owner like a wrong code: someone with the password who never
        types a code would otherwise confirm it again and again unseen."""
        now = time.time()
        with _pending_lock:
            _ran_out.extend(_pending.pop(k) for k in [k for k, v in _pending.items() if now - v["t"] > PENDING_FOR])
            del _ran_out[:-200]
        with _pending_lock:
            tls = self.https()
            for tok in self.cookie_values(CFG.cookie + "-pre"):
                key = hashlib.sha256(tok.encode()).hexdigest()
                p = _pending.get(key)   # (only on its kind of connection and, over plain HTTP, from where it started)
                if p and p.get("tls") == tls and (tls or auth.same_place(p.get("from"), self.client_ip())):
                    return _pending.pop(key) if consume else p
        return None

    def tell_ran_out(self):
        """Note the half-finished sign-ins that ran out or ended without the right code (pending() and ended_unfinished()
        collect them) as failures. Called where no lock is held: noting takes the account's file lock."""
        with _pending_lock:
            gone = _ran_out[:]
            _ran_out.clear()
        for p in gone:
            self.note_failure(p.get("from") or "?", f"right password, no code ({p.get('ended', 'the step ran out')})", "code",
                              p.get("dev"))

    def begin_try(self, ip, dev=None, account=True, session=None, waits=True):
        """Count a try BEFORE checking it, under one lock: parallel tries can't all slip in under a limit, and a crash
        mid-check still counted it. 0 = go ahead, -1 = locked, -2 = this session used up its tries; otherwise the
        seconds to wait. A trusted device (signed in here before) counts on its own, so someone hammering the account
        can't lock its owner out; so does a signed-in browser re-confirming the password (session), which then gets
        10 tries before it's signed out. waits=False (the code step): counted the same, toward the lock too, but
        never made to wait, or someone else's guessing could make every wait outlast the 5-minute step (that step
        has its own cap: 5 codes)."""
        now = time.time()
        with _try_lock:
            if session:
                fails, last = _session_tries.get(session, (0, 0))
                if fails >= SESSION_FAILS:
                    return -2
                wait = THROTTLE.wait_for(fails, last, now)
                if not wait:
                    if len(_session_tries) > 1000:
                        _session_tries.clear()
                    _session_tries[session] = (fails + 1, now)
                return wait
            d = ACCOUNT.get() if account else None
            if d and dev and dev in d.get("devices", {}) and d["devices"][dev].get("fails", 0) < auth.DEVICE_FAILS:   # (worn out: just a browser)
                v = d["devices"][dev]
                wait = THROTTLE.wait_for(v.get("fails", 0), v.get("last", 0), now) if waits else 0
                if not wait:
                    ACCOUNT.update(lambda x: x["devices"][dev].update(fails=x["devices"][dev].get("fails", 0) + 1, last=int(now))
                                   if dev in x.get("devices", {}) else None)
                return wait
            wait = THROTTLE.ip_wait(ip, now) if waits else 0
            if d:
                if d.get("failures", 0) >= auth.LOCK_AT:
                    return -1
                if waits:
                    wait = max(wait, THROTTLE.wait_for(d.get("failures", 0), d.get("last_fail", 0), now))
            if wait:
                return wait
            THROTTLE.ip_failed(ip, now)
            if d:
                reached = []

                def count(x):   # one locked update: each count is reached exactly once per climb, so no alert repeats or skips
                    x.update(failures=x.get("failures", 0) + 1, last_fail=int(now))
                    if x["failures"] in ALERT_AT:
                        reached.append(x["failures"])
                ACCOUNT.update(count)
                for n in reached:
                    self.log(f"sign-in: {n} tries in a row without a successful sign-in (wrong ones lock new browsers at "
                             f"{auth.LOCK_AT}); last from {ip}")
            return 0

    def session_spent(self, session):
        """The wrong try just counted was this signed-in browser's last one: it is signed out now, not on its next try
        (until then a stolen session would still read and change everything else)."""
        with _try_lock:
            return _session_tries.get(session, (0, 0))[0] >= SESSION_FAILS

    def try_ok(self, ip, dev=None, session=None):
        """A right answer: this address's count starts again, and the browser's own: the session's, a trusted
        device's, or (from any other browser) the account's. A trusted device never clears the account's count, so
        someone else's guessing keeps counting toward the lock while the owner signs in."""
        THROTTLE.ip_ok(ip)
        if session:
            _session_tries.pop(session, None)
            return
        ACCOUNT.update(lambda x: x["devices"][dev].update(fails=0) if dev and dev in x.get("devices", {})
                       else x.update(failures=0, last_fail=0))

    def refuse_wait(self, wait, new_browser=False, counted=False):
        """new_browser: a sign-in from a browser that never signed in here (someone else's guessing can keep it waiting:
        the account-wide waits are what stop guessing from many addresses at once), so it's told the way around."""
        if wait == -2:
            SESSIONS.end(self._token or "")
            ip = self.client_ip()
            try:
                if not counted:   # (the wrong try that used up the last one was already noted)
                    ACCOUNT.update(lambda x: ACCOUNT.fail(x, f"signed out after {SESSION_FAILS} wrong tries in {CFG.settings_label}", ip, "settings"))
            except auth.Broken:
                pass
            self.log(f"sign-in: a browser at {ip} signed out after {SESSION_FAILS} wrong tries in {CFG.settings_label}")
            return self._reply(401, {"error": f"{SESSION_FAILS} wrong tries in this browser: it's signed out. Sign in again.",
                                   "signin": True}, cookies=(self.make_cookie(CFG.cookie, "", clear=True),))
        if wait < 0:
            return self._reply(423, {"error": f"Sign-ins from new browsers are locked after {auth.LOCK_AT} wrong tries in a row. "
                                            "A browser that signed in here before (and hasn't had 10 wrong tries of its own) can still sign in; "
                                            "or unlock it on the host: " + CFG.unlock_hint})
        if new_browser:
            return self._reply(429, {"error": f"Too many wrong tries (anyone's count). Wait {fmt_wait(wait)}, or sign in from a "
                                            "browser you've signed in with before: it isn't kept waiting.", "retry": wait,
                                   "hint": True}, extra={"Retry-After": str(wait)})
        return self._reply(429, {"error": f"Too many tries. Wait {fmt_wait(wait)}, then try again.", "retry": wait},
                         extra={"Retry-After": str(wait)})

    def note_failure(self, ip, what, count=None, dev=None):
        """Log a failure; count = "password" or "code" counts it toward the next sign-in's notice. One made in a trusted
        browser (dev) is remembered for that browser: if the same browser then signs in, it was a typo. (Never by
        address: an attacker can share one with the owner, or every visitor can look alike.)"""
        try:
            ACCOUNT.update(lambda d: ACCOUNT.fail(d, what, ip, count))
        except auth.Broken:
            pass
        if count and dev:
            with _pending_lock:
                if len(_recent_fails) > 1000:
                    _recent_fails.clear()
                _recent_fails.setdefault(dev, []).append((time.time(), count, ip))
        self.log(f"sign-in: {what} from {ip}")

    @staticmethod
    def own_typos(dev, ip, wrong_codes=0):
        """What the sign-in that follows forgives: this trusted browser's own wrong passwords and codes of the last 10
        minutes typed from this same address (a copied device cookie used elsewhere isn't the owner typing), and the
        wrong codes of this very sign-in (its half-finished step). Every other record is dropped: after a sign-in,
        older ones can only be stale."""
        now = time.time()
        with _pending_lock:
            mine = [k for t, k, at in _recent_fails.get(dev, []) if now - t < 600 and at == ip] if dev else []
            _recent_fails.clear()
        return {"password": mine.count("password"), "code": max(mine.count("code"), wrong_codes)}

    def revoke_everything(self, ip, why, change, epoch):
        """One way out for every change that must end other access (password changed, two-step turned on or off): the
        change and a new epoch are saved together, so every session, half-finished sign-in and trusted device from
        before is worthless from that moment, even one being created right now. Applied only if the account is still
        at the epoch the change was approved under (and this browser's session still counts): a change approved just
        before another one can't land after it. This browser gets a new session and device (returned as cookies);
        None when it was too late."""
        ua = self.headers.get("User-Agent", "")
        cur = SESSIONS.check(self._token, epoch) if self._token else None
        if not cur:
            return None
        new = {}

        def apply(x):   # (under the account's file lock, which every sign-out also takes)
            if x["epoch"] != epoch or not SESSIONS.on_disk(self._token, epoch):
                return
            change(x)
            x["epoch"] = auth.new_epoch(epoch)
            x["devices"] = {}
            new.update(dev=auth.new_device(x, self.https()), epoch=x["epoch"])
            ACCOUNT.event(x, why, ip, ua)
        ACCOUNT.update(apply)
        if not new:
            return None
        SESSIONS.end_all()
        with _pending_lock:
            ended_unfinished(_pending.values(), "every browser was signed out")
            _pending.clear()
            _pending_totp.clear()
        token, max_age = SESSIONS.create(bool(cur.get("keep")), ip, ua, new["epoch"], self.https())
        self._token = token
        self.log(f"sign-in: {why} from {ip}: every other browser signed out")
        return (self.make_cookie(CFG.cookie, token, max_age), self.make_cookie(CFG.cookie + "-device", new["dev"], auth.DEVICE_FOR))

    def signed_in_now(self, ip, keep, what, dev, epoch, extra_cookies=(), wrong_codes=0):
        """Start a session (a new token: never one the browser brought) for the account as it was when the password was
        checked (epoch), and remember this browser as a trusted device. Failures since the last sign-in are shown once."""
        ua = self.headers.get("User-Agent", "")
        token, max_age = SESSIONS.create(keep, ip, ua, epoch, self.https())
        mine = self.device(ACCOUNT.get())   # (forgive only this browser's own typos: a step planted from elsewhere isn't)
        out, typos = {}, self.own_typos(dev if dev and dev == mine else None, ip, wrong_codes if dev and dev == mine else 0)

        def apply(x):
            if x["epoch"] != epoch:   # the password or two-step changed meanwhile: that session is already worthless
                return
            if not dev:
                out["dev"] = auth.new_device(x, self.https())
            ACCOUNT.event(x, what, ip, ua)
            since = {k: v - typos.get(k, 0) for k, v in x.get("since", {}).items()
                     if k in ("password", "code", "settings") and v > typos.get(k, 0)}
            x["since"] = {}
            if since.get("code"):   # the lasting alarm adds up until the password changes (or "That was me")
                x["notice"] = {"code": x.get("notice", {}).get("code", 0) + since["code"], "t": int(time.time())}
            out.update(ok=True, since=since, recovery_left=len(x.get("recovery", [])))
        ACCOUNT.update(apply)
        if not out.get("ok"):
            SESSIONS.end(token)
            return self._reply(401, {"error": "The password or two-step sign-in just changed: sign in again.", "restart": True},
                             cookies=(self.make_cookie(CFG.cookie + "-pre", "", clear=True),))
        self.try_ok(ip, dev)
        cookies = [self.make_cookie(CFG.cookie, token, max_age), *extra_cookies]
        if out.get("dev"):
            cookies.append(self.make_cookie(CFG.cookie + "-device", out["dev"], auth.DEVICE_FOR))
        self.log(f"sign-in: {what} from {ip}")
        notice = dict(out["since"])
        if "recovery code" in what:
            notice["recovery_left"] = out["recovery_left"]
        self._reply(200, {"ok": True, **({"notice": notice} if notice else {})}, cookies=cookies)

    def account_view(self):
        d = ACCOUNT.get()
        return {"user": d["user"], "totp": bool(d["totp"].get("on")), "recovery_left": len(d.get("recovery", [])),
                "sessions": SESSIONS.listing(self.session_token(), d["epoch"]), "events": d.get("events", [])[:20],
                "fails": d.get("fails", [])[:20], "notice": d.get("notice") or {}, "failures": d.get("failures", 0),
                "locked": d.get("failures", 0) >= auth.LOCK_AT, "min_length": auth.PW_MIN}

    def code_ok(self, code, epoch):
        """"ok" for a right authenticator code or recovery code (each works once), "used" for a right code that was
        already used, "wrong", or "stale" when the account changed since the password was checked. Checked and used up under one lock, on a fresh read: two
        requests with the same code can't both get through (and checked again inside the file-locked save, for a second
        app process on the same data folder)."""
        code = code if isinstance(code, str) else ""
        with _try_lock:
            d = ACCOUNT.get()
            if not d or d["epoch"] != epoch:
                return "stale"
            if not d["totp"].get("on"):
                return "wrong"
            if auth.looks_like_recovery(code):
                h = auth.rc_hash(code)
                if not any(hmac.compare_digest(h, x) for x in d.get("recovery", [])):
                    return "wrong"
                used = []   # still there inside the update (new codes made meanwhile end the old ones)
                ACCOUNT.update(lambda x: (used.append(1), x.update(recovery=[r for r in x["recovery"] if r != h]))
                               if h in x["recovery"] and x["epoch"] == epoch else None)
                return "ok" if used else "wrong"
            step = auth.totp_match(d["totp"]["secret"], code, d["totp"].get("last_step", 0))
            if step is None:
                return "used" if auth.totp_used(d["totp"]["secret"], code, d["totp"].get("last_step", 0)) else "wrong"
            used = []   # checked again inside the file-locked update: another app process on this data folder may have used it
            ACCOUNT.update(lambda x: (used.append(1), x["totp"].update(last_step=step))
                           if step > x["totp"].get("last_step", 0) and x["epoch"] == epoch else None)
            return "ok" if used else "used"

    def auth_post(self, path, body):
        refusal = self.transport_refusal(path, True, "post")
        if refusal:
            return self._reply(*refusal)
        try:
            return self._auth_post(path, body)
        except auth.Broken as e:   # e.g. the account was reset on the host in the middle of this request
            return self._reply(503, {"error": f"Signing in is off: {e}. Reload the page.", "restart": True})

    def _auth_post(self, path, body):
        self.pending()          # (collects half-finished sign-ins that ran out...)
        self.tell_ran_out()     # (...and tells the owner about them)
        d_in = body if isinstance(body, dict) else {}
        ip, ua = self.client_ip(), self.headers.get("User-Agent", "")

        def s(k):   # a text field, or "" (wrong types, too long, unpaired surrogates)
            v = d_in.get(k)
            return v if auth.is_text(v, 2048) else ""
        keep = d_in.get("keep") is True

        if path == "/api/logout":
            ended = [t for t in self.cookie_values(CFG.cookie) if SESSIONS.end(t)]   # (from any address: it's this browser's)
            if ended:
                self.log(f"sign-in: signed out from {ip}")
            with _pending_lock:          # a half-finished sign-in in this browser ends too ("Start over")
                p = self.pending(consume=True)
                if p:
                    ended_unfinished([p], "the sign-in was started over")
            self.tell_ran_out()
            # (not Clear-Site-Data "cookies": that wipes every cookie of the whole site, your SSO's included)
            return self._reply(200, {"ok": True}, extra={"Clear-Site-Data": '"cache"'},
                             cookies=(self.make_cookie(CFG.cookie, "", clear=True), self.make_cookie(CFG.cookie + "-pre", "", clear=True)))
        try:
            acct = ACCOUNT.get()
        except auth.Broken as e:
            return self._reply(503, {"error": f"Signing in is off: {e}. On the host: " + CFG.reset_hint})

        if path == "/api/setup-account":
            if acct is not None:
                return self._reply(409, {"error": "The account already exists. Sign in instead.", "restart": True})
            if not s("code").strip():
                return self._reply(400, {"error": "Type the setup code.", "field": "code"})
            wait = self.begin_try(ip, account=False)
            if wait:
                return self.refuse_wait(wait)
            wrong_code = {"error": "That's not the setup code. " + CFG.setup_code_hint, "field": "code"}
            if not auth.setup_code_matches(s("code")):
                self.log(f"sign-in: wrong setup code from {ip}")
                return self._reply(403, wrong_code)
            THROTTLE.ip_ok(ip)   # the right code: retrying a too-weak password doesn't count as guessing
            bad_name = auth.name_problem(s("user"))
            problem = bad_name or auth.password_problem(s("password"), s("user").strip())
            if problem:
                return self._reply(400, {"error": problem, "field": "user" if bad_name else "password"})
            d = {"v": 1, "user": s("user").strip(), "hash": auth.hash_password(s("password")), "totp": {}, "recovery": [],
                 "failures": 0, "last_fail": 0, "devices": {}, "events": [], "fails": [], "epoch": auth.new_epoch(),
                 "created": int(time.time())}   # (hashed before taking the locks: nothing else waits for scrypt)
            ACCOUNT.event(d, "account created", ip, ua)
            with ACCOUNT.lock, auth.file_lock():   # one account, even when raced (and never over a reset on the host)
                if ACCOUNT.exists():
                    return self._reply(409, {"error": "The account already exists. Sign in instead.", "restart": True})
                if not auth.setup_code_matches(s("code")):   # used (or replaced on the host) meanwhile
                    return self._reply(403, wrong_code)
                ACCOUNT.save(d)
                auth.clear_setup_code()
            self.log(f"sign-in: account created from {ip}")
            return self.signed_in_now(ip, keep, "signed in (new account)", None, d["epoch"])

        if acct is None:
            return self._reply(409, {"error": "There's no account yet: create it first.", "setup": True, "restart": True})
        dev = self.device(acct)

        if path == "/api/login":
            if not s("user").strip() or not s("password"):
                return self._reply(400, {"error": "Type your name and password.", "field": "user" if not s("user").strip() else "password"})
            wait = self.begin_try(ip, dev)
            if wait:
                return self.refuse_wait(wait, new_browser=not dev)
            acct = ACCOUNT.get()   # fresh: the account as it is now that this try is counted
            if acct is None:
                return self._reply(409, {"error": "There's no account yet: create it first.", "setup": True, "restart": True})
            name_ok = hmac.compare_digest(auth.norm(s("user").strip()).casefold().encode(), auth.norm(acct["user"]).casefold().encode())
            pw_ok, rehash = auth.verify_password(s("password"), acct["hash"])   # always runs: a wrong name takes as long
            if not (name_ok and pw_ok):
                self.note_failure(ip, "wrong name or password", "password", dev)
                return self._reply(401, {"error": "Wrong name or password.", "field": "password"})
            if rehash:   # stronger settings since it was saved; only if the password didn't change meanwhile
                new_hash = auth.hash_password(s("password"))
                ACCOUNT.update(lambda x: x.update(hash=new_hash) if x["hash"] == acct["hash"] else None)
            if acct["totp"].get("on"):
                pre = secrets.token_urlsafe(32)
                with _pending_lock:
                    if len(_pending) > 200:
                        ended_unfinished(_pending.values(), "too many sign-ins at once")
                        _pending.clear()
                    _pending[hashlib.sha256(pre.encode()).hexdigest()] = {"t": time.time(), "keep": keep, "tries": 0, "dev": dev,
                                                                          "epoch": acct["epoch"], "tls": self.https(), "from": ip}
                return self._reply(200, {"code_due": True}, cookies=(self.make_cookie(CFG.cookie + "-pre", pre, PENDING_FOR),))
            return self.signed_in_now(ip, keep, "signed in", dev, acct["epoch"])

        if path == "/api/login/code":
            p = self.pending()
            if not p:
                return self._reply(401, {"error": f"That step expired (it lasts 5 minutes, and ends when {CFG.service_noun} restarts): "
                                                "sign in again.", "restart": True})
            if not s("code").strip():
                return self._reply(400, {"error": "Type a code from your authenticator app, or a recovery code.", "field": "code"})
            with _pending_lock:   # the step's own 5 codes, reserved before checking: parallel tries can't all slip in
                if p["tries"] >= 5:
                    self.pending(consume=True)
                    ended_unfinished([p], "its tries were used up")
                    return self._reply(401, {"error": "Wrong code 5 times: sign in with your password again.", "restart": True,
                                           "field": "code"})
                p["tries"] += 1
            wait = self.begin_try(ip, p.get("dev"), waits=False)
            if wait:
                with _pending_lock:
                    p["tries"] -= 1
                return self.refuse_wait(wait)
            result = self.code_ok(s("code"), p["epoch"])
            if result == "used":   # (refused, but no guess: nothing for the alarm; it still uses up a try of this step,
                return self._reply(401, {"error": CODE_USED, "field": "code"})   # or a seen code could be replayed endlessly)
            if result != "ok":
                with _pending_lock:
                    p["wrong"] = p.get("wrong", 0) + (result == "wrong")   # (tries counts the right one too)
                    over = result == "stale" or p["tries"] >= 5
                    if over:
                        self.pending(consume=True)
                        if result == "stale":   # (the owner signed everyone out, or changed the password, meanwhile)
                            ended_unfinished([p], "the account changed meanwhile")
                if result == "stale":
                    return self._reply(401, {"error": "The password or two-step sign-in just changed: sign in again.", "restart": True})
                self.note_failure(ip, "right password, wrong code", "code", p.get("dev"))
                return self._reply(401, {"error": "Wrong code 5 times: sign in with your password again." if over else
                                                "Wrong code. Use the newest 6-digit code from your app, or a recovery code.",
                                       "restart": over, "field": "code"})
            p = self.pending(consume=True) or p
            used = "recovery code" if auth.looks_like_recovery(s("code")) else "authenticator code"
            return self.signed_in_now(ip, p["keep"], f"signed in (password + {used})", p.get("dev"), p["epoch"],
                                      (self.make_cookie(CFG.cookie + "-pre", "", clear=True),), wrong_codes=p.get("wrong", 0))

        # ---- everything below changes the account: a session is needed (the gate checked it) ----
        tok = self.session_token()
        if not tok:
            return self._reply(401, {"error": "Sign in first.", "signin": True})
        tok_key = hashlib.sha256(tok.encode()).hexdigest()

        if path == "/api/account/totp/confirm":
            if acct["totp"].get("on"):
                return self._reply(409, {"error": "The authenticator app is already on."})
            if not s("code").strip():
                return self._reply(400, {"error": "Type the 6-digit code your app shows.", "field": "code"})
            wait = self.begin_try(ip, session=tok_key)
            if wait:
                return self.refuse_wait(wait)
            with _try_lock:   # one confirm at a time: a double click can't show recovery codes that were then replaced
                with _pending_lock:
                    pend = _pending_totp.pop(tok_key, None)
                if not pend or time.time() - pend["t"] > 900:
                    return self._reply(409, {"error": "Start again: that setup took more than 15 minutes, or the server restarted.",
                                           "restart": True})
                step = auth.totp_match(pend["secret"], s("code"), 0)
                if step is None:
                    with _pending_lock:
                        _pending_totp[tok_key] = pend   # another try with the same QR code
            if step is None:
                self.note_failure(ip, "wrong code while setting up the authenticator")
                if self.session_spent(tok_key):
                    return self.refuse_wait(-2, counted=True)
                return self._reply(400, {"error": "That code doesn't match. Check the app's clock, and type the newest code.", "field": "code"})
            self.try_ok(ip, session=tok_key)
            codes, hashes = auth.new_recovery_codes()
            cookies = self.revoke_everything(ip, "authenticator app turned on",
                                             lambda x: x.update(totp={"secret": pend["secret"], "on": True, "last_step": step}, recovery=hashes),
                                             pend["epoch"])
            if not cookies:
                return self._reply(409, TOO_LATE)
            return self._reply(200, {"ok": True, "recovery": codes}, cookies=cookies)

        if path not in ("/api/account/password", "/api/account/totp/start", "/api/account/totp/off", "/api/account/recovery",
                        "/api/account/sessions/end", "/api/account/notice/dismiss"):
            return self._reply(404, {"error": "not found"})
        needs_code = acct["totp"].get("on") and path != "/api/account/totp/start"   # (a stolen session + password isn't enough)
        # cheap checks first: nothing is counted (or a code used up) for a request that can't succeed anyway
        if path == "/api/account/totp/start" and acct["totp"].get("on"):
            return self._reply(409, {"error": "The authenticator app is already on."})
        if path in ("/api/account/totp/off", "/api/account/recovery") and not acct["totp"].get("on"):
            return self._reply(409, {"error": "The authenticator app is already off." if path.endswith("off")
                                            else "Recovery codes come with the authenticator app: turn it on first."})
        if path == "/api/account/password":
            problem = auth.password_problem(s("new"), acct["user"])
            if problem:
                return self._reply(400, {"error": problem, "field": "new"})
            if hmac.compare_digest(auth.norm(s("new")).encode(), auth.norm(s("password")).encode()):
                return self._reply(400, {"error": "That's the same password.", "field": "new"})
        if not s("password"):
            return self._reply(400, {"error": "Type your current password.", "field": "password"})
        if needs_code and not s("code").strip():
            return self._reply(400, {"error": "Type a code from your authenticator app, or a recovery code.", "field": "code"})
        # the current password again (and the code, when the authenticator is on): counted for this session
        wait = self.begin_try(ip, session=tok_key)
        if wait:
            return self.refuse_wait(wait)
        acct = ACCOUNT.get()
        if acct is None:
            return self._reply(409, {"error": "There's no account any more: reload the page.", "restart": True})
        if not auth.verify_password(s("password"), acct["hash"])[0]:
            self.note_failure(ip, "wrong password (account change)", "settings")
            if self.session_spent(tok_key):
                return self.refuse_wait(-2, counted=True)
            return self._reply(403, {"error": "That's not the current password.", "field": "password"})
        needs_code = acct["totp"].get("on") and path != "/api/account/totp/start"   # (as the account is now)
        if needs_code:
            result = self.code_ok(s("code"), acct["epoch"])
            if result == "stale":
                return self._reply(409, TOO_LATE)
            if result == "used":   # (a try, as it cost a password hash; not a wrong code: nothing for the alarm)
                return self._reply(403, {"error": CODE_USED, "field": "code"})
            if result != "ok":
                self.note_failure(ip, "wrong code (account change)", "settings")
                if self.session_spent(tok_key):
                    return self.refuse_wait(-2, counted=True)
                return self._reply(403, {"error": "Wrong code. Use the newest 6-digit code from your app, or a recovery code.", "field": "code"})
        self.try_ok(ip, session=tok_key)

        # (the password again for these too, as ASVS asks: a session alone, say at a wall screen, can't end the
        # owner's other sessions or silence the "someone may know your password" warning)
        if path == "/api/account/sessions/end":
            if d_in.get("all") is True:   # every other browser's session and half-finished sign-in. Trusted devices
                if not SESSIONS.end_all(but_token=tok):   # stay: forgetting them is part of a password change. Half-finished
                    return self._reply(409, TOO_LATE)       # sign-ins stay too: they aren't sessions, and the owner's own
                ACCOUNT.update(lambda x: ACCOUNT.event(x, "signed out everywhere else", ip, ua))
                return self._reply(200, {"ok": True})
            ended = SESSIONS.end_id(s("id"), tok)
            if ended is None:
                return self._reply(409, TOO_LATE)
            if not ended:
                return self._reply(404, {"error": "That browser isn't signed in any more."})
            return self._reply(200, {"ok": True})

        if path == "/api/account/notice/dismiss":   # "That was me": the owner says those wrong codes were theirs
            seen = d_in.get("seen") if isinstance(d_in.get("seen"), int) else None   # what the page showed: newer ones stay

            def dismiss(x):
                left = 0 if seen is None else x.get("notice", {}).get("code", 0) - max(0, seen)
                x["notice"] = {**x["notice"], "code": left} if left > 0 else {}
                ACCOUNT.event(x, "warning dismissed (wrong codes were mine)", ip, ua)
            ACCOUNT.update(dismiss)
            return self._reply(200, {"ok": True})

        if path == "/api/account/password":
            h, now = auth.hash_password(s("new")), int(time.time())
            cookies = self.revoke_everything(ip, "password changed", lambda x: (
                x.update(hash=h, changed=now), x.get("notice", {}).pop("code", None), x.get("since", {}).pop("code", None)), acct["epoch"])
            return self._reply(200, {"ok": True}, cookies=cookies) if cookies else self._reply(409, TOO_LATE)

        if path == "/api/account/totp/start":
            secret = auth.new_totp_secret()
            with _pending_lock:
                if len(_pending_totp) > 50:
                    _pending_totp.clear()
                _pending_totp[tok_key] = {"t": time.time(), "secret": secret, "epoch": acct["epoch"]}
            uri = auth.otpauth_uri(secret, acct["user"])
            return self._reply(200, {"secret": secret, "uri": uri, "qr": auth.qr_svg(uri)})

        if path == "/api/account/totp/off":
            cookies = self.revoke_everything(ip, "authenticator app turned off", lambda x: x.update(totp={}, recovery=[]), acct["epoch"])
            return self._reply(200, {"ok": True}, cookies=cookies) if cookies else self._reply(409, TOO_LATE)

        if path == "/api/account/recovery":
            codes, hashes, done = *auth.new_recovery_codes(), []
            ACCOUNT.update(lambda x: (x.update(recovery=hashes), ACCOUNT.event(x, "new recovery codes", ip, ua), done.append(1))
                           if x["epoch"] == acct["epoch"] and SESSIONS.on_disk(tok, acct["epoch"]) else None)
            return self._reply(200, {"ok": True, "recovery": codes}) if done else self._reply(409, TOO_LATE)
