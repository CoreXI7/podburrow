"""Sign-in for the web app: taken from Fishbowl's audited app.py (same author, MIT), code unchanged except names."""
import hashlib, hmac, http.client, http.server, ipaddress, json, os, re, secrets, socket, sys, threading, time, urllib.parse
import auth

HERE = os.path.dirname(os.path.abspath(__file__))
_auth_env = os.environ.get("AUTH", "login").strip().lower() or "login"
TRUSTED_PROXY = os.environ.get("TRUSTED_PROXY", "").strip()
ALLOWED_ORIGINS = {o.rstrip("/") for o in os.environ.get("ORIGIN", "").split() if o}
LISTEN = os.environ.get("LISTEN", "").strip()
AUTH = "proxy" if _auth_env == "proxy" and TRUSTED_PROXY else "login"       # anything else means the built-in sign-in: never open
if _auth_env not in ("login", "proxy"):
    print(f"WARNING: AUTH={_auth_env[:20]!r} isn't login or proxy: using login", flush=True)
if _auth_env == "proxy" and not TRUSTED_PROXY:
    print("WARNING: AUTH=proxy needs TRUSTED_PROXY (else anyone could skip the proxy's sign-in): using login", flush=True)
auth.configure(os.environ.get("DATA", "/data"))
ACCOUNT, SESSIONS, THROTTLE = auth.Account(), auth.Sessions(), auth.Throttle()
DEMO = False


class Invalid(ValueError):
    """A request body that isn't usable JSON."""


PUBLIC_GET = {"/login", "/js/login.js", "/login.css", "/api/auth/state", "/favicon.ico", "/icon.svg", "/apple-touch-icon.png"}
PUBLIC_POST = {"/api/login", "/api/login/code", "/api/setup-account", "/api/logout"}
PAGES = {"/"}

_pending = {}                 # sha256(pre-sign-in token) -> {"t", "keep", "tries", "wrong", "dev", "epoch", "tls", "from"}: the password was right, a code is due

_ran_out = []                 # half-finished sign-ins that ran out, until they're noted as failures (tell_ran_out)

_pending_totp = {}            # sha256(session token) -> {"t", "secret", "epoch"}: an authenticator being set up, not confirmed yet

_recent_fails = {}            # trusted-device hash -> [(time, "password" | "code", address)]: typos in that browser, forgiven at its next sign-in

_session_tries = {}           # sha256(session token) -> (wrong tries, last): re-confirming the password in Settings

SESSION_FAILS = 10            # wrong tries a signed-in browser gets before it's signed out

_pending_lock = threading.RLock()

_try_lock = threading.Lock()  # counting a try, and using up a code, happen one at a time

PENDING_FOR = 300             # seconds to type the code after the password

CODE_USED = "That code was just used. Wait for the next one in your app (a new one every 30 seconds)."

TOO_LATE = {"error": "The password or two-step sign-in changed meanwhile: reload the page (sign in again if asked) and "
                     "try again.", "restart": True}

FORWARD_HEADERS = ("X-Forwarded-For", "X-Real-IP", "X-Forwarded-Proto", "Forwarded")   # a proxy in front adds these

OWN_NETWORKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                                   "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")]

_NEXT_RE = re.compile(r"/(?:settings)?(?:\?[A-Za-z0-9_=&-]{1,100})?")

PROXY_HEADERS = ("X-Real-IP", "X-Forwarded-Proto")

_proxy_ip = {"ips": set(), "at": float("-inf")}

_gw = {"t": float("-inf"), "ip": None}

def ended_unfinished(steps, why):
    """Half-finished sign-ins ended without the right code ("Start over", tries used up, cleared): told to the owner
    like one that ran out, unless a wrong code in them already was. Call with _pending_lock held."""
    _ran_out.extend({**p, "ended": why} for p in steps if not p.get("wrong"))
    del _ran_out[:-200]

def safe_next(n):
    """Where to go after signing in: one of our own pages, with a plain query (?wall, ?security=fw); else "/"."""
    return n if isinstance(n, str) and _NEXT_RE.fullmatch(n) else "/"

def fmt_wait(sec):
    return f"{sec // 60} min {sec % 60} s" if sec >= 60 else f"{sec} s"

def gap_hint(gaps):
    """What the proxy setup is missing, in a sentence or two (the sign-in page shows it and its refusals start with
    it), or "". The one place this is worded."""
    if "untrusted" in gaps:
        return ("The app sits behind a proxy it wasn't told about, so it can't see where you connect from, and "
                "signing in is refused. Set TRUSTED_PROXY to the proxy's container name in docker-compose.yml.")
    what = {"X-Real-IP": "Your reverse proxy doesn't send X-Real-IP, so the app can't tell visitors apart: they "
                         "share one count of wrong tries, and signing in over plain HTTP is refused.",
            "X-Forwarded-Proto": "Your reverse proxy doesn't send X-Forwarded-Proto, so the app can't tell whether "
                                 "you use https, and signing in from outside your network is refused."}
    if "gateway" in gaps:
        return ("Every request reaches the app from Docker's gateway or its own address (Docker's userland proxy, "
                "rootless Docker or Podman), so it can't tell visitors apart, and signing in over plain HTTP is refused. Sign in through "
                "your reverse proxy's https address, or, without one, from another computer at the server's own LAN "
                "address (a browser on the server itself, or an SSH tunnel to it, arrives from the gateway too).")
    heads = [g for g in gaps if g in PROXY_HEADERS]
    if heads:
        return " ".join(what[g] for g in heads)
    return ""

def log_safe(text, limit=300):
    """Text for the container log: clipped, with control and other unprintable characters shown as \\xNN,
    so a request path or header can't put terminal escape sequences or fake lines into the log."""
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" if ord(c) < 256 else f"\\u{ord(c):04x}"
                   for c in str(text)[:limit])

def local_name(host):
    """A Host no website can own: an IP address, localhost, a name without dots, or a LAN-only suffix. Over plain HTTP
    with ORIGIN unset, only these may sign in or change anything: a website can point its own name at your app's
    address (DNS rebinding) and pass the Origin check with it."""
    h = (host or "").strip().lower()
    h = h[1:h.index("]")] if h.startswith("[") and "]" in h else h.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    return bool(h) and ("." not in h.rstrip(".") or h.rstrip(".").endswith((".lan", ".local", ".home.arpa", ".internal", ".localhost")))

def default_gateway():
    """The container's default gateway (from /proc/net/route, looked up once a minute), or None. Every request comes
    from it with Docker's userland proxy or rootless Docker/Podman: then visitors can't be told apart."""
    if time.monotonic() - _gw["t"] > 60:
        _gw["t"], _gw["ip"] = time.monotonic(), None
        try:
            with open("/proc/net/route") as f:
                for line in f.read(65536).splitlines()[1:]:
                    p = line.split()
                    if len(p) > 2 and p[1] == "00000000" and p[2] != "00000000":
                        _gw["ip"] = socket.inet_ntoa(int(p[2], 16).to_bytes(4, "little"))
                        break
        except (OSError, ValueError):
            pass
    return _gw["ip"]

def forwarded_alike(client, local):
    """Does a direct connection come from where every visitor would: the container's gateway (Docker's userland proxy,
    rootless Docker) or the container's own address (rootless Podman 4's port forwarder, slirp4netns, rewrites every
    visitor to it)? Loopback aside: that's the app itself or someone on the host inside the container."""
    client, local = (str(a).removeprefix("::ffff:") for a in (client, local))
    try:
        loopback = ipaddress.ip_address(client).is_loopback
    except ValueError:
        return False
    return client == default_gateway() or (client == local and not loopback)

def is_address(v):
    """A full IPv4/IPv6 address (not a prefix, not anything else)."""
    try:
        return isinstance(v, str) and bool(ipaddress.ip_address(v))
    except ValueError:
        return False

def count_networks(v4_routes, v6_routes):
    """The interfaces (loopback aside) in /proc/net/route (device first, after a header) and /proc/net/ipv6_route
    (device last); at least 1."""
    devs = {r.split()[0] for r in v4_routes.splitlines()[1:] if r.split()}
    devs |= {r.split()[-1] for r in v6_routes.splitlines() if r.split()}
    return max(1, len(devs - {"lo"}))

_nets = {"t": float("-inf"), "n": 1}


def network_count():
    """How many networks (interfaces with an IPv4 or IPv6 route, loopback aside) the container is on; looked up once a
    minute. IPv6 too: on an IPv6-only network a name's A lookup is empty and its AAAA answer comes from that network
    alone, so a container there with the proxy's name was the proxy."""
    if time.monotonic() - _nets["t"] > 60:
        texts = []
        for path in ("/proc/net/route", "/proc/net/ipv6_route"):
            try:
                with open(path) as f:
                    texts.append(f.read(65536))
            except OSError:
                texts.append("")
        _nets["t"], _nets["n"] = time.monotonic(), count_networks(*texts)
    return _nets["n"]

def listen_specific():
    """LISTEN names addresses (none of them a wildcard): the dash then answers only on those networks."""
    addrs = LISTEN.split()
    return bool(addrs) and not any(a in ("0.0.0.0", "::", "*") for a in addrs)

def proxy_ips():
    """Every address of the trusted reverse proxy: TRUSTED_PROXY may list several names or IPs (Docker's DNS answers
    a container's name with its address on one shared network only, so a proxy on two networks may need its second
    address listed). Looked up at most once a minute (addresses change when it's recreated). A name that answers with
    two addresses of one kind is shared by another container (a compose service named like the proxy gets that alias
    on the network): either could be the proxy, so neither counts. A lookup that fails for now keeps the last good
    answer; a name that no longer exists keeps nothing (Docker hands its old address to the next container)."""
    if time.monotonic() - _proxy_ip["at"] > 60:
        ips, shared, skipped, by = set(), {}, [], _proxy_ip.setdefault("by", {})
        # On more than one network Docker answers a name from one of them only: a container on another network holding
        # the proxy's name as an alias would be the only "proxy". Then (unless LISTEN keeps those networks out) only
        # addresses count.
        names_ok = network_count() <= 1 or listen_specific()
        for entry in TRUSTED_PROXY.split():
            if not names_ok and not is_address(entry):
                skipped.append(entry)
                continue
            try:
                by[entry] = {a[4][0] for a in socket.getaddrinfo(entry, None)}
            except socket.gaierror as e:
                if e.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)):
                    by.pop(entry, None)
            except (OSError, UnicodeError):   # (a label that's empty or too long isn't a name)
                pass
            found = by.get(entry, set())
            if sum(":" not in a for a in found) > 1 or sum(":" in a for a in found) > 1:
                shared[entry] = sorted(found)
                if _proxy_ip.get("shared", {}).get(entry) != shared[entry]:
                    print(log_safe(f"WARNING: TRUSTED_PROXY {entry!r} answers with {', '.join(shared[entry])}: more than "
                                   "one container has that name, so none of them is trusted (name the proxy by its IP)"), flush=True)
                continue
            ips |= found
        _proxy_ip.update(ips=ips, at=time.monotonic(), shared=shared, skipped=skipped)
    return _proxy_ip["ips"]

def is_proxy_address(ip):
    """Is ip one of the proxy's addresses? An IPv4 one arriving on an IPv6 socket (LISTEN "::") as ::ffff:a.b.c.d too."""
    ip = ip[7:] if isinstance(ip, str) and ip.lower().startswith("::ffff:") and "." in ip else ip
    return ip in proxy_ips()




def allowed_ip(ip, local):
    """With a proxy named, only the proxy may connect (and the container itself, for its health check)."""
    if not TRUSTED_PROXY or is_proxy_address(ip):
        return True
    return ip in ("127.0.0.1", "::1") or ip == local


def proxy_refusal_note():
    return ""


class _Budget:
    """A file wrapper that lets readline() read at most n bytes in all: http.client.LineTooLong once they're used up."""
    def __init__(self, f, n):
        self.f, self.n = f, n

    def readline(self, limit=-1):
        line = self.f.readline(self.n + 1 if limit < 0 else min(limit, self.n + 1))
        self.n -= len(line)
        if self.n < 0:
            raise http.client.LineTooLong("request headers")
        return line

    def __getattr__(self, name):
        return getattr(self.f, name)


class GuardedServer(http.server.ThreadingHTTPServer):
    """Refuses a client that isn't the proxy before a thread is started for it: otherwise any container on the
    proxy's network could hold the app's threads (pids_limit) with idle connections. Logged once a minute per IP.
    Also caps connections (in all, and per address other than the proxy's) and gives each one a deadline, so
    connections trickling a byte at a time can't use up the threads either."""
    daemon_threads = True
    request_queue_size = 64   # the default 5 drops connections when a page opens many at once
    MAX_CONN, MAX_PER_IP, READ_DEADLINE, DEADLINE = 32, 16, 20, 120   # (the compose file allows 64 processes and threads)
    _logged = {}
    # one table for the whole process (every LISTEN address): request -> [opened, address, still reading, read by, done by]
    _conn_lock, _conns, _reaping = threading.Lock(), {}, []

    def _note(self, ip, why):
        if len(self._logged) > 10000:   # (one entry per refused address: bounded)
            self._logged.clear()
        if time.monotonic() - self._logged.get(ip, float("-inf")) > 60:
            self._logged[ip] = time.monotonic()
            print(log_safe(f"blocked direct connection from {ip}" + why), flush=True)

    def verify_request(self, request, client_address):
        ip = client_address[0]
        if not allowed_ip(ip, request.getsockname()[0]):
            self._note(ip, proxy_refusal_note())
            return False
        if not GuardedServer._reaping:
            GuardedServer._reaping.append(True)
            threading.Thread(target=GuardedServer._reaper, daemon=True).start()
        key, now = auth.Throttle._key(ip), time.monotonic()   # (IPv6 per /64)
        with self._conn_lock:
            mine = [(v[0], r) for r, v in self._conns.items() if v[1] == key and v[2] != "cut"]
            if len(mine) >= self.MAX_PER_IP and not is_proxy_address(ip):
                # full for this address: cut its own oldest connection still sending its request, so one address
                # trickling requests (everyone behind a proxy nobody named in TRUSTED_PROXY, say) only crowds itself
                slow = [x for x in mine if self._conns[x[1]][2] is True]
                if not slow:
                    self._note(ip, f": too many connections ({len(mine)} from it)")
                    return False
                self._cut(min(slow, key=lambda x: x[0])[1])
            if len(self._conns) >= self.MAX_CONN:
                # full: cut the oldest connection still sending its request, so slow senders (through a proxy that
                # passes bodies on as they come, from many addresses) can't hold every place
                slow = [(v[0], r) for r, v in self._conns.items() if v[2] is True]
                if not slow:
                    self._note(ip, f": too many connections ({len(self._conns)} open)")
                    return False
                self._cut(min(slow, key=lambda x: x[0])[1])
            self._conns[request] = [now, key, True, now + self.READ_DEADLINE, now + self.DEADLINE]
        return True

    def _cut(self, request):
        """End a connection still sending its request (holding _conn_lock): its thread sees the socket close."""
        self._conns[request][2] = "cut"
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def read_done(self, request):
        with self._conn_lock:
            if request in self._conns and self._conns[request][2] is True:
                self._conns[request][2] = False

    def proxied(self, request, ip):
        """A connection from the proxy is for this browser address: count it there (False = that address has too many)."""
        key = "via " + auth.Throttle._key(ip)
        with self._conn_lock:
            if request not in self._conns:
                return True
            if sum(1 for r, v in self._conns.items() if v[1] == key and r is not request) >= self.MAX_PER_IP:
                return False
            self._conns[request][1] = key
        return True

    def handle_error(self, request, client_address):
        e = sys.exc_info()[1]
        if isinstance(e, (ConnectionError, TimeoutError)):
            return   # a browser that left (or a connection cut for taking too long): nothing worth a traceback
        if isinstance(e, RuntimeError) and "thread" in str(e):   # out of threads (the process limit): one line, not a traceback
            return self._note(client_address[0], ": no thread left to answer it")
        super().handle_error(request, client_address)

    def process_request(self, request, client_address):
        try:
            super().process_request(request, client_address)
        except Exception:   # no thread could be started: the connection is closed, so it no longer counts
            self._done(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._done(request)

    def _done(self, request):
        with self._conn_lock:
            self._conns.pop(request, None)

    @staticmethod
    def _reaper():
        """Every second: cut connections still sending their request after READ_DEADLINE, and any after DEADLINE
        (a read timeout alone restarts with every byte)."""
        while True:
            time.sleep(1)
            now = time.monotonic()
            with GuardedServer._conn_lock:
                old = [r for r, v in GuardedServer._conns.items() if now > v[4] or (v[2] is True and now > v[3])]
            for r in old:
                try:
                    r.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass



class SignIn:
    """Mixin for the HTTP handler."""
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
            for tok in self.cookie_values("podburrow-pre"):
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
                ACCOUNT.update(lambda x: x.update(failures=x.get("failures", 0) + 1, last_fail=int(now)))
            return 0

    def refuse_wait(self, wait, new_browser=False, counted=False):
        """new_browser: a sign-in from a browser that never signed in here (someone else's guessing can keep it waiting:
        the account-wide waits are what stop guessing from many addresses at once), so it's told the way around."""
        if wait == -2:
            SESSIONS.end(self._token or "")
            ip = self.client_ip()
            try:
                if not counted:   # (the wrong try that used up the last one was already noted)
                    ACCOUNT.update(lambda x: ACCOUNT.fail(x, f"signed out after {SESSION_FAILS} wrong tries in Settings", ip, "settings"))
            except auth.Broken:
                pass
            print(log_safe(f"sign-in: a browser at {ip} signed out after {SESSION_FAILS} wrong tries in Settings"), flush=True)
            return self.send(401, {"error": f"{SESSION_FAILS} wrong tries in this browser: it's signed out. Sign in again.",
                                   "signin": True}, cookies=(self.make_cookie("podburrow", "", clear=True),))
        if wait < 0:
            return self.send(423, {"error": f"Sign-ins from new browsers are locked after {auth.LOCK_AT} wrong tries in a row. "
                                            "A browser that signed in here before (and hasn't had 10 wrong tries of its own) can still sign in; "
                                            "or unlock it on the host: "
                                            "docker exec -it <container> python /app/auth.py unlock"})
        if new_browser:
            return self.send(429, {"error": f"Too many wrong tries (anyone's count). Wait {fmt_wait(wait)}, or sign in from a "
                                            "browser you've signed in with before: it isn't kept waiting.", "retry": wait,
                                   "hint": True}, extra={"Retry-After": str(wait)})
        return self.send(429, {"error": f"Too many tries. Wait {fmt_wait(wait)}, then try again.", "retry": wait},
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
        print(log_safe(f"sign-in: {what} from {ip}"), flush=True)

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
                       else x.update(failures=0, last_fail=0))   # (a device forgotten mid-try was counted on the account)

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
        print(log_safe(f"sign-in: {why} from {ip}: every other browser signed out"), flush=True)
        return (self.make_cookie("podburrow", token, max_age), self.make_cookie("podburrow-device", new["dev"], auth.DEVICE_FOR))

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
            return self.send(401, {"error": "The password or two-step sign-in just changed: sign in again.", "restart": True},
                             cookies=(self.make_cookie("podburrow-pre", "", clear=True),))
        self.try_ok(ip, dev)
        cookies = [self.make_cookie("podburrow", token, max_age), *extra_cookies]
        if out.get("dev"):
            cookies.append(self.make_cookie("podburrow-device", out["dev"], auth.DEVICE_FOR))
        print(log_safe(f"sign-in: {what} from {ip}"), flush=True)
        notice = dict(out["since"])
        if "recovery code" in what:
            notice["recovery_left"] = out["recovery_left"]
        self.send(200, {"ok": True, **({"notice": notice} if notice else {})}, cookies=cookies)

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
        app on the same data folder)."""
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
            used = []   # checked again inside the file-locked update: another app on this data folder may have used it
            ACCOUNT.update(lambda x: (used.append(1), x["totp"].update(last_step=step))
                           if step > x["totp"].get("last_step", 0) and x["epoch"] == epoch else None)
            return "ok" if used else "used"

    def auth_post(self, path):
        try:
            return self._auth_post(path)
        except auth.Broken as e:   # e.g. the account was reset on the host in the middle of this request
            return self.send(503, {"error": f"Signing in is off: {e}. Reload the page.", "restart": True})

    def _auth_post(self, path):
        self.pending()          # (collects half-finished sign-ins that ran out...)
        self.tell_ran_out()     # (...and tells the owner about them)
        d_in = self.json_body(8192)
        ip, ua = self.client_ip(), self.headers.get("User-Agent", "")

        def s(k):   # a text field, or "" (wrong types, too long, unpaired surrogates)
            v = d_in.get(k)
            return v if auth.is_text(v, 2048) else ""
        keep = d_in.get("keep") is True

        if path == "/api/logout":
            ended = [t for t in self.cookie_values("podburrow") if SESSIONS.end(t)]   # (from any address: it's this browser's)
            if ended:
                print(log_safe(f"sign-in: signed out from {ip}"), flush=True)
            with _pending_lock:          # a half-finished sign-in in this browser ends too ("Start over")
                p = self.pending(consume=True)
                if p:
                    ended_unfinished([p], "the sign-in was started over")
            self.tell_ran_out()
            # (not Clear-Site-Data "cookies": that wipes every cookie of the whole site, your SSO's included)
            return self.send(200, {"ok": True}, extra={"Clear-Site-Data": '"cache"'},
                             cookies=(self.make_cookie("podburrow", "", clear=True), self.make_cookie("podburrow-pre", "", clear=True)))
        try:
            acct = ACCOUNT.get()
        except auth.Broken as e:
            return self.send(503, {"error": f"Signing in is off: {e}. On the host: docker exec -it <container> "
                                            "python /app/auth.py reset (settings and keys stay)."})
        if path in ("/api/login", "/api/login/code", "/api/setup-account") and not self.plain_http_ok():
            return self.send(403, {"error": gap_hint(self.proxy_gaps()) or "Use the app's https address to sign in: "
                                            "over plain HTTP, passwords are only accepted from your own network."})

        if path == "/api/setup-account":
            if acct is not None:
                return self.send(409, {"error": "The account already exists. Sign in instead.", "restart": True})
            if not s("code").strip():
                return self.send(400, {"error": "Type the setup code.", "field": "code"})
            wait = self.begin_try(ip, account=False)
            if wait:
                return self.refuse_wait(wait)
            wrong_code = {"error": "That's not the setup code. Use the newest one in the container's log: "
                                   "docker logs <container> 2>&1 | grep '^SETUP CODE' | tail -n 1 (or the one auth.py "
                                   "reset or setup-code printed).", "field": "code"}
            if not auth.setup_code_matches(s("code")):
                print(log_safe(f"sign-in: wrong setup code from {ip}"), flush=True)
                return self.send(403, wrong_code)
            THROTTLE.ip_ok(ip)   # the right code: retrying a too-weak password doesn't count as guessing
            bad_name = auth.name_problem(s("user"))
            problem = bad_name or auth.password_problem(s("password"), s("user").strip())
            if problem:
                return self.send(400, {"error": problem, "field": "user" if bad_name else "password"})
            d = {"v": 1, "user": s("user").strip(), "hash": auth.hash_password(s("password")), "totp": {}, "recovery": [],
                 "failures": 0, "last_fail": 0, "devices": {}, "events": [], "fails": [], "epoch": auth.new_epoch(),
                 "created": int(time.time())}   # (hashed before taking the locks: nothing else waits for scrypt)
            ACCOUNT.event(d, "account created", ip, ua)
            with ACCOUNT.lock, auth.file_lock():   # one account, even when raced (and never over a reset on the host)
                if ACCOUNT.exists():
                    return self.send(409, {"error": "The account already exists. Sign in instead.", "restart": True})
                if not auth.setup_code_matches(s("code")):   # used (or replaced on the host) meanwhile
                    return self.send(403, wrong_code)
                ACCOUNT.save(d)
                auth.clear_setup_code()
            print(log_safe(f"sign-in: account created from {ip}"), flush=True)
            return self.signed_in_now(ip, keep, "signed in (new account)", None, d["epoch"])

        if acct is None:
            return self.send(409, {"error": "There's no account yet: create it first.", "setup": True, "restart": True})
        dev = self.device(acct)

        if path == "/api/login":
            if not s("user").strip() or not s("password"):
                return self.send(400, {"error": "Type your name and password.", "field": "user" if not s("user").strip() else "password"})
            wait = self.begin_try(ip, dev)
            if wait:
                return self.refuse_wait(wait, new_browser=not dev)
            acct = ACCOUNT.get()   # fresh: the account as it is now that this try is counted
            if acct is None:
                return self.send(409, {"error": "There's no account yet: create it first.", "setup": True, "restart": True})
            name_ok = hmac.compare_digest(auth.norm(s("user").strip()).casefold().encode(), auth.norm(acct["user"]).casefold().encode())
            pw_ok, rehash = auth.verify_password(s("password"), acct["hash"])   # always runs: a wrong name takes as long
            if not (name_ok and pw_ok):
                self.note_failure(ip, "wrong name or password", "password", dev)
                return self.send(401, {"error": "Wrong name or password.", "field": "password"})
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
                return self.send(200, {"code_due": True}, cookies=(self.make_cookie("podburrow-pre", pre, PENDING_FOR),))
            return self.signed_in_now(ip, keep, "signed in", dev, acct["epoch"])

        if path == "/api/login/code":
            p = self.pending()
            if not p:
                return self.send(401, {"error": "That step expired (it lasts 5 minutes, and ends when the app restarts): "
                                                "sign in again.", "restart": True})
            if not s("code").strip():
                return self.send(400, {"error": "Type a code from your authenticator app, or a recovery code.", "field": "code"})
            with _pending_lock:   # the step's own 5 codes, reserved before checking: parallel tries can't all slip in
                if p["tries"] >= 5:
                    self.pending(consume=True)
                    ended_unfinished([p], "its tries were used up")
                    return self.send(401, {"error": "Wrong code 5 times: sign in with your password again.", "restart": True,
                                           "field": "code"})
                p["tries"] += 1
            wait = self.begin_try(ip, p.get("dev"), waits=False)
            if wait:
                with _pending_lock:
                    p["tries"] -= 1
                return self.refuse_wait(wait)
            result = self.code_ok(s("code"), p["epoch"])
            if result == "used":   # (refused, but no guess: nothing for the alarm; it still uses up a try of this step,
                return self.send(401, {"error": CODE_USED, "field": "code"})   # or a seen code could be replayed endlessly)
            if result != "ok":
                with _pending_lock:
                    p["wrong"] = p.get("wrong", 0) + (result == "wrong")   # (tries counts the right one too)
                    over = result == "stale" or p["tries"] >= 5
                    if over:
                        self.pending(consume=True)
                        if result == "stale":   # (the owner signed everyone out, or changed the password, meanwhile)
                            ended_unfinished([p], "the account changed meanwhile")
                if result == "stale":
                    return self.send(401, {"error": "The password or two-step sign-in just changed: sign in again.", "restart": True})
                self.note_failure(ip, "right password, wrong code", "code", p.get("dev"))
                return self.send(401, {"error": "Wrong code 5 times: sign in with your password again." if over else
                                                "Wrong code. Use the newest 6-digit code from your app, or a recovery code.",
                                       "restart": over, "field": "code"})
            p = self.pending(consume=True) or p
            used = "recovery code" if auth.looks_like_recovery(s("code")) else "authenticator code"
            return self.signed_in_now(ip, p["keep"], f"signed in (password + {used})", p.get("dev"), p["epoch"],
                                      (self.make_cookie("podburrow-pre", "", clear=True),), wrong_codes=p.get("wrong", 0))

        # ---- everything below changes the account: a session is needed (the gate checked it) ----
        tok = self.session_token()
        if not tok:
            return self.send(401, {"error": "Sign in first.", "signin": True})
        tok_key = hashlib.sha256(tok.encode()).hexdigest()

        if path == "/api/account/totp/confirm":
            if acct["totp"].get("on"):
                return self.send(409, {"error": "The authenticator app is already on."})
            if not s("code").strip():
                return self.send(400, {"error": "Type the 6-digit code your app shows.", "field": "code"})
            wait = self.begin_try(ip, session=tok_key)
            if wait:
                return self.refuse_wait(wait)
            with _try_lock:   # one confirm at a time: a double click can't show recovery codes that were then replaced
                with _pending_lock:
                    pend = _pending_totp.pop(tok_key, None)
                if not pend or time.time() - pend["t"] > 900:
                    return self.send(409, {"error": "Start again: that setup took more than 15 minutes, or the server restarted.",
                                           "restart": True})
                step = auth.totp_match(pend["secret"], s("code"), 0)
                if step is None:
                    with _pending_lock:
                        _pending_totp[tok_key] = pend   # another try with the same QR code
            if step is None:
                self.note_failure(ip, "wrong code while setting up the authenticator")
                if self.session_spent(tok_key):
                    return self.refuse_wait(-2, counted=True)
                return self.send(400, {"error": "That code doesn't match. Check the app's clock, and type the newest code.", "field": "code"})
            self.try_ok(ip, session=tok_key)
            codes, hashes = auth.new_recovery_codes()
            cookies = self.revoke_everything(ip, "authenticator app turned on",
                                             lambda x: x.update(totp={"secret": pend["secret"], "on": True, "last_step": step}, recovery=hashes),
                                             pend["epoch"])
            if not cookies:
                return self.send(409, TOO_LATE)
            return self.send(200, {"ok": True, "recovery": codes}, cookies=cookies)

        if path not in ("/api/account/password", "/api/account/totp/start", "/api/account/totp/off", "/api/account/recovery",
                        "/api/account/sessions/end", "/api/account/notice/dismiss"):
            return self.send(404, {"error": "not found"})
        needs_code = acct["totp"].get("on") and path != "/api/account/totp/start"   # (a stolen session + password isn't enough)
        # cheap checks first: nothing is counted (or a code used up) for a request that can't succeed anyway
        if path == "/api/account/totp/start" and acct["totp"].get("on"):
            return self.send(409, {"error": "The authenticator app is already on."})
        if path in ("/api/account/totp/off", "/api/account/recovery") and not acct["totp"].get("on"):
            return self.send(409, {"error": "The authenticator app is already off." if path.endswith("off")
                                            else "Recovery codes come with the authenticator app: turn it on first."})
        if path == "/api/account/password":
            problem = auth.password_problem(s("new"), acct["user"])
            if problem:
                return self.send(400, {"error": problem, "field": "new"})
            if hmac.compare_digest(auth.norm(s("new")).encode(), auth.norm(s("password")).encode()):
                return self.send(400, {"error": "That's the same password.", "field": "new"})
        if not s("password"):
            return self.send(400, {"error": "Type your current password.", "field": "password"})
        if needs_code and not s("code").strip():
            return self.send(400, {"error": "Type a code from your authenticator app, or a recovery code.", "field": "code"})
        # the current password again (and the code, when the authenticator is on): counted for this session
        wait = self.begin_try(ip, session=tok_key)
        if wait:
            return self.refuse_wait(wait)
        acct = ACCOUNT.get()
        if acct is None:
            return self.send(409, {"error": "There's no account any more: reload the page.", "restart": True})
        if not auth.verify_password(s("password"), acct["hash"])[0]:
            self.note_failure(ip, "wrong password (account change)", "settings")
            if self.session_spent(tok_key):
                return self.refuse_wait(-2, counted=True)
            return self.send(403, {"error": "That's not the current password.", "field": "password"})
        needs_code = acct["totp"].get("on") and path != "/api/account/totp/start"   # (as the account is now)
        if needs_code:
            result = self.code_ok(s("code"), acct["epoch"])
            if result == "stale":
                return self.send(409, TOO_LATE)
            if result == "used":   # (a try, as it cost a password hash; not a wrong code: nothing for the alarm)
                return self.send(403, {"error": CODE_USED, "field": "code"})
            if result != "ok":
                self.note_failure(ip, "wrong code (account change)", "settings")
                if self.session_spent(tok_key):
                    return self.refuse_wait(-2, counted=True)
                return self.send(403, {"error": "Wrong code. Use the newest 6-digit code from your app, or a recovery code.", "field": "code"})
        self.try_ok(ip, session=tok_key)

        # (the password again for these too, as ASVS asks: a session alone, say at a wall screen, can't end the
        # owner's other sessions or silence the "someone may know your password" warning)
        if path == "/api/account/sessions/end":
            if d_in.get("all") is True:   # every other browser's session and half-finished sign-in. Trusted devices
                if not SESSIONS.end_all(but_token=tok):   # stay: forgetting them is part of a password change. Half-finished
                    return self.send(409, TOO_LATE)       # sign-ins stay too: they aren't sessions, and the owner's own
                ACCOUNT.update(lambda x: ACCOUNT.event(x, "signed out everywhere else", ip, ua))
                return self.send(200, {"ok": True})
            ended = SESSIONS.end_id(s("id"), tok)
            if ended is None:
                return self.send(409, TOO_LATE)
            if not ended:
                return self.send(404, {"error": "That browser isn't signed in any more."})
            return self.send(200, {"ok": True})

        if path == "/api/account/notice/dismiss":   # "That was me": the owner says those wrong codes were theirs
            seen = d_in.get("seen") if isinstance(d_in.get("seen"), int) else None   # what the page showed: newer ones stay

            def dismiss(x):
                left = 0 if seen is None else x.get("notice", {}).get("code", 0) - max(0, seen)
                x["notice"] = {**x["notice"], "code": left} if left > 0 else {}
                ACCOUNT.event(x, "warning dismissed (wrong codes were mine)", ip, ua)
            ACCOUNT.update(dismiss)
            return self.send(200, {"ok": True})

        if path == "/api/account/password":
            h, now = auth.hash_password(s("new")), int(time.time())
            cookies = self.revoke_everything(ip, "password changed", lambda x: (
                x.update(hash=h, changed=now), x.get("notice", {}).pop("code", None), x.get("since", {}).pop("code", None)), acct["epoch"])
            return self.send(200, {"ok": True}, cookies=cookies) if cookies else self.send(409, TOO_LATE)

        if path == "/api/account/totp/start":
            secret = auth.new_totp_secret()
            with _pending_lock:
                if len(_pending_totp) > 50:
                    _pending_totp.clear()
                _pending_totp[tok_key] = {"t": time.time(), "secret": secret, "epoch": acct["epoch"]}
            uri = auth.otpauth_uri(secret, acct["user"])
            return self.send(200, {"secret": secret, "uri": uri, "qr": auth.qr_svg(uri)})

        if path == "/api/account/totp/off":
            cookies = self.revoke_everything(ip, "authenticator app turned off", lambda x: x.update(totp={}, recovery=[]), acct["epoch"])
            return self.send(200, {"ok": True}, cookies=cookies) if cookies else self.send(409, TOO_LATE)

        if path == "/api/account/recovery":
            codes, hashes, done = *auth.new_recovery_codes(), []
            ACCOUNT.update(lambda x: (x.update(recovery=hashes), ACCOUNT.event(x, "new recovery codes", ip, ua), done.append(1))
                           if x["epoch"] == acct["epoch"] and SESSIONS.on_disk(tok, acct["epoch"]) else None)
            return self.send(200, {"ok": True, "recovery": codes}) if done else self.send(409, TOO_LATE)

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
            self._token = next((t for t in self.cookie_values("podburrow") if SESSIONS.check(t, d["epoch"], self.client_ip(), tls)), "") if ok else ""
            if self._token and self.session_spent(hashlib.sha256(self._token.encode()).hexdigest()):
                SESSIONS.end(self._token)   # its 10 wrong tries are used up, whichever reply used the last one
                self._token = ""
        return self._token or None

    def device(self, acct):
        """This browser's trusted-device token hash (it signed in here before), or None."""
        tls = self.https()
        return next((h for h in (auth.device_of(acct, t, tls) for t in self.cookie_values("podburrow-device")) if h), None) if acct else None

    def gate(self, p, post=False, q=""):
        """AUTH=login: everything except the sign-in page (and the open-source CSS/JS/fonts it uses) needs a session.
        Pages send you to sign in (and back to the same page afterwards); the API answers 401. Public paths are
        matched exactly."""
        if AUTH != "login" or p in (PUBLIC_POST if post else PUBLIC_GET):
            return True
        if not post and False:
            return True
        if self.session_token():
            return True
        if not post and p in PAGES:
            nxt = safe_next(p + ("?" + q if q else ""))
            self.send(303, b"", "text/plain", extra={"Location": "/login?next=" + urllib.parse.quote(nxt, safe="/")})
        else:
            self.send(401, {"error": "Sign in first.", "signin": True})
        return False

    def login_page(self, query):
        nxt = safe_next((query.get("next") or ["/"])[0])   # only our own pages: never an open redirect
        if AUTH != "login" or self.session_token():
            return self.send(303, b"", "text/plain", extra={"Location": nxt})
        with open(os.path.join(HERE, "static", "login.html"), "rb") as f:
            self.send(200, f.read(), "text/html; charset=utf-8")

    def auth_state(self):
        """What the sign-in page needs to know (nothing about the account itself)."""
        if AUTH != "login":
            return {"mode": AUTH}
        try:
            broken, setup = False, ACCOUNT.get() is None
        except auth.Broken:
            broken, setup = True, False
        return {"mode": "login", "setup": setup, "broken": broken, "signed_in": bool(self.session_token()),
                "code_due": bool(self.pending()), "https": self.https(), "http_ok": self.plain_http_ok(),
                "min_length": auth.PW_MIN, "proxy_asked": _auth_env == "proxy", "gap_hint": gap_hint(self.proxy_gaps())}

    def body(self, limit):
        cl = (self.headers.get("Content-Length") or "0").strip()
        if not re.fullmatch(r"[0-9]{1,9}", cl):
            raise Invalid("bad Content-Length")
        n = int(cl)
        if n > limit:
            raise Invalid(f"too large (max {limit // 1024} KB)")
        data = self.rfile.read(n)
        self.read_done()
        return data

    def plain_http_ok(self):
        """May a password come over this connection? Only on positive evidence: the trusted proxy says the browser used
        HTTPS, or the browser's address is known and on your own network (LAN, loopback, link-local). ORIGIN alone
        isn't enough: a browser on http:// would send the password before the Origin check refuses it."""
        if self.proxy_says_https():
            return True
        try:
            a = ipaddress.ip_address(self.real_ip() or "")
        except ValueError:
            return False
        a = getattr(a, "ipv4_mapped", None) or a
        if not self.via_proxy() and forwarded_alike(a, self.connection.getsockname()[0]):   # every visitor looks alike
            return False
        return any(a in n for n in OWN_NETWORKS)

    def proxy_says_https(self):
        return self.via_proxy() and (self.one_header("X-Forwarded-Proto") or "").lower() == "https"

    def proxy_gaps(self):
        """What keeps the app from seeing who's connecting, and how: headers the trusted proxy leaves out, a proxy
        it wasn't told about ("untrusted"), or every request coming from the container's gateway or own address ("gateway")."""
        gaps = []
        if self.via_proxy():
            gaps += ["X-Real-IP"] if not self.real_ip() else []
            gaps += ["X-Forwarded-Proto"] if (self.one_header("X-Forwarded-Proto") or "").lower() not in ("http", "https") else []
        elif AUTH == "login" and any(self.headers.get_all(h) for h in FORWARD_HEADERS):
            gaps.append("untrusted")
        elif AUTH == "login" and forwarded_alike(self.client_address[0], self.connection.getsockname()[0]):
            gaps.append("gateway")
        return gaps

    def via_proxy(self):
        return bool(TRUSTED_PROXY) and is_proxy_address(self.client_address[0])

    def one_header(self, name):
        """A header the proxy sets, or None when it's missing or repeated (a proxy that appends instead of replacing
        would let the client pick the first copy)."""
        vals = self.headers.get_all(name) or []
        return vals[0].strip() if len(vals) == 1 else None

    def real_ip(self):
        """The browser's own address when it's known: the proxy's X-Real-IP for requests through the proxy (anyone else
        could send that header themselves; X-Forwarded-For's first entry is the client's to choose), otherwise the
        connection's address. None when the proxy doesn't say (Caddy doesn't send X-Real-IP by default)."""
        if not self.via_proxy() and any(self.headers.get_all(h) for h in FORWARD_HEADERS):
            return None   # a proxy we weren't told about: the connection's address is the proxy's, not the browser's
        if self.via_proxy():
            try:
                a = ipaddress.ip_address(self.one_header("X-Real-IP") or "")
            except ValueError:
                return None
            if a.version == 6 and a.scope_id:   # "fe80::1%<any text>": not an address the owner should read
                return None
            return str(getattr(a, "ipv4_mapped", None) or a)
        return self.client_address[0]

    def client_ip(self):
        """The address sign-in limits count against (the proxy's own when it doesn't say who's behind it: one shared count)."""
        return self.real_ip() or self.client_address[0]

    def https(self):
        """Does the browser reach us over HTTPS? Through the proxy: its X-Forwarded-Proto says. Otherwise (or when the
        proxy doesn't say) ORIGIN decides: every change must come from that address (origin_problem), and a browser only
        sends an https Origin from a page it loaded over HTTPS. Decides the cookies' Secure flag and __Host- name."""
        if self.via_proxy():
            xfp = (self.one_header("X-Forwarded-Proto") or "").lower()
            if xfp in ("http", "https"):
                return xfp == "https"
        return bool(ALLOWED_ORIGINS) and all(o.startswith("https://") for o in ALLOWED_ORIGINS)

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

    def origin_problem(self):
        """Why this POST is refused ("" = fine). CSRF guard for every POST: the browser's Origin must be the app itself (ORIGIN / site.origin if set,
        otherwise the Host the request was sent to); the browser's own Sec-Fetch-Site, when it sends one, must say
        same-origin (a sibling subdomain is "same-site", not enough); and the body must be JSON (or an upload's raw
        bytes), which no HTML form on another site can send."""
        if DEMO:
            return ""
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        want = "application/octet-stream" if urllib.parse.urlsplit(self.path).path == "/api/upload" else "application/json"
        if ctype != want:
            return f"it wasn't sent as {want}"
        if (self.headers.get("Sec-Fetch-Site") or "same-origin").strip().lower() != "same-origin":
            return "your browser says it came from another site"
        origin = (self.headers.get("Origin") or "").rstrip("/")
        if ALLOWED_ORIGINS:
            return "" if origin in ALLOWED_ORIGINS else "it didn't come from the address set in ORIGIN"
        host = self.headers.get("Host", "")
        try:
            netloc = urllib.parse.urlsplit(origin).netloc
        except ValueError:   # "http://[" and the like
            netloc = None
        if not host or netloc != host:
            return "it didn't come from this app's own page"
        if AUTH == "login" and not self.https() and not local_name(host):
            return "over plain HTTP, only a LAN address (an IP, a name without dots, .lan, .local) is trusted without ORIGIN"
        return ""

    def json_body(self, limit):
        """Parse a JSON object safely: deeply nested input ([[[[...) would overflow the parser's C stack and kill
        the whole process, so nesting is checked with a cheap scan first."""
        try:
            raw = self.body(limit).decode("utf-8")   # (json.loads would also take UTF-16, past the scan below)
        except UnicodeDecodeError:
            raise Invalid("not UTF-8")
        depth = deepest = 0
        in_str = esc_next = False
        for ch in raw:
            if in_str:
                if esc_next:
                    esc_next = False
                elif ch == "\\":
                    esc_next = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch in "[{":
                depth += 1
                deepest = max(deepest, depth)
                if deepest > 32:
                    raise Invalid("JSON nested too deeply")
            elif ch in "]}":
                depth -= 1
        try:
            d = json.loads(raw or b"{}")
        except ValueError:
            raise Invalid("not valid JSON")
        if not isinstance(d, dict):
            raise Invalid("expected a JSON object")
        return d

    def parse_request(self):
        """The request line and headers, within 64 KB in all (http.server alone allows 100 lines of 64 KB each, so a few
        stalled connections could fill the memory)."""
        real = self.rfile
        self.rfile = _Budget(real, 64 * 1024)
        try:
            return super().parse_request()
        finally:
            self.rfile = real

    def read_done(self):
        """The request is read in full: from now on only the overall deadline applies (see Server)."""
        if hasattr(self.server, "read_done"):
            self.server.read_done(self.request)

    def send_error(self, code, message=None, explain=None):
        """http.server's own refusals (bad request line, headers too long, unknown method): as JSON, with the same
        headers as every other answer (CSP, nosniff, no framing), and the connection closed."""
        self.close_connection = True
        if not hasattr(self, "headers"):
            self.headers = http.client.HTTPMessage()   # (the request never got that far)
        if self.request_version == "HTTP/0.9":         # (an answer without a status line or headers helps nobody)
            self.request_version = "HTTP/1.0"
        try:
            self.send(code, {"error": str(message or code)[:200]})
        except OSError:
            pass
