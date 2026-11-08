"""Sign-in for the web app: the shared signin-core package (app/signin_core/, pinned by app/signin_core.pin; contract in
signin-core's SPEC.md) wired to Podburrow, plus Podburrow's own proxy rules, connection guard and request parsing.
The vendored copy is checked against its pin before it is imported: a changed or half-synced copy stops the app."""
import hashlib, hmac, http.client, http.server, ipaddress, json, os, re, secrets, socket, sys, threading, time, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from signin_core import verify as _verify   # noqa: E402  (stdlib only; imports nothing else from the package)

_ok, _problems = _verify.check(HERE)
if not _ok:
    raise SystemExit("signin_core does not match signin_core.pin: " + "; ".join(_problems))
from signin_core import web, auth   # noqa: E402

_auth_env = os.environ.get("AUTH", "login").strip().lower() or "login"
TRUSTED_PROXY = os.environ.get("TRUSTED_PROXY", "").strip()
ALLOWED_ORIGINS = {o.rstrip("/") for o in os.environ.get("ORIGIN", "").split() if o}
LISTEN = os.environ.get("LISTEN", "").strip()
AUTH = "proxy" if _auth_env == "proxy" and TRUSTED_PROXY else "login"       # anything else means the built-in sign-in: never open
if _auth_env not in ("login", "proxy"):
    print(f"WARNING: AUTH={_auth_env[:20]!r} isn't login or proxy: using login", flush=True)
if _auth_env == "proxy" and not TRUSTED_PROXY:
    print("WARNING: AUTH=proxy needs TRUSTED_PROXY (else anyone could skip the proxy's sign-in): using login", flush=True)
DEMO = False


class Invalid(ValueError):
    """A request body that isn't usable JSON."""


PUBLIC_GET = {"/login", "/js/login.js", "/login.css", "/api/auth/state", "/favicon.ico", "/icon.svg", "/apple-touch-icon.png"}
PUBLIC_POST = {"/api/login", "/api/login/code", "/api/setup-account", "/api/logout"}
PAGES = {"/"}
CLI = "docker exec -it <container> python /app/auth.py"
CONFIG = web.Config(
    auth=AUTH, app="Podburrow", cookie="podburrow", error_key="error", settings_label="Settings",
    service_noun="the app", open_noun="the app", signin_first="Sign in first.",
    banned_words=("podburrow", "homelab", "dashboard"), cli_hint=CLI, reset_keeps="settings and keys stay",
    setup_code_hint="Use the newest one in the container's log: docker logs <container> 2>&1 | grep '^SETUP CODE' | "
                    "tail -n 1 (or the one auth.py reset or setup-code printed).",
    setup_code_where="the newest in the container's log, or the one reset printed",
    run_as_hint="Run it as the container's user (docker exec without -u root): files made by root would lock the app out.",
    data_dir=os.environ.get("DATA", "/data"), public_get=PUBLIC_GET, public_post=PUBLIC_POST, pages=PAGES)
web.setup(CONFIG)                        # (no file is touched until used)
ACCOUNT, SESSIONS, THROTTLE = web.ACCOUNT, web.SESSIONS, web.THROTTLE


FORWARD_HEADERS = ("X-Forwarded-For", "X-Real-IP", "X-Forwarded-Proto", "Forwarded")   # a proxy in front adds these

OWN_NETWORKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                                   "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")]

_NEXT_RE = re.compile(r"/(?:settings)?(?:\?[A-Za-z0-9_=&-]{1,100})?")

PROXY_HEADERS = ("X-Real-IP", "X-Forwarded-Proto")

_proxy_ip = {"ips": set(), "at": float("-inf")}

_gw = {"t": float("-inf"), "ip": None}


def safe_next(n):
    """Where to go after signing in: one of our own pages, with a plain query (?wall, ?security=fw); else "/"."""
    return n if isinstance(n, str) and _NEXT_RE.fullmatch(n) else "/"


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


class SignIn(web.SignIn):
    """Mixin for the HTTP handler: signin-core's SignIn plus Podburrow's hooks."""

    def log(self, text):
        print(log_safe(text), flush=True)

    def refuse_page(self, p, q):
        nxt = safe_next(p + ("?" + q if q else ""))
        self.send(303, b"", "text/plain", extra={"Location": "/login?next=" + urllib.parse.quote(nxt, safe="/")})

    def public_extra(self, p):
        return False

    def transport_refusal(self, p, post, stage):
        """Passwords only over HTTPS (as the trusted proxy says) or from the owner's own network."""
        if stage == "post" and p in ("/api/login", "/api/login/code", "/api/setup-account") and not self.plain_http_ok():
            return 403, {"error": gap_hint(self.proxy_gaps()) or "Use the app's https address to sign in: "
                                  "over plain HTTP, passwords are only accepted from your own network."}
        return None

    def auth_state_extra(self):
        return {"http_ok": self.plain_http_ok(), "proxy_asked": _auth_env == "proxy", "gap_hint": gap_hint(self.proxy_gaps())}


    def login_page(self, query):
        nxt = safe_next((query.get("next") or ["/"])[0])   # only our own pages: never an open redirect
        if AUTH != "login" or self.session_token():
            return self.send(303, b"", "text/plain", extra={"Location": nxt})
        with open(os.path.join(HERE, "static", "login.html"), "rb") as f:
            self.send(200, f.read(), "text/html; charset=utf-8")


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
