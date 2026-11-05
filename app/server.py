#!/usr/bin/env python3
"""Podburrow: follows podcast feeds, downloads every episode and files it
the way Plex's music library wants it, so each show is ONE artist with one album per year:

    /media/<Show>/<YYYY>/<NNN> - <YYYY-MM-DD> - <Title>.mp3  (year folders: one 900-track album makes Plex lag)
    tags: artist = album artist = <Show>, album = "<Show> <YYYY>", track = episode number (oldest = 1), genre Podcast,
          date, title, cover. Compilation flag and sort tags removed (they split shows into "Various Artists").
    Dates/years are local time (TZ), so a New Year's Eve evening episode lands in the right year.

Plex is not called: its "scan automatically when files change" picks the files up (so no Plex token in here).
Stdlib + mutagen. One worker thread does feed checks and downloads, one at a time.

Security (reviewed by 4 agents, round 1 fixes in):
  - every outside fetch goes through fetch(): IPv4 public addresses only, checked after DNS and on every redirect, the
    socket connects to the checked address, TLS verified, overall deadline per fetch, size caps;
  - feeds: UTF-8/ASCII/Latin-1 only, DOCTYPE/ENTITY refused, parsed incrementally (memory stays small);
  - a show whose check crashed the process, or an episode whose download did, is paused/failed on the next start
    instead of crash-looping; downloads are size/time capped, written as .part, tag size checked, renamed into place;
  - file and folder names are cleaned and capped at 200 bytes; every path is kept inside MEDIA;
  - POSTs need X-Podburrow: 1 and a known Host; run it on a Docker network only your reverse proxy joins.
"""
import email.utils, fcntl, html, http.client, http.server, ipaddress, json, os, re, shutil, signal, socket, sqlite3
import ssl, subprocess, sys, threading, time, traceback, urllib.parse, xml.etree.ElementTree as ET, xml.parsers.expat
from datetime import datetime, timezone
import authweb

DATA = os.environ.get("DATA", "/data")
MEDIA = os.environ.get("MEDIA", "/media")
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
DB = os.path.join(DATA, "podcasts.db")
COVERS = os.path.join(DATA, "covers")
ALLOWED_HOSTS = set(os.environ.get("ALLOWED_HOSTS", "localhost:8000 127.0.0.1:8000").split())
PORT = int(os.environ.get("PORT", "8000"))
UA = "Mozilla/5.0 (compatible; Podburrow)"
FEED_MAX = 16 << 20          # big shows reach ~10 MB
AUDIO_MAX = 2 << 30          # 2 GB per episode
COVER_MAX = 8 << 20
EMBED_MAX = 512 << 10        # covers bigger than this aren't embedded in every file (Plex uses the folder's cover.jpg)
TAG_MAX = 16 << 20           # refuse files whose existing ID3 tag claims to be bigger than this
MIN_FREE = 20 << 30          # don't download below 20 GB free on the media drive
TRIES_MAX = 6                # backoff 15 min, 30 min, 1 h, ... capped at a day: a failed episode is retried daily forever
STALL = 600                  # a download that sends nothing for 10 min is dropped (and retried later)
AUDIO_HOURS = 6              # absolute cap per episode download
ITEM_ELEMENTS = 20000        # max XML elements inside one channel child / item (an element flood can't eat the memory)
NEW_PER_CHECK = 200          # after a show is added, at most this many new episodes per feed check (a GUID-churning feed
                             # can't flood the database)
NAME_BYTES = 200             # Linux allows 255 bytes per name; leaves room for ".part"
FEED_ITEMS = 5000            # keep only the newest 5000 items of a feed (big shows have ~900)
NET_FAILS_MAX = 3            # the 3rd network-type failure in a row counts as a real try (2 are free)
PORTS = {80, 443}            # outside fetches only to normal web ports
HOME_NAMES = os.environ.get("HOME_NAMES", "").split()   # never fetch our own public IP
BLOCKED_IPS = {"168.63.129.16"}   # Azure's host service: global on paper, a metadata endpoint in practice
SENTINEL = ".podcasts-media"   # must exist in MEDIA: missing = the drive isn't mounted (Docker made an empty folder)

DEFAULTS = {"check_minutes": 240, "new_show": "all"}           # new_show: "all" back catalog, or "new" (from now on)

lock = threading.RLock()     # one writer at a time; sqlite is opened per call
check_now = threading.Event()  # "check every feed now" (Check now, a new show)
queue_now = threading.Event()  # "look at the download queue now" (retry, resume, ...)
status = {"state": "idle", "detail": "", "progress": 0.0, "since": 0}


# ---------------------------------------------------------------- database
def db():
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c


def init_db():
    os.makedirs(COVERS, exist_ok=True)
    with lock, db() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS shows (
            id INTEGER PRIMARY KEY, title TEXT NOT NULL, folder TEXT NOT NULL UNIQUE, feed_url TEXT NOT NULL UNIQUE,
            author TEXT DEFAULT '', image_url TEXT DEFAULT '', paused INTEGER DEFAULT 0, added_at REAL NOT NULL,
            last_check REAL DEFAULT 0, last_error TEXT DEFAULT '', checking INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS episodes (
            id INTEGER PRIMARY KEY, show_id INTEGER NOT NULL REFERENCES shows(id) ON DELETE CASCADE, guid TEXT NOT NULL,
            title TEXT NOT NULL, pub TEXT NOT NULL, audio_url TEXT NOT NULL, summary TEXT DEFAULT '', num INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued', path TEXT DEFAULT '', size INTEGER DEFAULT 0, error TEXT DEFAULT '',
            tries INTEGER DEFAULT 0, next_try REAL DEFAULT 0, done_at REAL DEFAULT 0, UNIQUE(show_id, guid));
        CREATE INDEX IF NOT EXISTS ep_status ON episodes(status);
        CREATE INDEX IF NOT EXISTS ep_show_done ON episodes(show_id, done_at);
        """)
        for table, col, decl in (("shows", "checking", "INTEGER DEFAULT 0"), ("episodes", "next_try", "REAL DEFAULT 0"),
                                 ("episodes", "net_fails", "INTEGER DEFAULT 0")):
            if col not in {r[1] for r in c.execute(f"PRAGMA table_info({table})")}:   # older databases
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        for k, v in DEFAULTS.items():
            c.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (k, json.dumps(v)))


def setting(k):
    with db() as c:
        r = c.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    return json.loads(r["v"]) if r else DEFAULTS[k]


# ---------------------------------------------------------------- safe fetching (public internet only)
class Blocked(Exception):
    """A permanent problem with this link/file (counts as a failed try)."""


class Offline(Exception):
    """The network looks down (DNS/connect/timeout): wait and retry later, don't count it against the episode."""


_home = {"ips": set(), "at": 0.0}


def home_ips():
    """Our own public address(es): a feed must not loop back into the house through the router. A lookup failure is
    never cached: the old set is kept and retried in a minute; if it never worked, every fetch waits (Offline)."""
    if not HOME_NAMES:                                          # not set: this protection is off (the README explains it)
        return set()
    if time.time() - _home["at"] > 3600:
        ips, ok = set(), True
        for n in HOME_NAMES:
            try:
                ips |= {i[4][0] for i in socket.getaddrinfo(n, 443, socket.AF_INET)}
            except OSError:
                ok = False
        if ok and ips:
            _home.update(ips=ips, at=time.time())
        else:                                                   # keep what we knew, and try again in a minute
            _home["at"] = time.time() - 3600 + 60
    if not _home["ips"]:
        raise Offline("can't look up our own public address yet")
    return _home["ips"]


def public_addr(host, port):
    """Resolve host to a public IPv4 address, or refuse. (IPv6 is refused: the Docker network has none, and it keeps
    the check simple: no NAT64/IPv4-compatible tricks.)"""
    if port not in PORTS:
        raise Blocked(f"{host}: only ports 80 and 443 are allowed")
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as e:
        if e.errno in (socket.EAI_AGAIN,):
            raise Offline(f"DNS lookup failed for {host}") from e
        raise Blocked(f"{host}: address not allowed or not found") from e
    for _, _, _, _, sa in infos:
        ip = ipaddress.ip_address(sa[0])
        if not ip.is_global or ip.is_multicast or str(ip) in BLOCKED_IPS or str(ip) in home_ips():
            raise Blocked(f"{host}: address not allowed or not found")
    if not infos:
        raise Blocked(f"{host}: address not allowed or not found")
    return infos[0][4]


class _PinnedHTTP(http.client.HTTPConnection):
    guard = None                                                # set by Guard: its deadline can pass during connect

    def __init__(self, host, port, addr, timeout):
        super().__init__(host, port, timeout=timeout)
        self._addr = addr

    def _check_deadline(self):
        """The Guard can't reach a socket that's still connecting or in its TLS handshake, so check once it's up."""
        if self.guard and self.guard.expired:
            self.sock.close()
            raise TimeoutError("past the time limit")

    def connect(self):
        self.sock = socket.create_connection(self._addr, self.timeout)
        self._check_deadline()


class _PinnedHTTPS(_PinnedHTTP):
    _ctx = ssl.create_default_context()

    def connect(self):
        super().connect()
        self.sock = self._ctx.wrap_socket(self.sock, server_hostname=self.host)
        self._check_deadline()


class Guard:
    """Hard deadline for one connection: when it passes, the socket is shut down from a timer thread, so even a
    server that dribbles one byte at a time (which resets every socket timeout) or stalls the TLS handshake can't
    hold the worker or a request thread."""
    def __init__(self, conn, deadline):
        self.conn, self.timer, self.expired = conn, None, False
        conn.guard = self
        self.final = deadline                                   # the hard end; arm() may set earlier stall deadlines
        self.arm(deadline)

    def arm(self, deadline):
        self.cancel()
        self.deadline = deadline
        self.timer = threading.Timer(max(0.0, deadline - time.monotonic()), self._kill)
        self.timer.daemon = True
        self.timer.start()

    def _kill(self):
        self.expired = True
        try:
            if self.conn.sock:
                self.conn.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def cancel(self):
        if self.timer:
            self.timer.cancel()

    def why(self):
        if time.monotonic() >= self.final - 1:
            return Blocked("took too long (over the time limit)")
        return Offline(f"no data for {STALL // 60} minutes")      # stalled, not hopeless: retried later


class Response:
    """An open download (with its Guard)."""
    def __init__(self, r, conn, url, guard):
        self.r, self.conn, self.url, self.guard = r, conn, url, guard

    def header(self, k):
        return self.r.getheader(k)

    def set_deadline(self, deadline, final=None):
        if final is not None:
            self.guard.final = final
        self.guard.arm(min(deadline, self.guard.final))

    def read(self, n):
        try:
            b = self.r.read(n)
        except (OSError, http.client.HTTPException, ValueError) as e:
            if self.guard.expired:
                raise self.guard.why() from e
            if isinstance(e, (socket.timeout, TimeoutError)):
                raise Offline("the server stopped sending") from e
            raise Offline(f"connection broke: {type(e).__name__}") from e
        if self.guard.expired:                                  # the timer cut the connection: that's not a real end
            raise self.guard.why()
        return b

    def close(self):
        self.guard.cancel()
        self.r.close(); self.conn.close()


def fetch(url, timeout=30, total=120, accept="*/*"):
    """GET url, following up to 8 redirects; every hop must be http(s) to a public IPv4 address. Caller closes."""
    deadline = time.monotonic() + total
    for _ in range(9):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise Blocked("only http/https links are allowed")
        if u.username or u.password:
            raise Blocked("links with a login in them are not allowed")
        try:
            port = u.port or (443 if u.scheme == "https" else 80)
        except ValueError as e:
            raise Blocked("bad port in link") from e
        addr = public_addr(u.hostname, port)
        conn = (_PinnedHTTPS if u.scheme == "https" else _PinnedHTTP)(u.hostname, port, addr, timeout)
        path = urllib.parse.quote(u.path or "/", safe="/%:@!$&'()*+,;=~-._") + ("?" + urllib.parse.quote(u.query, safe="=&%+,;:@/?!$'()*~-._") if u.query else "")
        guard = Guard(conn, deadline)
        try:
            conn.request("GET", path, headers={"User-Agent": UA, "Accept": accept, "Accept-Encoding": "identity"})
            r = conn.getresponse()
        except ssl.SSLCertVerificationError as e:
            guard.cancel(); conn.close()
            raise Blocked(f"{u.hostname}: bad TLS certificate") from e
        except (OSError, http.client.HTTPException) as e:
            guard.cancel(); conn.close()
            if guard.expired:
                raise Blocked(f"{u.hostname}: took too long") from e
            raise Offline(f"{u.hostname}: {type(e).__name__}") from e
        except Exception:
            guard.cancel(); conn.close()
            raise
        if r.status in (301, 302, 303, 307, 308):
            loc = r.getheader("Location", "")
            guard.cancel(); r.close(); conn.close()
            if not loc:
                raise Blocked("redirect without a location")
            url = urllib.parse.urljoin(url, loc)
            continue
        if r.status != 200:
            guard.cancel(); r.close(); conn.close()
            if r.status in (429, 500, 502, 503, 504):
                raise Offline(f"HTTP {r.status}")
            raise Blocked(f"HTTP {r.status}")
        return Response(r, conn, url, guard)
    raise Blocked("too many redirects")


def read_capped(resp, cap):
    out, n = [], 0
    try:
        while True:
            b = resp.read(1 << 16)
            if not b:
                break
            n += len(b)
            if n > cap:
                raise Blocked(f"bigger than {cap >> 20} MB")
            out.append(b)
    finally:
        resp.close()
    return b"".join(out)


# ---------------------------------------------------------------- feeds
ITUNES = "{http://www.itunes.com/dtds/podcast-1.0.dtd}"
OK_ENCODINGS = {"utf-8", "utf8", "us-ascii", "ascii", "iso-8859-1", "latin-1", "latin1", "windows-1252", "cp1252"}


def clean_text(s, cap=2000):
    s = re.sub(r"<[^<>]*>", " ", (s or "")[:cap * 4])         # cut first + one-pass pattern: no slow regex on huge text
    s = html.unescape(s)
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
    return re.sub(r"\s+", " ", s).strip()[:cap]


def parse_date(s):
    s = (s or "")[:100].strip()
    try:
        d = email.utils.parsedate_to_datetime(s)
    except (TypeError, ValueError, IndexError):
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    try:
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        d = d.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        return None
    if not 1970 <= d.year <= 2100:
        return None
    return min(d, datetime.now(timezone.utc))                   # a future date can't jump the download queue


def local(pub_iso):
    """The episode's local date/time (container TZ): used for the year album and the date in names/tags."""
    return datetime.fromisoformat(pub_iso).astimezone()


def check_xml(data):
    """Encoding allowlist, then a fast C (expat) pass that refuses any DOCTYPE or ENTITY declaration and anything that
    isn't well-formed XML."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff") or data[:4] in (b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00"):
        raise Blocked("feed is UTF-16/32 (not supported)")
    m = re.match(rb'\s*(?:\xef\xbb\xbf)?\s*<\?xml[^>]{0,200}?encoding\s*=\s*["\']([A-Za-z0-9._-]{1,40})', data[:300])
    if m and m.group(1).decode().lower() not in OK_ENCODINGS:
        raise Blocked(f"feed encoding {m.group(1).decode()} not supported")

    def refuse(*_):
        raise Blocked("feed has DOCTYPE/ENTITY declarations (refused)")
    px = xml.parsers.expat.ParserCreate()
    px.StartDoctypeDeclHandler = refuse
    px.EntityDeclHandler = refuse
    try:
        px.Parse(data, True)
    except xml.parsers.expat.ExpatError as e:
        raise Blocked(f"feed isn't valid XML ({e})") from e


def parse_feed(data, base_url=""):
    """Incremental parse: each <item> is read and then dropped, so a big feed doesn't need a big tree in memory."""
    check_xml(data)
    show = {"title": "", "author": "", "image_url": ""}
    eps, depth, stack, inner, channels = [], 0, [], 0, 0
    p = ET.XMLPullParser(events=("start", "end"))
    for i in range(0, len(data), 1 << 16):
        p.feed(data[i:i + (1 << 16)])
        for ev, el in p.read_events():
            if ev == "start":
                depth += 1
                stack.append(el)
                if depth == 1 and el.tag != "rss":
                    raise Blocked("not an RSS podcast feed")
                if depth > 2:
                    inner += 1
                    if inner > ITEM_ELEMENTS:
                        raise Blocked("feed item is absurdly large")
                continue
            depth -= 1
            stack.pop()
            if depth == 1 and el.tag == "channel":
                channels += 1
                if channels > 1:
                    raise Blocked("feed has more than one channel")
            if depth == 1 and el.tag != "channel":               # junk directly under <rss>: drop it too
                el.clear()
                stack[-1].remove(el)
                continue
            if depth == 2:
                inner = 0
            if el.tag == "item" and depth == 2:
                try:
                    ep = item(el, base_url)
                except (ValueError, OverflowError):              # one broken episode, not a broken feed
                    ep = None
                if ep:
                    eps.append(ep)
                el.clear()
                stack[-1].remove(el)                                # the channel must not keep a million emptied items
            elif depth == 2:                                     # channel-level fields
                if el.tag == "title":
                    show["title"] = clean_text(el.text, 200)
                elif el.tag == ITUNES + "author" and not show["author"]:
                    show["author"] = clean_text(el.text, 200)
                elif el.tag == ITUNES + "image" and el.get("href"):
                    show["image_url"] = el.get("href")[:2000]
                elif el.tag == "image" and not show["image_url"]:
                    show["image_url"] = (el.findtext("url") or "").strip()[:2000]
                el.clear()
                stack[-1].remove(el)
    p.close()
    if not show["title"] and not eps:
        raise Blocked("not an RSS podcast feed")
    show["title"] = show["title"] or "Untitled podcast"
    if len(eps) > FEED_ITEMS:
        eps = sorted(eps, key=lambda e: e["pub"])[-FEED_ITEMS:]
    return show, eps


def parse_feed_safe(data, base_url=""):
    """parse_feed() in feedparse.py, a separate process with a hard memory cap: the server never parses untrusted XML."""
    try:
        p = subprocess.run([sys.executable, "-I", os.path.join(os.path.dirname(os.path.abspath(__file__)), "feedparse.py"),
                            urllib.parse.quote(base_url[:500], safe=":/?&=%#@+,;~!$'()*-._")], input=data,
                           capture_output=True, timeout=120)
    except subprocess.TimeoutExpired as e:
        raise Blocked("reading the feed took too long") from e
    if p.returncode != 0:
        msg = (p.stderr.decode(errors="replace").strip().splitlines() or ["the feed reader crashed"])[-1][:300]
        raise Blocked(msg if p.returncode in (2, 3) else f"the feed reader crashed ({p.returncode})")
    r = json.loads(p.stdout)
    return r["show"], r["eps"]


def item(it, base_url):
    enc = it.find("enclosure")
    url = (enc.get("url") or "").strip() if enc is not None else ""
    if not url:
        return None
    url = urllib.parse.urljoin(base_url, url)
    if urllib.parse.urlsplit(url).scheme.lower() not in ("http", "https"):
        return None
    d = parse_date(it.findtext("pubDate"))
    if d is None:
        return None
    guid = (it.findtext("guid") or "").strip() or urllib.parse.urlsplit(url)._replace(query="", fragment="").geturl()
    return {"guid": guid[:500], "title": clean_text(it.findtext("title"), 300) or "Untitled episode", "pub": d.isoformat(),
            "audio_url": url[:2000], "summary": clean_text(it.findtext(ITUNES + "summary") or it.findtext("description"))}


def safe_name(s, cap=NAME_BYTES):
    """File/folder name that works on Linux, Samba/Windows and Plex: no slashes, control chars or reserved names, and
    at most `cap` bytes of UTF-8."""
    s = re.sub(r'[\x00-\x1f\x7f/\\:*?"<>|\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]', "", s)   # bidi marks can disguise a name
    s = re.sub(r"\s+", " ", s).strip(" .")
    while len(s.encode()) > cap:
        s = s[:-1]
    s = s.strip(" .")
    if not s or s.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL"} | {f"{p}{i}" for p in ("COM", "LPT") for i in range(10)}:
        s = "_" + s
    return s


def add_show(feed_url, mode=None):
    resp = fetch(feed_url, accept="application/rss+xml, application/xml, text/xml, */*")
    final = resp.url
    show, eps = parse_feed_safe(read_capped(resp, FEED_MAX), final)
    mode = mode or setting("new_show")
    folder = safe_name(show["title"], 150)
    with lock, db() as c:
        # the same show under another link (http/https, a redirect) would download the whole back catalog again
        if c.execute("SELECT 1 FROM shows WHERE feed_url IN (?,?)", (feed_url, final)).fetchone():
            raise Blocked("already following that feed")
        if c.execute("SELECT 1 FROM shows WHERE title=? COLLATE NOCASE", (show["title"],)).fetchone():
            raise Blocked(f'already following a show called "{show["title"]}"')
        base, n = folder, 2
        while c.execute("SELECT 1 FROM shows WHERE folder=?", (folder,)).fetchone():
            folder, n = f"{base} ({n})", n + 1
        sid = c.execute("INSERT INTO shows (title, folder, feed_url, author, image_url, added_at, last_check) VALUES (?,?,?,?,?,?,?)",
                        (show["title"], folder, feed_url, show["author"], show["image_url"], time.time(), time.time())).lastrowid
        store_episodes(c, sid, eps, queue=(mode == "all"))
    save_cover(sid, show["image_url"])
    queue_now.set()
    return sid


def store_episodes(c, sid, eps, queue=True, limit=None):
    """Insert episodes not seen before, numbered after the newest known one (oldest first = number 1). An episode that
    comes back with a new GUID (feed moved hosts) is recognised by its date + title and not downloaded twice."""
    known = {r["guid"] for r in c.execute("SELECT guid FROM episodes WHERE show_id=?", (sid,))}
    same = {(local(r["pub"]).date().isoformat(), r["title"].lower()) for r in c.execute("SELECT pub, title FROM episodes WHERE show_id=?", (sid,))}
    new, seen = [], set()
    for e in sorted(eps, key=lambda e: e["pub"]):
        key = (local(e["pub"]).date().isoformat(), e["title"].lower())
        if e["guid"] in known or e["guid"] in seen or key in same:
            continue
        seen.add(e["guid"]); same.add(key); new.append(e)
    if limit is not None:
        new = new[:limit]                                       # oldest first, so the numbering keeps following the dates
    refresh_links(c, sid, eps)
    top = c.execute("SELECT COALESCE(MAX(num),0) FROM episodes WHERE show_id=?", (sid,)).fetchone()[0]
    for i, e in enumerate(new, 1):
        c.execute("INSERT OR IGNORE INTO episodes (show_id, guid, title, pub, audio_url, summary, num, status) VALUES (?,?,?,?,?,?,?,?)",
                  (sid, e["guid"], e["title"], e["pub"], e["audio_url"], e["summary"], top + i, "queued" if queue else "skipped"))
    return len(new)


def refresh_links(c, sid, eps):
    """Podcast hosts change download links over time (Podgrab never noticed, so old links 404'd). For episodes not
    downloaded yet: take the feed's current link (matched by ID, else by date + title); a failed one whose link changed
    is queued again right away. Episodes that left the feed are marked so they stop retrying (only when the feed wasn't
    cut to the newest FEED_ITEMS, so nothing is judged on a partial list)."""
    if not eps:                                                 # an empty feed proves nothing: often a host's hiccup
        return
    by_guid = {e["guid"]: e for e in eps}
    by_key = {(local(e["pub"]).date().isoformat(), e["title"].lower()): e for e in eps}
    for r in c.execute("SELECT id, guid, title, pub, audio_url, status FROM episodes WHERE show_id=? AND status!='downloaded'",
                       (sid,)).fetchall():
        e = by_guid.get(r["guid"]) or by_key.get((local(r["pub"]).date().isoformat(), r["title"].lower()))
        if e is None:
            if len(eps) < FEED_ITEMS and r["status"] in ("failed", "queued"):
                c.execute("UPDATE episodes SET status='skipped', error='no longer in the feed' WHERE id=?", (r["id"],))
            continue
        if e["audio_url"] != r["audio_url"]:
            c.execute("""UPDATE episodes SET audio_url=?, error='', tries=0, net_fails=0, next_try=0,
                         status=CASE WHEN status='failed' THEN 'queued' ELSE status END WHERE id=?""", (e["audio_url"], r["id"]))


def check_show(sid):
    with db() as c:
        s = c.execute("SELECT * FROM shows WHERE id=?", (sid,)).fetchone()
    if not s:
        return 0
    with lock, db() as c:                                     # if this check kills the process, the show gets paused at startup
        c.execute("UPDATE shows SET checking=1 WHERE id=?", (sid,))
    err = ""
    n = 0
    try:
        resp = fetch(s["feed_url"], accept="application/rss+xml, application/xml, text/xml, */*")
        final = resp.url
        show, eps = parse_feed_safe(read_capped(resp, FEED_MAX), final)
        with lock, db() as c:
            n = store_episodes(c, sid, eps, queue=True, limit=NEW_PER_CHECK)
            if show["image_url"]:
                c.execute("UPDATE shows SET image_url=? WHERE id=?", (show["image_url"], sid))
        if n >= NEW_PER_CHECK:
            err = f"over {NEW_PER_CHECK} new episodes in one check: the rest come with the next checks"
        if not cover_bytes(sid):
            save_cover(sid, show["image_url"] or s["image_url"])
    except (Blocked, Offline, ET.ParseError) as e:
        err = str(e)[:300]
    except Exception as e:
        traceback.print_exc()
        err = f"{type(e).__name__}"
    with lock, db() as c:
        c.execute("UPDATE shows SET checking=0, last_check=?, last_error=? WHERE id=?", (time.time(), err, sid))


def save_cover(sid, url):
    if not url:
        return
    try:
        b = read_capped(fetch(url, total=60, accept="image/*"), COVER_MAX)
        if not (b.startswith(b"\xff\xd8") or b.startswith(b"\x89PNG")):
            return
        tmp = os.path.join(COVERS, f".{sid}.tmp")
        with open(tmp, "wb") as f:
            f.write(b)
        os.replace(tmp, os.path.join(COVERS, f"{sid}.jpg"))
    except Exception:
        pass


def cover_bytes(sid):
    try:
        with open(os.path.join(COVERS, f"{int(sid)}.jpg"), "rb") as f:
            return f.read()
    except OSError:
        return b""


# ---------------------------------------------------------------- files + tags
def episode_path(show, ep, ext):
    d = local(ep["pub"])
    name = safe_name(f'{ep["num"]:03d} - {d.date().isoformat()} - {ep["title"]}', NAME_BYTES - 6)
    return os.path.join(show["folder"], str(d.year), f"{name}.{ext}")   # one folder (= one Plex album) per year


def sniff_ext(head, content_type, url):
    ct = (content_type or "").lower()
    if "text/html" in ct or head.lstrip()[:1] == b"<":
        return None                                             # an error page, not audio
    if head[:3] == b"ID3" or (len(head) > 1 and head[0] == 0xFF and head[1] & 0xE0 == 0xE0 and head[1] & 0x06):
        return "mp3"                                            # MPEG audio frame (layer bits set; ADTS AAC has them 0)
    if len(head) > 1 and head[0] == 0xFF and head[1] & 0xF6 == 0xF0:
        return "aac"
    if head[4:8] == b"ftyp":
        return "m4a"
    if head[:4] == b"OggS":
        return "opus" if b"OpusHead" in head[:80] else "ogg"
    path_ext = os.path.splitext(urllib.parse.urlsplit(url).path)[1].lower().lstrip(".")
    if "mpeg" in ct or path_ext == "mp3":
        return "mp3"
    if "mp4" in ct or "m4a" in ct or path_ext in ("m4a", "mp4"):
        return "m4a"
    return None


def id3_size(path):
    with open(path, "rb") as f:
        h = f.read(10)
    if len(h) < 10 or h[:3] != b"ID3":
        return 0
    return (h[6] << 21) | (h[7] << 14) | (h[8] << 7) | h[9]


def write_tags(path, ext, show, ep, cover_file):
    """Plex-friendly tags, written by tagger.py in its own memory-capped process (see there). Big covers aren't
    embedded (Plex uses the folder's cover.jpg)."""
    if ext == "mp3" and id3_size(path) > TAG_MAX:
        raise Blocked("the file's tag block is suspiciously big")
    d = local(ep["pub"])
    if cover_file and (not os.path.exists(cover_file) or os.path.getsize(cover_file) > EMBED_MAX):
        cover_file = ""
    job = {"path": path, "ext": ext, "show": show["title"], "title": ep["title"], "num": int(ep["num"]),
           "date": d.date().isoformat(), "summary": ep["summary"] or "", "cover": cover_file or ""}
    try:
        p = subprocess.run([sys.executable, "-I", os.path.join(os.path.dirname(os.path.abspath(__file__)), "tagger.py")],
                           input=json.dumps(job).encode(), capture_output=True, timeout=300)
    except subprocess.TimeoutExpired as e:
        raise Offline("tagging took too long (disk busy?)") from e
    if p.returncode == -signal.SIGXCPU:                         # its CPU limit: this file's tags are built to waste time
        raise Blocked("tagging used too much CPU")
    if p.returncode < 0:
        raise Offline(f"the tagger was killed (signal {-p.returncode})")
    if p.returncode != 0:
        raise Blocked("couldn't write tags: " + (p.stderr.decode(errors="replace").strip().splitlines() or ["?"])[-1][:200])


def cover_file(sid):
    f = os.path.join(COVERS, f"{int(sid)}.jpg")
    return f if os.path.exists(f) else ""


def create_new(path):
    """Open a fresh file for writing; never follows a symlink planted at that name."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644), "wb")


def place_covers(album_dir, cover):
    """cover.jpg (album art) in the year folder and artist.jpg in the show folder above it, for Plex."""
    if not cover:
        return
    for p in (os.path.join(album_dir, "cover.jpg"), os.path.join(os.path.dirname(album_dir), "artist.jpg")):
        if not os.path.lexists(p):
            tmp = p + ".part"
            with create_new(tmp) as f:
                f.write(cover)
            os.replace(tmp, p)


def under_media(rel):
    full = os.path.realpath(os.path.join(MEDIA, rel))
    if not full.startswith(os.path.realpath(MEDIA) + os.sep):
        raise Blocked("path escapes the media folder")
    return full


def download(ep_id):
    with db() as c:
        ep = c.execute("SELECT * FROM episodes WHERE id=?", (ep_id,)).fetchone()
        show = c.execute("SELECT * FROM shows WHERE id=?", (ep["show_id"],)).fetchone() if ep else None
    if not ep or not show:
        return
    set_status("downloading", f'{show["title"]}: {ep["title"]}')
    resp = fetch(ep["audio_url"], timeout=60, total=120, accept="audio/*, */*")   # connect + headers within 2 min
    tmp = None
    try:
        final = time.monotonic() + AUDIO_HOURS * 3600
        resp.set_deadline(time.monotonic() + STALL, final)       # as long as data keeps coming, it keeps going
        total = int(resp.header("Content-Length") or 0)
        if total > AUDIO_MAX:
            raise Blocked("episode is bigger than 2 GB")
        head = b""
        while len(head) < 4096:
            b = resp.read(4096 - len(head))
            if not b:
                break
            head += b
        ext = sniff_ext(head, resp.header("Content-Type"), resp.url)
        if ext is None:
            raise Blocked(f'not an audio file ({resp.header("Content-Type") or "unknown type"})')
        rel = episode_path(show, ep, ext)
        dest = under_media(rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        tmp = dest + ".part"
        n = len(head)
        with create_new(tmp) as f:
            f.write(head)
            while True:
                b = resp.read(1 << 20)
                if not b:
                    break
                n += len(b)
                if n > AUDIO_MAX:
                    raise Blocked("episode is bigger than 2 GB")
                f.write(b)
                resp.set_deadline(time.monotonic() + STALL)
                if n % (32 << 20) < len(b):                     # don't let dirty page cache fill the container (slow HDD)
                    f.flush(); os.fsync(f.fileno())
                    os.posix_fadvise(f.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
                if total:
                    status["progress"] = n / total
            f.flush(); os.fsync(f.fileno())
        if total and n < total:
            raise Offline(f"download cut short ({n >> 20} of {total >> 20} MB)")   # counts after NET_FAILS_MAX in a row
        if n < 100_000:
            raise Blocked("file is too small to be an episode")
        write_tags(tmp, ext, show, ep, cover_file(show["id"]))
        fd = os.open(tmp, os.O_RDONLY)
        try:
            os.fsync(fd); os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        finally:
            os.close(fd)
        os.replace(tmp, dest)
        tmp = None
        place_covers(os.path.dirname(dest), cover_bytes(show["id"]))
        with lock, db() as c:
            c.execute("UPDATE episodes SET status='downloaded', path=?, size=?, error='', net_fails=0, done_at=? WHERE id=?",
                      (rel, os.path.getsize(dest), time.time(), ep_id))
    finally:
        resp.close()
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


def file_gone(path):
    """Only 'no such file' means gone: a folder we can't read today says nothing about the file."""
    try:
        os.stat(path)
        return False
    except FileNotFoundError:
        return True
    except OSError:
        return False


def mark_missing():
    """Downloaded episodes whose file is gone (deleted in Plex or by hand) become 'missing': shown in the UI with a
    Download button, never fetched again on their own (Podgrab re-downloaded them; deleting should stick)."""
    if not media_ok():
        return
    with db() as c:
        rows = [(r["id"], r["path"]) for r in c.execute("SELECT id, path FROM episodes WHERE status='downloaded'")]
    gone = [i for i, p in rows if not p or file_gone(os.path.join(MEDIA, p))]
    if gone:
        with lock, db() as c:
            c.executemany("UPDATE episodes SET status='missing', error='file deleted from disk' WHERE id=?", [(i,) for i in gone])


def media_ok():
    return os.path.exists(os.path.join(MEDIA, SENTINEL))


# ---------------------------------------------------------------- worker
HOPELESS = ("bigger than 2 GB", "over the time limit", "too much CPU")      # only the real 6-hour cap, not slow tagging/headers


def backoff(tries, err=""):
    """15 min, 30 min, 1 h, 2 h ... at most a day (a week for errors that cost a lot and rarely change): a long outage
    or a host that's down for days never makes an episode give up for good."""
    if any(h in err for h in HOPELESS):
        return 7 * 86400
    return min(900 * 2 ** max(tries - 1, 0), 86400)


def set_status(state, detail=""):
    status.update(state=state, detail=detail, progress=0.0, since=time.time())


def worker():
    last_full = 0.0
    while True:
        offline = paused = False
        try:
            if time.time() - last_full >= setting("check_minutes") * 60 or check_now.is_set():
                check_now.clear()
                with db() as c:
                    todo = [(r["id"], r["title"]) for r in c.execute("SELECT id, title FROM shows WHERE paused=0 ORDER BY title")]
                for sid, title in todo:
                    set_status("checking", title)
                    check_show(sid)
                mark_missing()
                last_full = time.time()
            queue_now.clear()
            with lock, db() as c:                               # nothing is in flight here: no row can really be 'downloading'
                c.execute("UPDATE episodes SET status='queued' WHERE status='downloading'")
            net_hosts = []                                      # hosts of the last network failures in a row
            while not check_now.is_set() and time.time() - last_full < setting("check_minutes") * 60:
                if not media_ok():
                    set_status("paused", "the podcast drive isn't mounted"); paused = True
                    break
                if shutil.disk_usage(MEDIA).free < MIN_FREE:
                    set_status("paused", "less than 20 GB free on the podcast drive"); paused = True
                    break
                with db() as c:
                    # newest first, but taking turns between shows (the show that got a file longest ago goes first)
                    ep = c.execute("""SELECT e.id, e.show_id FROM episodes e JOIN shows s ON s.id=e.show_id
                                      LEFT JOIN (SELECT show_id, MAX(done_at) AS last FROM episodes GROUP BY show_id) d
                                             ON d.show_id=e.show_id
                                      WHERE s.paused=0 AND e.next_try<=? AND e.status IN ('queued','failed')
                                      ORDER BY e.status='failed', COALESCE(d.last,0), e.pub DESC LIMIT 1""",
                                   (time.time(),)).fetchone()
                if not ep:
                    break
                with lock, db() as c:                           # if this download kills the process, it counts as a try
                    c.execute("UPDATE episodes SET status='downloading', tries=tries+1 WHERE id=?", (ep["id"],))
                began = time.time()
                try:
                    download(ep["id"])
                    net_hosts = []
                except Offline as e:
                    with lock, db() as c:
                        row = c.execute("SELECT net_fails, audio_url FROM episodes WHERE id=?", (ep["id"],)).fetchone()
                        if row is None:                         # show unfollowed during the download
                            continue
                        # this show's host is in trouble: let the other shows go first for a while
                        c.execute("UPDATE episodes SET next_try=? WHERE show_id=? AND status='queued' AND next_try<=?",
                                  (time.time() + 1800, ep["show_id"], time.time()))
                        if row["net_fails"] + 1 < NET_FAILS_MAX:  # network trouble: not counted yet, try again in 30 min
                            c.execute("""UPDATE episodes SET status='queued', tries=MAX(tries-1,0), net_fails=net_fails+1,
                                         error=?, next_try=? WHERE id=?""", ("network: " + str(e)[:290], time.time() + 1800, ep["id"]))
                        else:                                     # keeps happening to this one: count it like any failure
                            t = c.execute("SELECT tries FROM episodes WHERE id=?", (ep["id"],)).fetchone()["tries"]
                            c.execute("UPDATE episodes SET status='failed', net_fails=0, error=?, next_try=? WHERE id=?",
                                      (str(e)[:300], time.time() + backoff(t, str(e)), ep["id"]))
                    net_hosts.append(urllib.parse.urlsplit(row["audio_url"]).hostname)
                    if len(net_hosts) >= 5 and len(set(net_hosts[-5:])) >= 2:   # several hosts failing: our internet is down
                        set_status("waiting", f"network problem ({e}); trying again in 5 min")
                        offline = True
                        break
                except Exception as e:
                    if not isinstance(e, Blocked):
                        traceback.print_exc()
                    with lock, db() as c:
                        row = c.execute("SELECT tries FROM episodes WHERE id=?", (ep["id"],)).fetchone()
                        if row is not None:                     # (None: show unfollowed during the download)
                            c.execute("UPDATE episodes SET status='failed', error=?, next_try=? WHERE id=?",
                                      (str(e)[:300] or type(e).__name__, time.time() + backoff(row["tries"], str(e)), ep["id"]))
                            if time.time() - began > 10:        # a slow failure: other shows go first for a while
                                c.execute("UPDATE episodes SET next_try=? WHERE show_id=? AND status='queued' AND next_try<=?",
                                          (time.time() + 1800, ep["show_id"], time.time()))
        except Exception:
            traceback.print_exc()
        if not offline and not paused:
            set_status("idle")
        queue_now.wait(timeout=300 if offline else 60)          # actions (retry, check, resume) set queue_now


# ---------------------------------------------------------------- web
def state():
    with db() as c:
        shows = []
        for s in c.execute("SELECT * FROM shows ORDER BY title COLLATE NOCASE"):
            cnt = dict(c.execute("SELECT status, COUNT(*) FROM episodes WHERE show_id=? GROUP BY status", (s["id"],)).fetchall())
            latest = c.execute("SELECT MAX(pub) FROM episodes WHERE show_id=?", (s["id"],)).fetchone()[0]
            size = c.execute("SELECT COALESCE(SUM(size),0) FROM episodes WHERE show_id=? AND status='downloaded'", (s["id"],)).fetchone()[0]
            shows.append({"id": s["id"], "title": s["title"], "author": s["author"], "feed_url": s["feed_url"],
                          "folder": s["folder"], "paused": bool(s["paused"]), "last_check": s["last_check"],
                          "last_error": s["last_error"], "counts": cnt, "latest": latest, "size": size,
                          "has_cover": os.path.exists(os.path.join(COVERS, f'{s["id"]}.jpg'))})
    du = shutil.disk_usage(MEDIA)
    return {"shows": shows, "status": status, "free": du.free, "total": du.total,
            "settings": {k: setting(k) for k in DEFAULTS}, "now": time.time()}


def episodes(sid):
    with db() as c:
        return [dict(r) for r in c.execute("SELECT id, num, title, pub, status, size, error, tries, next_try, path FROM episodes "
                                           "WHERE show_id=? ORDER BY pub DESC", (sid,))]


def search(q):
    q = q.strip()[:120]
    if not q:
        return []
    resp = fetch("https://itunes.apple.com/search?" + urllib.parse.urlencode({"media": "podcast", "term": q, "limit": 15}),
                 total=20, accept="application/json")
    out = []
    for x in json.loads(read_capped(resp, 4 << 20)).get("results", []):
        if x.get("feedUrl"):
            img = str(x.get("artworkUrl100", ""))
            out.append({"title": str(x.get("collectionName", ""))[:200], "author": str(x.get("artistName", ""))[:200],
                        "feed_url": str(x["feedUrl"])[:1000], "episodes": x.get("trackCount"),
                        "image": img[:1000] if re.match(r"https://[a-z0-9.-]+\.mzstatic\.com/", img) else ""})
    return out


def act(body):
    a = body.get("action")
    if a == "add":
        url = str(body.get("feed_url", "")).strip()[:2000]
        mode = body.get("mode") if body.get("mode") in ("all", "new") else None
        return {"id": add_show(url, mode)}
    if a == "check":
        check_now.set(); queue_now.set(); return {}
    if a not in ("pause", "remove", "retry", "retry_all", "get_all", "settings"):
        raise Blocked("unknown action")
    sid = 0
    if a != "settings":
        try:
            sid = int(body.get("id") or 0)
        except (TypeError, ValueError):
            raise Blocked("bad id") from None
    if a == "pause" and not isinstance(body.get("paused"), bool):
        raise Blocked("paused must be true or false")
    with lock, db() as c:
        if a == "pause":
            c.execute("UPDATE shows SET paused=? WHERE id=?", (1 if body["paused"] else 0, sid))
            c.execute("UPDATE shows SET last_error='' WHERE id=? AND last_error LIKE 'paused automatically%'", (sid,))
        elif a == "remove":                                     # unfollow; downloaded files stay on disk
            c.execute("DELETE FROM shows WHERE id=?", (sid,))
            try:
                os.unlink(os.path.join(COVERS, f"{sid}.jpg"))
            except OSError:
                pass
        elif a == "retry":
            c.execute("UPDATE episodes SET status='queued', tries=0, net_fails=0, next_try=0, error='' WHERE id=? AND status IN ('failed','skipped','missing','queued')", (sid,))
        elif a == "retry_all":
            c.execute("UPDATE episodes SET status='queued', tries=0, net_fails=0, next_try=0, error='' WHERE show_id=? AND status='failed'", (sid,))
        elif a == "get_all":                                    # download the back catalog of a show added as "new only"
            c.execute("UPDATE episodes SET status='queued' WHERE show_id=? AND status='skipped'", (sid,))
        elif a == "settings":
            m = int(body.get("check_minutes") or 0)
            if not 30 <= m <= 1440:
                raise Blocked("check every 30 to 1440 minutes")
            c.execute("UPDATE settings SET v=? WHERE k='check_minutes'", (json.dumps(m),))
            if body.get("new_show") in ("all", "new"):
                c.execute("UPDATE settings SET v=? WHERE k='new_show'", (json.dumps(body["new_show"]),))
        else:
            raise Blocked("unknown action")
    queue_now.set()
    return {}


ICONS = {"/favicon.ico": ("favicon.ico", "image/x-icon"), "/icon.svg": ("icon.svg", "image/svg+xml"),
         "/apple-touch-icon.png": ("apple-touch-icon.png", "image/png")}
# style-src keeps 'unsafe-inline' only for a few style attributes; scripts have no inline at all.
CSP = ("default-src 'none'; img-src 'self' data: https://*.mzstatic.com; style-src 'self' 'unsafe-inline'; script-src 'self'; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")


class Handler(authweb.SignIn, http.server.BaseHTTPRequestHandler):
    server_version = "podburrow"
    sys_version = ""
    timeout = 20

    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json", cache="no-store", extra=None, cookies=()):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", CSP)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def host_ok(self):
        if (self.headers.get("Host") or "").lower() in ALLOWED_HOSTS:
            return True
        self.send(421, {"error": "unknown host"})
        return False

    def do_HEAD(self):
        self.do_GET()

    def allowed(self):
        """With a proxy named, only the proxy gets through (the health check answers earlier). In AUTH=proxy mode the
        container itself doesn't count either, or something inside could skip the proxy's sign-in."""
        ip = self.client_address[0]
        if authweb.TRUSTED_PROXY and not self.via_proxy() and (authweb.AUTH == "proxy" or not authweb.allowed_ip(ip, self.connection.getsockname()[0])):
            self.send(403, {"error": "Only the reverse proxy may connect."})
            return False
        return self.host_ok()

    def guarded(self, fn):
        """No raw exception reaches the browser. One plain spelling per path, so nothing can reach a page the gate didn't check."""
        try:
            self._token = None
            if self.request_version == "HTTP/0.9":
                return self.send_error(400, "HTTP/0.9 isn't supported")
            if self.command in ("GET", "HEAD"):
                self.read_done()
            if self.via_proxy() and self.real_ip() and not self.server.proxied(self.request, self.real_ip()):
                return self.send(429, {"error": "Busy for your address: try again in a few seconds."}, extra={"Retry-After": "3"})
            path = urllib.parse.urlsplit(self.path or "").path if re.match(r"/(?![/\\\\])", self.path or "") else ""
            if not path or re.search(r"[\\%;\x00-\x20\x7f]|//|/\.", path):
                return self.send(400, {"error": "bad request"})
            fn()
        except authweb.Invalid as e:
            self.send(400, {"error": str(e)})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True                        # the client left or stalled: nothing to answer
        except Exception:
            traceback.print_exc()
            try:
                self.send(500, {"error": "server error (see the container log)"})
            except OSError:
                pass

    def do_GET(self):
        self.guarded(self.get)

    def do_POST(self):
        self.guarded(self.post)

    def get(self):
        if self.path == "/health":
            return self.send(200, {"ok": True})
        if not self.allowed():
            return
        u = urllib.parse.urlsplit(self.path)
        if u.path.startswith("/api/") and (self.headers.get("Sec-Fetch-Site") or "").strip().lower() in ("same-site", "cross-site"):
            return self.send(403, {"error": "forbidden"})
        q = urllib.parse.parse_qs(u.query)
        if not self.gate(u.path, q="" if not u.query else u.query):
            return
        try:
            if u.path == "/login":
                return self.login_page(q)
            if u.path == "/api/auth/state":
                return self.send(200, self.auth_state())
            if u.path == "/api/account":
                return self.send(200, self.account_view()) if authweb.AUTH == "login" else self.send(404, {"error": "not found"})
            if u.path in ("/js/login.js", "/login.css"):
                name, ctype = (u.path.rsplit("/", 1)[1], "text/javascript; charset=utf-8" if u.path.endswith(".js") else "text/css; charset=utf-8")
                with open(os.path.join(STATIC, name), "rb") as f:
                    return self.send(200, f.read(), ctype)
            if u.path in ("/app.js", "/app.css"):
                name, ctype = u.path[1:], ("text/javascript; charset=utf-8" if u.path.endswith(".js") else "text/css; charset=utf-8")
                with open(os.path.join(STATIC, name), "rb") as f:
                    return self.send(200, f.read(), ctype)
            if u.path == "/":
                with open(os.path.join(STATIC, "index.html"), "rb") as f:
                    return self.send(200, f.read(), "text/html; charset=utf-8")
            if u.path in ICONS:
                name, ctype = ICONS[u.path]
                with open(os.path.join(STATIC, name), "rb") as f:
                    return self.send(200, f.read(), ctype, "public, max-age=86400")
            if u.path == "/api/state":
                return self.send(200, state())
            if u.path == "/api/episodes":
                return self.send(200, episodes(int(q.get("id", ["0"])[0])))
            if u.path == "/api/search":
                return self.send(200, search(q.get("q", [""])[0]))
            m = re.fullmatch(r"/api/cover/(\d{1,9})", u.path)
            if m:
                b = cover_bytes(m.group(1))
                if b:
                    return self.send(200, b, "image/png" if b.startswith(b"\x89PNG") else "image/jpeg", "private, max-age=3600")
            return self.send(404, {"error": "not found"})
        except (Blocked, Offline, ValueError, ET.ParseError) as e:
            return self.send(400, {"error": str(e)})
        except Exception as e:
            traceback.print_exc()
            return self.send(500, {"error": type(e).__name__})

    def post(self):
        if not self.allowed():
            return
        why = self.origin_problem()
        if why:
            return self.send(403, {"error": f"Refused: {why}."})
        path = urllib.parse.urlsplit(self.path).path
        if not self.gate(path, post=True):
            return
        if authweb.AUTH == "login" and (path in authweb.PUBLIC_POST or path.startswith("/api/account/")):
            try:
                return self.auth_post(path)
            except authweb.Invalid as e:
                return self.send(400, {"error": str(e)})
        if self.headers.get("X-Podburrow") != "1" or path != "/api/act":
            return self.send(403, {"error": "forbidden"})
        try:
            body = self.json_body(65536)
            return self.send(200, act(body))
        except (TimeoutError, ConnectionError):
            raise
        except (Blocked, Offline, ValueError, KeyError, TypeError, ET.ParseError) as e:
            return self.send(400, {"error": str(e)})
        except Exception as e:
            traceback.print_exc()
            return self.send(500, {"error": type(e).__name__})


class Server(authweb.GuardedServer):
    """Connection caps and deadlines: see GuardedServer."""
    allow_reuse_address = True


CLEAN = os.path.join(DATA, ".clean-exit")
CRASH_CHECK = "check interrupted"
CRASH_DL = "interrupted by a crash"


def on_sigterm(*_):
    """docker stop: note that this was a clean exit (so nothing gets paused on the next start), then leave."""
    try:
        open(CLEAN, "w").close()
    finally:
        os._exit(0)


def home_names_note():
    if not HOME_NAMES:
        print("NOTE: HOME_NAMES isn't set, so a feed could reach your own public address. See the README.", flush=True)


def setup_code_note():
    """No account yet: print a one-time code, so only someone who can read the server's log can create it."""
    if authweb.AUTH == "login" and not authweb.ACCOUNT.exists():
        print(f"SETUP CODE: {authweb.auth.new_setup_code()}\n(a new one at every start until the account exists. To show it: "
              "docker logs <container> 2>&1 | grep '^SETUP CODE' | tail -n 1)", flush=True)


def startup():
    if authweb.AUTH == "login" and not authweb.auth._common_passwords():
        raise SystemExit("common-passwords.txt.gz is missing: the image is incomplete")
    if authweb.AUTH != "login" and os.path.exists(authweb.auth.SESSIONS_FILE):
        os.remove(authweb.auth.SESSIONS_FILE)                   # switching back to the login later must not revive old sign-ins
    setup_code_note()
    home_names_note()
    """Hold the data lock (tools/migrate.py refuses to run while it's held), then undo anything a crash left behind."""
    global _lockf
    os.makedirs(DATA, exist_ok=True)
    _lockf = open(os.path.join(DATA, ".server.lock"), "w")
    try:
        fcntl.flock(_lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise SystemExit("another Podburrow process (or a migration) is using /data")
    init_db()
    clean = os.path.exists(CLEAN)
    if clean:
        os.unlink(CLEAN)
    with lock, db() as c:
        if clean:                                               # docker stop / restart / reboot: just carry on
            c.execute("UPDATE shows SET checking=0")
            c.execute("UPDATE episodes SET status='queued', tries=MAX(tries-1,0) WHERE status='downloading'")
        else:                                                   # a crash: pause only if the same thing crashed it before
            c.execute(f"""UPDATE shows SET paused=1, last_error='paused automatically: checking this feed crashed the app twice'
                         WHERE checking=1 AND last_error LIKE '{CRASH_CHECK}%'""")
            c.execute(f"UPDATE shows SET last_error='{CRASH_CHECK} (crash?)' WHERE checking=1 AND paused=0")
            c.execute(f"""UPDATE shows SET paused=1, last_error='paused automatically: a download from this show crashed the app twice'
                         WHERE id IN (SELECT show_id FROM episodes WHERE status='downloading' AND error LIKE '{CRASH_DL}%')""")
            c.execute(f"""UPDATE episodes SET status='failed', error='{CRASH_DL} (during this download)',
                         next_try=? WHERE status='downloading'""", (time.time() + 900,))
            c.execute("UPDATE shows SET checking=0")
        folders = [r["folder"] for r in c.execute("SELECT folder FROM shows")]
    for folder in folders:
        try:
            clean_parts(os.path.join(MEDIA, folder))
        except OSError:                                         # a folder we can't read mustn't stop the app starting
            pass


def clean_parts(show_dir):
    """.part leftovers from a crash, only in our own show and year folders."""
    if not os.path.isdir(show_dir) or os.path.islink(show_dir):
        return
    dirs = [show_dir] + [os.path.join(show_dir, y) for y in os.listdir(show_dir) if re.fullmatch(r"\d{4}", y)
                         and os.path.isdir(os.path.join(show_dir, y)) and not os.path.islink(os.path.join(show_dir, y))]
    for d in dirs:
        for f in os.listdir(d):
            if f.endswith(".part"):
                try:
                    os.unlink(os.path.join(d, f))
                except OSError:
                    pass


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, on_sigterm)
    startup()
    threading.Thread(target=worker, daemon=True).start()
    print(f"Podburrow on :{PORT}, media {MEDIA}", flush=True)
    Server(("0.0.0.0", PORT), Handler).serve_forever()
