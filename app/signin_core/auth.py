"""signin-core's account layer (contract: SPEC.md): one account, an optional authenticator app, server-side sessions.
Moved from Fishbowl's auth.py (commit 549fb7f); the app's names come from configure(config).

Built to NIST SP 800-63B-4 and the OWASP Password Storage / Session Management cheat sheets:
- passwords: 15 to 1024 characters, no composition rules, checked against common passwords and the account's own
  words; stored with scrypt (N=2^15, r=8, p=3: 32 MiB, one hash at a time so sign-ins can't run the service out of
  memory); a wrong name costs the same as a wrong password.
- sessions: 256-bit random tokens, kept only as SHA-256 hashes; a new one at every sign-in; all others end when the
  password changes; "keep me signed in" lasts at most 30 days.
- guessing: waits that double after 5 failures, per address and for the account; 100 failures in a row lock the
  account until `unlock` on the host.
- authenticator codes (TOTP, RFC 6238): each code works once; 10 one-time recovery codes.
- first run: the account can only be created with a one-time setup code.

Files (in the data folder, 0600): auth.json (the account), sessions.json (signed-in browsers), setup-code (while
there's no account; only its hash). The command line: <cli_hint> status | unlock | setup-code | signout | reset
"""
import base64
import contextlib
import fcntl
import gzip
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import struct
import sys
import tempfile
import threading
import time
import unicodedata

DATA_DIR = os.environ.get("DATA_DIR", "/data")
AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
SESSIONS_FILE = os.path.join(DATA_DIR, "sessions.json")
SETUP_FILE = os.path.join(DATA_DIR, "setup-code")
HERE = os.path.dirname(os.path.abspath(__file__))


CONFIG = None   # the app's signin_core.web.Config (configure())


def configure(config):
    """The app's names and data folder (a signin_core.web.Config), or just a data folder (a path: the names stay).
    Touches no file."""
    global CONFIG, DATA_DIR, AUTH_FILE, SESSIONS_FILE, SETUP_FILE
    if isinstance(config, (str, os.PathLike)):
        data_dir = os.fspath(config)
    else:
        CONFIG = config
        data_dir = config.data_dir
    DATA_DIR = data_dir
    AUTH_FILE = os.path.join(data_dir, "auth.json")
    SESSIONS_FILE = os.path.join(data_dir, "sessions.json")
    SETUP_FILE = os.path.join(data_dir, "setup-code")

# ---------- passwords ----------

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 3   # 32 MiB per hash (OWASP's scrypt alternative for limited memory)
SCRYPT_MAXMEM = 64 * 1024 * 1024
PW_MIN, PW_MAX = 15, 1024                      # NIST: 15 when the password is the only factor; allow long passphrases
NAME_MAX = 64
_hash_slot = threading.BoundedSemaphore(1)     # one hash at a time: concurrent sign-ins queue instead of piling up RAM


def norm(s):
    """NFKC, as NIST recommends, so the same password typed on another device (other Unicode forms) still matches."""
    return unicodedata.normalize("NFKC", s)


def is_text(s, most=PW_MAX):
    """A string that can be stored and hashed: not too long, no lone surrogates (JSON allows "\\ud800")."""
    if not isinstance(s, str) or len(s) > most:
        return False
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _scrypt(pw, salt, n, r, p):
    with _hash_slot:
        return hashlib.scrypt(norm(pw).encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=SCRYPT_MAXMEM, dklen=32)


def hash_password(pw):
    salt = secrets.token_bytes(16)
    dk = _scrypt(pw, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return "scrypt${}${}${}${}${}".format(SCRYPT_N.bit_length() - 1, SCRYPT_R, SCRYPT_P,
                                          base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def _parse_hash(stored):
    """(n, r, p, salt, key) of a stored scrypt hash, or None if it isn't one (any shape: a damaged file must read as
    damaged, never crash the server or `auth.py reset`)."""
    m = re.fullmatch(r"scrypt\$(\d{1,2})\$(\d{1,2})\$(\d{1,2})\$([A-Za-z0-9+/=]{16,64})\$([A-Za-z0-9+/=]{40,64})",
                     stored if isinstance(stored, str) else "")
    if not m:
        return None
    n, r, p = 2 ** int(m[1]), int(m[2]), int(m[3])
    if not (2 ** 14 <= n <= 2 ** 20 and 1 <= r <= 16 and 1 <= p <= 16 and 128 * n * r <= SCRYPT_MAXMEM // 2):
        return None
    try:
        return n, r, p, base64.b64decode(m[4], validate=True), base64.b64decode(m[5], validate=True)
    except ValueError:   # (binascii.Error: bad padding)
        return None


def verify_password(pw, stored):
    """(matches, should be re-hashed with today's settings). A stored hash that can't be read never matches, but it
    still costs one hash, like a right one would."""
    parsed = _parse_hash(stored)
    if not is_text(pw) or parsed is None:
        _scrypt(pw if is_text(pw) else "x", b"0" * 16, SCRYPT_N, SCRYPT_R, SCRYPT_P)
        return False, False
    n, r, p, salt, dk = parsed
    ok = hmac.compare_digest(_scrypt(pw, salt, n, r, p), dk)
    return ok, ok and (n, r, p) != (SCRYPT_N, SCRYPT_R, SCRYPT_P)


_common = {}


def _common_passwords():
    if "set" not in _common:
        try:
            with gzip.open(os.path.join(HERE, "common-passwords.txt.gz"), "rt", encoding="utf-8") as f:
                _common["set"] = {line.rstrip("\n") for line in f if line.strip()}
        except OSError:
            _common["set"] = set()
    return _common["set"]


def password_problem(pw, user=""):
    """Why a new password isn't good enough (one plain sentence), or None. NIST SP 800-63B-4: length, no composition
    rules, and a blocklist of common, guessable and context words."""
    if not is_text(pw, 10 * PW_MAX):
        return "The password must be plain text."
    n = min(len(pw), len(norm(pw)))   # one character that normalizes to many ("\ufdfa" -> 18) still counts once
    if n < PW_MIN:
        return f"Use at least {PW_MIN} characters (it has {n}). A few random words make a good one."
    if max(len(pw), len(norm(pw))) > PW_MAX:
        return f"Use at most {PW_MAX} characters."
    if not pw.isprintable() and any(ord(c) < 32 or ord(c) == 127 for c in pw):
        return "The password can't contain control characters."
    if any(unicodedata.category(c) == "Cn" for c in pw):   # (its normalization could change with a newer Python)
        return "The password has a character this system doesn't know yet. Pick another."
    low = norm(pw).casefold()
    squeezed = re.sub(r"[\s_.-]+", "", low)
    if low in _common_passwords() or squeezed in _common_passwords():
        return "That one is on lists of common passwords. Pick another."
    for form in (pw.casefold(), low):   # as typed and normalized ("\ufdfa" alone becomes 18 different characters)
        if len(set(form)) < 5:
            return "It repeats too few different characters."
        core = re.sub(r"[\d\W_]+$", "", form) or form   # "monkeymonkey123": the same with digits stuck on
        for f in (form, core):
            for k in range(1, 9):   # a short piece repeated: "passwordpassword", "abcabcabcabcabc"
                if len(f) >= 2 * k and len(f) % k == 0 and f == f[:k] * (len(f) // k):
                    return "It's one short piece repeated."
        if len(form) >= 15 and len(set(form[i:i + 4] for i in range(len(form) - 3))) <= 3:
            return "It's too repetitive."
    seqs = ("0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx3edc4rfv")
    if any(squeezed in (s * 3) or squeezed in (s[::-1] * 3) for s in seqs):
        return "It's a keyboard or alphabet sequence."
    for word in {user.casefold().strip(), *(w.casefold() for w in (CONFIG.banned_words if CONFIG else ()))} - {""}:
        if len(word) >= 3 and word in squeezed and len(squeezed.replace(word, "")) < 10:
            return "It's mostly your name or the app's name. Pick something else."
    return None


_BLANKS = {"\u115f", "\u1160", "\u3164", "\uffa0", "\u2800"}   # fillers that print as nothing


def name_problem(user):
    if not is_text(user, NAME_MAX) or not (1 <= len(user.strip()) <= NAME_MAX):
        return f"Pick a name of 1 to {NAME_MAX} characters."
    if not user.isprintable():
        return "The name can't contain control characters."
    if not any(c not in _BLANKS and not unicodedata.category(c).startswith(("Z", "C", "M")) for c in user):
        return "Pick a name you can see."
    return None


# ---------- authenticator codes (TOTP, RFC 6238) and recovery codes ----------

TOTP_STEP, TOTP_DIGITS, TOTP_WINDOW = 30, 6, 1


def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")   # 160 bits (RFC 4226 recommends 160)


def _b32(secret):
    s = secret.upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def totp_code(secret, step, digits=TOTP_DIGITS, algo="sha1"):
    mac = hmac.new(_b32(secret) if isinstance(secret, str) else secret, struct.pack(">Q", step), algo).digest()
    off = mac[-1] & 0x0F
    num = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(num).zfill(digits)


def totp_match(secret, code, last_step, now=None):
    """The time step a code belongs to, if it's right and newer than the last one used; None otherwise. Each code
    works once (NIST: replay resistance); one step either side allows for clock drift and typing."""
    code = (code if isinstance(code, str) else "").replace(" ", "")
    if not re.fullmatch(r"[0-9]{6}", code):   # ASCII digits only: \d (and int()) also take other scripts' digits
        return None
    now = time.time() if now is None else now
    cur = int(now // TOTP_STEP)
    found = None
    for step in range(cur - TOTP_WINDOW, cur + TOTP_WINDOW + 1):   # every step checked: no early exit to time
        if hmac.compare_digest(totp_code(secret, step), code) and step > (last_step or 0):
            found = step
    return found


def totp_used(secret, code, last_step, now=None):
    """Is this a right code that was already used (the same 30 seconds, typed twice or on two devices)? Still refused,
    but not a guess: the owner is told to wait for the next one."""
    code = (code if isinstance(code, str) else "").replace(" ", "")
    if not re.fullmatch(r"[0-9]{6}", code) or not last_step:
        return False
    cur = int((time.time() if now is None else now) // TOTP_STEP)
    return any(hmac.compare_digest(totp_code(secret, step), code) for step in range(cur - TOTP_WINDOW, cur + TOTP_WINDOW + 1)
               if step <= last_step)


def otpauth_uri(secret, user, issuer=None):
    from urllib.parse import quote
    issuer = issuer or (CONFIG.app if CONFIG else "signin-core")
    label = quote(f"{issuer}:{user}", safe="")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer, safe='')}&algorithm=SHA1&digits=6&period=30"


def qr_svg(text):
    """The QR code for an authenticator app, as SVG (drawn here: the secret never leaves the server for a QR service)."""
    from . import qrcodegen
    qr = qrcodegen.QrCode.encode_text(text, qrcodegen.QrCode.Ecc.MEDIUM)
    n, border = qr.get_size(), 4
    path = " ".join(f"M{x + border},{y + border}h1v1h-1z" for y in range(n) for x in range(n) if qr.get_module(x, y))
    s = n + 2 * border
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {s} {s}" shape-rendering="crispEdges" '
            f'role="img" aria-label="QR code for your authenticator app"><rect width="100%" height="100%" fill="#fff"/>'
            f'<path d="{path}" fill="#000"/></svg>')


RECOVERY_COUNT = 10
_RC_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O, 1/I: easy to read off paper


def new_recovery_codes():
    """(the codes to show once, their hashes to keep). 24 characters from 32 = 120 bits each: enough that their SHA-256
    hashes can't be reversed even if auth.json leaks."""
    codes = ["-".join("".join(secrets.choice(_RC_ALPHABET) for _ in range(4)) for _ in range(6)) for _ in range(RECOVERY_COUNT)]
    return codes, [rc_hash(c) for c in codes]


def rc_hash(code):
    return hashlib.sha256(re.sub(r"[ -]", "", code.upper()).encode("ascii", "replace")).hexdigest()


def looks_like_recovery(code):
    return isinstance(code, str) and bool(re.fullmatch(r"(?:[A-Za-z0-9]{4}[ -]?){5}[A-Za-z0-9]{4}", code.strip(" "), re.ASCII))


# ---------- files ----------

def _write_private(path, text):
    """Atomically replace a file only the app's user can read (0600), flushed to disk (the folder too)."""
    folder = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix="." + os.path.basename(path) + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    try:
        dfd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def _read_private(path, limit=1 << 20):
    """A file's text, never through a link or from a FIFO; None if it isn't there."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not (st.st_mode & 0o170000 == 0o100000) or st.st_size > limit:
            raise OSError(f"{os.path.basename(path)} isn't a regular file of a sane size")
        return f.read().decode("utf-8")


_thread_lock = threading.RLock()
_held = threading.local()


@contextlib.contextmanager
def file_lock():
    """One writer at a time for auth.json, sessions.json and the setup code: the server's threads (an RLock) and the
    command line in another process (flock on data/.auth.lock). Nested use in one thread is fine."""
    with _thread_lock:
        depth = getattr(_held, "depth", 0)
        if depth:
            _held.depth = depth + 1
            try:
                yield
            finally:
                _held.depth -= 1
            return
        fd = os.open(os.path.join(DATA_DIR, ".auth.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            _held.depth = 1
            try:
                yield
            finally:
                _held.depth = 0
        finally:
            os.close(fd)


class Broken(Exception):
    """auth.json exists but can't be used: nobody can sign in until it's fixed or reset (fail closed)."""


# ---------- the account ----------

EVENTS_KEPT = 30
LOCK_AT = 100          # NIST: at most 100 consecutive failures, then the authenticator is disabled
_HEX64 = re.compile(r"[0-9a-f]{64}")
TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")   # a session, device or pre-sign-in token (secrets.token_urlsafe(32))


def _valid(d):
    """auth.json's shape, every field (a wrong type or an empty authenticator secret must never mean "anyone")."""
    if not (isinstance(d, dict) and d.get("v") == 1 and isinstance(d.get("user"), str) and 1 <= len(d["user"]) <= NAME_MAX
            and _parse_hash(d.get("hash")) and isinstance(d.get("epoch", 1), int)):
        return False
    t = d.get("totp", {})
    if not isinstance(t, dict) or (t.get("on") and not (isinstance(t.get("secret"), str) and re.fullmatch(r"[A-Z2-7]{32}", t["secret"])
                                                       and isinstance(t.get("last_step", 0), int))):
        return False
    if not (isinstance(d.get("recovery", []), list) and all(isinstance(x, str) and _HEX64.fullmatch(x) for x in d.get("recovery", []))):
        return False
    devs = d.get("devices", {})
    if not (isinstance(devs, dict) and all(_HEX64.fullmatch(k) and isinstance(v, dict)
                                           and all(isinstance(v.get(f, 0), int) for f in ("t", "fails", "last", "epoch"))
                                           for k, v in devs.items())):
        return False
    if not all(isinstance(d.get(k, {}), dict) and all(isinstance(v, int) for v in d.get(k, {}).values()) for k in ("since", "notice")):
        return False
    return all(isinstance(d.get(k, 0), int) for k in ("failures", "last_fail")) and \
        all(isinstance(d.get(k, []), list) for k in ("events", "fails"))


class Account:
    """auth.json: the one account. Re-read when the file changes on disk (the reset/unlock commands run separately).
    epoch (random) changes whenever access must end (password changed, two-step turned on or off): sessions, half-finished
    sign-ins and trusted devices from an older epoch are worthless."""
    def __init__(self, path=None):
        self.path = path or AUTH_FILE
        self.lock = threading.RLock()
        self._sig, self._d = None, None

    def _load(self):
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            self._sig, self._d = None, None
            return None
        sig = (st.st_ino, st.st_size, st.st_mtime_ns)
        if sig == self._sig:
            return self._d
        try:
            d = json.loads(_read_private(self.path) or "")
        except (OSError, ValueError, UnicodeDecodeError, RecursionError):
            raise Broken("auth.json can't be read")
        if not _valid(d):
            raise Broken("auth.json doesn't look right")
        for k, v in (("totp", {}), ("recovery", []), ("failures", 0), ("last_fail", 0), ("events", []), ("fails", []),
                     ("devices", {}), ("epoch", 1), ("since", {}), ("notice", {})):
            d.setdefault(k, v)
        self._sig, self._d = sig, d
        return d

    def get(self):
        with self.lock:
            return self._load()

    def exists(self):
        return os.path.lexists(self.path)

    def save(self, d):
        with self.lock, file_lock():
            _write_private(self.path, json.dumps(d, ensure_ascii=False))
            st = os.stat(self.path)
            self._sig, self._d = (st.st_ino, st.st_size, st.st_mtime_ns), d

    def update(self, fn):
        """Change the account under the locks, on a fresh read (the command line may have reset it meanwhile: then
        there's no account and nothing is written back)."""
        with self.lock, file_lock():
            self._sig = None
            d = self._load()
            if d is None:
                raise Broken("there's no account")
            d = json.loads(json.dumps(d))
            fn(d)
            self.save(d)
            return d

    @staticmethod
    def event(d, kind, ip, ua=""):
        d["events"] = ([{"t": int(time.time()), "kind": kind, "ip": str(ip)[:64], "ua": str(ua)[:120]}] + d.get("events", []))[:EVENTS_KEPT]

    @staticmethod
    def fail(d, kind, ip, count=None):
        """Failures have their own list (a flood of them can't push the sign-ins out of view), and sign-in failures
        are counted until the next successful sign-in, which shows them once: count = "password" (wrong name or
        password) or "code" (the right password with a wrong code: someone knows the password)."""
        d["fails"] = ([{"t": int(time.time()), "kind": kind, "ip": str(ip)[:64]}] + d.get("fails", []))[:EVENTS_KEPT]
        if count:
            since = d.setdefault("since", {})
            since[count] = int(since.get(count, 0)) + 1


def new_epoch(old=None):
    """A random epoch: unique across accounts too, so nothing made for an account that was reset can match the next."""
    while True:
        e = secrets.randbits(62)
        if e and e != old:
            return e


# ---------- trusted devices ----------
# OWASP "device cookies": a browser that signed in before carries a device token, and its tries count on their own,
# so someone hammering the account (which makes everyone wait, and locks it after 100) can't lock the owner out.

DEVICES_KEPT, DEVICE_FAILS, DEVICE_FOR = 10, 10, 365 * 86400


def same_place(made, ip):
    """Is ip the address a plain-HTTP session was made from? Browsers send cookies to every port of a host, so over
    plain HTTP every other web app on that address gets ours; a session made there only counts from that very address
    (IPv6 too: a /64 is a whole network, the host's own address included; a browser whose privacy address changed signs
    in again)."""
    try:
        a, b = ipaddress.ip_address(made or ""), ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    return (getattr(a, "ipv4_mapped", None) or a) == (getattr(b, "ipv4_mapped", None) or b)


def new_device(d, tls=False):
    """Add a device token (for this epoch, and this kind of connection: http or https) to the account dict d; returns
    the token (for the cookie). Not bound to an address: a laptop that changes networks must stay trusted, or someone
    guessing could keep its owner out (a copied token gets only the device's own 10 tries, and its wrong tries made
    from another address are never forgiven as the owner's typos)."""
    token = secrets.token_urlsafe(32)
    devs = {k: v for k, v in (d.get("devices") or {}).items()
            if isinstance(v, dict) and time.time() - v.get("t", 0) < DEVICE_FOR and v.get("epoch") == d["epoch"]}
    while len(devs) >= DEVICES_KEPT:
        del devs[min(devs, key=lambda k: devs[k].get("t", 0))]
    devs[hashlib.sha256(token.encode()).hexdigest()] = {"t": int(time.time()), "fails": 0, "epoch": d["epoch"], "tls": bool(tls)}
    d["devices"] = devs
    return token


def device_of(d, token, tls=False):
    """The device-token hash if this token belongs to the account (this epoch, the same kind of connection it was
    made on, not worn out by wrong tries)."""
    if not isinstance(token, str) or not TOKEN.fullmatch(token):
        return None
    h = hashlib.sha256(token.encode()).hexdigest()
    v = (d.get("devices") or {}).get(h)
    if isinstance(v, dict) and time.time() - v.get("t", 0) < DEVICE_FOR and v.get("fails", 0) < DEVICE_FAILS \
            and v.get("epoch") == d["epoch"] and bool(v.get("tls")) == tls:
        return h
    return None


# ---------- sessions ----------

class Sessions:
    """sessions.json: {sha256(token): {id, created, seen, until, idle, ip, ua, keep, epoch, tls}}. The cookie holds only the
    token; the file only its hash, so reading the file doesn't let anyone in."""
    KEEP_FOR, KEEP_IDLE = 30 * 86400, 7 * 86400        # "keep me signed in" (NIST AAL1: re-authenticate within 30 days)
    BRIEF_FOR, BRIEF_IDLE = 12 * 3600, 3600            # otherwise
    SEEN_EVERY = 60                                    # last-seen is written at most once a minute per session
    MAX = 50                                           # oldest ones go first

    def __init__(self, path=None):
        self.path = path or SESSIONS_FILE
        self.lock = threading.RLock()
        self._sig, self._d = None, {}

    def _load(self, fresh=False):
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            self._sig, self._d = None, {}
            return self._d
        sig = (st.st_ino, st.st_size, st.st_mtime_ns)
        if fresh or sig != self._sig:
            try:
                d = json.loads(_read_private(self.path, 1 << 22) or "{}")
            except (OSError, ValueError, UnicodeDecodeError, RecursionError):
                d = {}   # a damaged file signs everyone out (never in)
            self._d = {k: v for k, v in (d.items() if isinstance(d, dict) else ())
                       if _HEX64.fullmatch(k) and isinstance(v, dict) and all(isinstance(v.get(f), int) for f in ("until", "idle", "seen", "epoch", "created"))
                       and isinstance(v.get("id"), str)}
            self._sig = sig
        return self._d

    def _save(self):
        _write_private(self.path, json.dumps(self._d))
        st = os.stat(self.path)
        self._sig = (st.st_ino, st.st_size, st.st_mtime_ns)

    @staticmethod
    def _key(token):
        return hashlib.sha256(token.encode("ascii", "replace")).hexdigest()

    def create(self, keep, ip, ua, epoch, tls=False):
        token = secrets.token_urlsafe(32)                 # 256 bits
        now = int(time.time())
        with self.lock, file_lock():
            d = self._load(fresh=True)
            for k in [k for k, v in d.items() if not self._alive(v, now)]:
                del d[k]
            while len(d) >= self.MAX:
                del d[min(d, key=lambda k: d[k]["seen"])]
            d[self._key(token)] = {"id": secrets.token_hex(8), "created": now, "seen": now,
                                   "until": now + (self.KEEP_FOR if keep else self.BRIEF_FOR),
                                   "idle": self.KEEP_IDLE if keep else self.BRIEF_IDLE,
                                   "ip": str(ip)[:64], "ua": str(ua)[:160], "keep": bool(keep), "epoch": int(epoch),
                                   "tls": bool(tls), **({} if tls else {"from": str(ip)[:64]})}
            self._save()
        return token, (self.KEEP_FOR if keep else None)

    @staticmethod
    def _alive(s, now):
        return now < s["until"] and now - s["seen"] < s["idle"]

    def check(self, token, epoch, ip=None, tls=None):
        """The session for this cookie value, if it's still valid for this epoch (and mark it seen); None otherwise.
        tls: the kind of connection this request came over; a session counts only on the kind it was made on (one
        made over plain HTTP was exposed there, and is no good over HTTPS), and one made over plain HTTP only from
        the address it was made from (same_place). An unknown token costs a hash and a lookup (no file read): a
        request may carry many cookie values to try."""
        if not isinstance(token, str) or not TOKEN.fullmatch(token):
            return None
        now, key = int(time.time()), self._key(token)
        with self.lock:
            s = self._load().get(key)
            if not s or (tls is not None and bool(s.get("tls")) != tls) or (tls is False and not same_place(s.get("from"), ip)):
                return None
            if self._alive(s, now) and s["epoch"] == epoch and now - s["seen"] < self.SEEN_EVERY:
                return s
            with file_lock():
                d = self._load(fresh=True)
                s = d.get(key)
                if not s:
                    return None
                if not self._alive(s, now) or s["epoch"] != epoch:
                    del d[key]
                    self._save()
                    return None
                s["seen"] = now
                if ip:
                    s["ip"] = str(ip)[:64]
                self._save()
                return s

    def on_disk(self, token, epoch):
        """Is this session in the file right now? For checks inside another locked update (call it holding
        file_lock, as Account.update does): no cache and no Sessions.lock (taking that here would invert the lock
        order), and every writer holds file_lock, so the file can't change under it."""
        if not isinstance(token, str) or not TOKEN.fullmatch(token):
            return False
        try:
            d = json.loads(_read_private(self.path, 1 << 22) or "{}")
        except (OSError, ValueError, UnicodeDecodeError, RecursionError):
            return False
        s = d.get(self._key(token)) if isinstance(d, dict) else None
        try:
            return bool(s) and s["epoch"] == epoch and self._alive(s, int(time.time()))
        except (KeyError, TypeError):
            return False

    def end(self, token):
        """End this session: True if there was one. A value that matches none costs a hash and a lookup (sign-out tries
        every cookie value the browser sent)."""
        key = self._key(token or "")
        with self.lock:
            if key not in self._load():
                return False
            with file_lock():
                if self._load(fresh=True).pop(key, None) is not None:
                    self._save()
                    return True
        return False

    def end_id(self, sid, own=None):
        """End the session with this id: True, False if there's none, None when the asking browser's own session
        (own) ended meanwhile (then nothing is ended)."""
        if not isinstance(sid, str) or not re.fullmatch(r"[0-9a-f]{16}", sid):
            return False
        with self.lock, file_lock():
            d = self._load(fresh=True)
            if own and self._key(own) not in d:
                return None
            for k in [k for k, v in d.items() if hmac.compare_digest(v["id"].encode(), sid.encode())]:
                del d[k]
                self._save()
                return True
        return False

    def end_all(self, but_token=None):
        """End every session (but this one). False, ending nothing, when "this one" has itself ended meanwhile."""
        with self.lock, file_lock():
            keep = self._key(but_token) if but_token else None
            d = self._load(fresh=True)
            if keep and keep not in d:
                return False
            for k in [k for k in d if k != keep]:
                del d[k]
            self._save()
            return True

    def listing(self, current_token=None, epoch=None):
        now = int(time.time())
        cur = self._key(current_token) if current_token else None
        with self.lock:
            return sorted(({"id": v["id"], "created": v["created"], "seen": v["seen"], "ip": v.get("ip", ""), "ua": v.get("ua", ""),
                            "keep": v.get("keep", False), "current": k == cur}
                           for k, v in self._load().items() if self._alive(v, now) and (epoch is None or v["epoch"] == epoch)),
                          key=lambda s: -s["seen"])


# ---------- guessing ----------

class Throttle:
    """Failed tries per address (in memory, last 15 minutes) and for the account (consecutive, saved in auth.json):
    after 5, each try has to wait twice as long as the one before, up to 15 minutes. Checked before any hashing."""
    FREE, MAX_WAIT, WINDOW = 5, 900, 900

    def __init__(self):
        self.lock = threading.Lock()
        self.by_ip = {}

    @classmethod
    def wait_for(cls, count, last, now):
        if count < cls.FREE:
            return 0
        last = min(last, now)   # a clock stepped back can't make a wait longer than MAX_WAIT
        left = last + min(2 ** (count - cls.FREE), cls.MAX_WAIT) - now
        return math.ceil(left) + 1 if left > 0 else 0   # rounded up: "wait 1 s" never means a second "too many tries"

    @staticmethod
    def _key(ip):
        """IPv6 addresses count per /64: one home or server usually gets a whole /64 to pick addresses from."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return str(ip)[:64]
        if a.version == 6 and not a.ipv4_mapped:
            return str(ipaddress.ip_network(f"{a}/64", strict=False))
        return str(getattr(a, "ipv4_mapped", None) or a)

    def ip_wait(self, ip, now=None):
        now, ip = time.time() if now is None else now, self._key(ip)
        with self.lock:
            fails = [t for t in self.by_ip.get(ip, []) if now - t < self.WINDOW]
            self.by_ip[ip] = fails
            if not fails:
                self.by_ip.pop(ip, None)
            return self.wait_for(len(fails), fails[-1] if fails else 0, now)

    def ip_failed(self, ip, now=None):
        now, ip = time.time() if now is None else now, self._key(ip)
        with self.lock:
            if len(self.by_ip) > 10000:                 # a flood of addresses can't grow this without bound
                for k in list(self.by_ip)[:5000]:
                    del self.by_ip[k]
            self.by_ip.setdefault(ip, []).append(now)
            self.by_ip[ip] = self.by_ip[ip][-200:]

    def ip_ok(self, ip):
        with self.lock:
            self.by_ip.pop(self._key(ip), None)




# ---------- the first-run setup code ----------
# Shown once (by the app at first start, or by `setup-code`); only its hash is kept in <data folder>/setup-code.

def new_setup_code():
    """A one-time code for creating the account: 25 characters from 32 = 125 bits. Returns it (to print)."""
    code = "-".join("".join(secrets.choice(_RC_ALPHABET) for _ in range(5)) for _ in range(5))
    with file_lock():
        _write_private(SETUP_FILE, hashlib.sha256(code.replace("-", "").encode()).hexdigest() + "\n")
    return code


def setup_code_matches(code):
    try:
        want = (_read_private(SETUP_FILE, 200) or "").strip()
    except (OSError, UnicodeDecodeError):
        return False
    got = re.sub(r"[ -]", "", code.upper()) if isinstance(code, str) else ""
    if not (_HEX64.fullmatch(want) and re.fullmatch(r"[A-Z0-9]{25}", got)):
        return False
    return hmac.compare_digest(want.encode(), hashlib.sha256(got.encode()).hexdigest().encode())


def clear_setup_code():
    with file_lock():
        try:
            os.remove(SETUP_FILE)
        except FileNotFoundError:
            pass


# ---------- the command line (on the host: <cli_hint> ...; each app keeps a shim at its old auth.py path) ----------

def _cli(argv):
    usage = (f"usage: {CONFIG.cli_hint} status | unlock | setup-code | signout | reset [--yes]\n"
             "  status      the account's name, whether it's locked, authenticator on/off, signed-in browsers\n"
             "  unlock      allow sign-ins again after 100 wrong tries in a row\n"
             "  setup-code  a new one-time code for creating the account (only while there's no account)\n"
             "  signout     sign every browser out and forget trusted browsers (the account stays)\n"
             f"  reset       delete the account and every session ({CONFIG.reset_keeps}), and print a new setup code")
    sys.stdout.reconfigure(errors="backslashreplace")   # (a damaged account file's name must not crash status)
    if not argv or argv[0] not in ("status", "unlock", "setup-code", "signout", "reset"):
        print(usage)
        return 2
    if os.geteuid() == 0:
        print(CONFIG.run_as_hint)
        return 1
    acct, sess = Account(), Sessions()
    cmd = argv[0]
    try:
        d, broken = acct.get(), None
    except Broken as e:
        d, broken = None, e
    if cmd == "status":
        if broken:
            print(f"The account file is damaged ({broken}): nobody can sign in. Fix it with: reset")
            return 1
        if d is None:
            print("No account yet." + (f" (A setup code exists: {CONFIG.setup_code_where}; "
                                       "make a new one with setup-code.)" if os.path.exists(SETUP_FILE) else ""))
            return 0
        name = "".join(c if c.isprintable() else f"\\x{ord(c):02x}" if ord(c) < 256 else f"\\u{ord(c):04x}" for c in d["user"])
        print(f"Account: {name}\nLocked: {'yes' if d.get('failures', 0) >= LOCK_AT else 'no'} "
              f"({d.get('failures', 0)} wrong tries in a row)\nAuthenticator app: {'on' if d['totp'].get('on') else 'off'}"
              f"\nRecovery codes left: {len(d.get('recovery', []))}\nSigned-in browsers: {len(sess.listing(epoch=d['epoch']))}")
        return 0
    if cmd == "setup-code":
        if broken:
            print(f"The account file is damaged ({broken}): reset deletes it and prints a new setup code.")
            return 1
        with file_lock():   # the same lock as creating the account: never a code next to a fresh account
            if acct.exists():
                print("There's already an account: setup codes are only for creating one (reset deletes it first).")
                return 1
            code = new_setup_code()
        print(f"Setup code: {code}")
        return 0
    if cmd == "signout":
        with file_lock():
            try:
                os.remove(SESSIONS_FILE)
            except FileNotFoundError:
                pass
        if d is not None:   # a new epoch: half-finished sign-ins can't complete, and no browser stays trusted
            acct.update(lambda x: (x.update(epoch=new_epoch(x["epoch"]), devices={}),
                                   Account.event(x, "every browser signed out on the host", "host")))
        print("Every browser is signed out and none is trusted any more (no restart needed). If someone else may know the "
              "password, sign in and change it. If someone keeps guessing, new browsers have to wait: auth.py unlock "
              "clears that.")
        return 0
    if cmd == "unlock":
        if d is None:
            print(f"The account file is damaged ({broken}): use reset." if broken else "No account: nothing to unlock.")
            return 1
        was = d.get("failures", 0)
        acct.update(lambda x: (x.update(failures=0, last_fail=0), Account.event(x, "unlocked on the host", "host")))
        print("Unlocked: sign-ins work again (no restart needed)." if was >= LOCK_AT else
              f"It wasn't locked ({was} wrong tries in a row); the count starts again from 0.")
        return 0
    if "--yes" not in argv:
        if not sys.stdin.isatty():
            print("reset deletes the account: run it with -it to confirm, or add --yes")
            return 1
        if input(f"This deletes the account and signs every browser out ({CONFIG.reset_keeps}). Type RESET: ").strip() != "RESET":
            print("Nothing changed.")
            return 1
    with file_lock():   # nothing the running server writes can bring the old account back
        for p in (AUTH_FILE, SESSIONS_FILE):
            try:
                os.remove(p)
            except FileNotFoundError:
                pass
        code = new_setup_code()
    print(f"Done. Open {CONFIG.open_noun} and create the account with this setup code: {code}")
    return 0


def cli(config, argv):
    """The command line, for an app's auth.py shim: configure, then run."""
    configure(config)
    return _cli(argv)
