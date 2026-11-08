"""signin-core: check a vendored copy against its pin (SPEC.md "verify.check"). Stdlib only, and it imports nothing else
from signin_core, so an app can run it BEFORE importing the package: a tampered or half-synced copy never executes.

Walks with directory file descriptors and O_NOFOLLOW (no path string is resolved twice), so a symlink swapped in during
the walk is seen, not followed. What it is for: catching a hand edit, a half-finished sync or a stray file before the
app imports the package. Not what it is for: stopping someone who can already write into the app's folder and races the
check (swapping files mid-walk); they could edit the app itself (SPEC.md, Security model 2, residual).
"""
import hashlib, os, re, stat

PIN_NAME = "signin_core.pin"
PKG = "signin_core"
PIN_MAX = 64 * 1024
FILE_MAX = 8 * 1024 * 1024
_HEADER = re.compile(r"signin-core (\d+\.\d+\.\d+) ([0-9a-f]{40})")
_LINE = re.compile(r"([0-9a-f]{64})  (signin_core/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)")
_NOFOLLOW = os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def parse_pin(data):
    """bytes (or text) -> (version, commit, {path: sha256}) or raise ValueError(why)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, bytes):
        raise ValueError("pin is not bytes")
    if len(data) > PIN_MAX:
        raise ValueError("pin over 64 KiB")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("pin is not ASCII")
    if not text.endswith("\n"):
        raise ValueError("pin does not end with a newline")
    lines = text[:-1].split("\n")
    m = _HEADER.fullmatch(lines[0])
    if not m:
        raise ValueError("pin header is not 'signin-core <version> <commit>'")
    files = {}
    for line in lines[1:]:
        lm = _LINE.fullmatch(line)
        if not lm or ".." in lm.group(2).split("/") or lm.group(2) in files:
            raise ValueError("pin has a bad line")
        files[lm.group(2)] = lm.group(1)
    if not files or list(files) != sorted(files):
        raise ValueError("pin lists no files or is not sorted")
    return m.group(1), m.group(2), files


def _read_regular(dir_fd, name, limit):
    """The bytes of a regular file under dir_fd, opened without following a symlink; None if it isn't one."""
    try:
        fd = os.open(name, os.O_RDONLY | _NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=dir_fd)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            return None
        chunks, left = [], limit + 1
        while left > 0:
            b = os.read(fd, min(1 << 20, left))
            if not b:
                break
            chunks.append(b)
            left -= len(b)
        data = b"".join(chunks)
        return data if len(data) <= limit else None
    finally:
        os.close(fd)


MAX_ENTRIES, MAX_DEPTH = 500, 8


def _walk(dir_fd, prefix, found, problems, want=None, depth=0, count=None):
    """Every entry under dir_fd. found['prefix/name'] = its sha256 for a listed regular file (or every regular file when
    want is None), or None for an unlisted one (present, never read: extras cost no reading). Anything that isn't a
    regular file or folder is a problem; so is going deeper than MAX_DEPTH or past MAX_ENTRIES. In __pycache__ only
    regular *.pyc files are ignored."""
    count = count if count is not None else [0]
    if depth > MAX_DEPTH:
        problems.append(f"{prefix}: nested deeper than {MAX_DEPTH}")
        return
    for entry in sorted(os.listdir(dir_fd)):
        count[0] += 1
        if count[0] > MAX_ENTRIES:
            problems.append(f"{prefix}: more than {MAX_ENTRIES} entries")
            return
        rel = f"{prefix}/{entry}"
        try:
            st = os.stat(entry, dir_fd=dir_fd, follow_symlinks=False)
        except OSError:
            problems.append(f"{rel}: vanished while checking")
            continue
        in_cache = prefix.endswith("/__pycache__")
        if stat.S_ISLNK(st.st_mode):
            problems.append(f"{rel}: is a symlink")
        elif stat.S_ISDIR(st.st_mode):
            try:
                sub = os.open(entry, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW, dir_fd=dir_fd)
            except OSError:
                problems.append(f"{rel}: folder can't be opened")
                continue
            try:
                _walk(sub, rel, found, problems, want, depth + 1, count)
            finally:
                os.close(sub)
        elif stat.S_ISREG(st.st_mode):
            if in_cache and entry.endswith(".pyc"):
                continue
            if want is not None and rel not in want:
                found[rel] = None
                continue
            data = _read_regular(dir_fd, entry, FILE_MAX)
            if data is None:
                problems.append(f"{rel}: not a readable regular file under 8 MiB")
            else:
                found[rel] = hashlib.sha256(data).hexdigest()
        else:
            problems.append(f"{rel}: not a regular file")


def check(vendor_dir):
    """(ok, problems): the vendored signin_core/ under vendor_dir matches vendor_dir/signin_core.pin exactly."""
    problems = []
    try:
        top = os.open(vendor_dir, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW)
    except OSError:
        return False, [f"{vendor_dir}: not a folder (or a symlink)"]
    try:
        data = _read_regular(top, PIN_NAME, PIN_MAX)
        if data is None:
            return False, [f"{PIN_NAME}: missing, not a regular file, or over 64 KiB"]
        try:
            _, _, want = parse_pin(data)
        except ValueError as exc:
            return False, [f"{PIN_NAME}: {exc}"]
        try:
            pkg = os.open(PKG, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW, dir_fd=top)
        except OSError:
            return False, [f"{PKG}/: missing, or a symlink"]
        found = {}
        try:
            _walk(pkg, PKG, found, problems, want)
        finally:
            os.close(pkg)
    finally:
        os.close(top)
    for path in sorted(set(want) | set(found)):
        if path not in found:
            problems.append(f"{path}: missing")
        elif path not in want:
            problems.append(f"{path}: not in the pin")   # (unlisted files are seen, never read)
        elif found[path] != want[path]:
            problems.append(f"{path}: changed")
    return not problems, problems


def manifest(pkg_parent, version, commit):
    """The pin text for the signin_core/ under pkg_parent (used by tools/sync.py and the release step)."""
    ok_problems, found = [], {}
    top = os.open(pkg_parent, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW)
    try:
        pkg = os.open(PKG, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW, dir_fd=top)
        try:
            _walk(pkg, PKG, found, ok_problems)
        finally:
            os.close(pkg)
    finally:
        os.close(top)
    if ok_problems:
        raise ValueError("; ".join(ok_problems))
    if not _HEADER.fullmatch(f"signin-core {version} {commit}"):
        raise ValueError("bad version or commit")
    return f"signin-core {version} {commit}\n" + "".join(f"{h}  {p}\n" for p, h in sorted(found.items()))


if __name__ == "__main__":
    import sys
    ok, probs = check(sys.argv[1] if len(sys.argv) > 1 else ".")
    print("ok" if ok else "\n".join(probs))
    sys.exit(0 if ok else 1)
