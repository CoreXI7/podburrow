#!/usr/bin/env python3
"""Move Podgrab's shows and downloaded episodes into Podburrow.
Runs INSIDE the Podburrow image while the Podburrow server AND Podgrab are STOPPED (it refuses if the server runs):

    docker compose run --rm --no-deps -v <podgrab config>:/podgrab:ro podburrow python3 /tools/migrate.py           dry run
    docker compose run --rm --no-deps -v <podgrab config>:/podgrab:ro podburrow python3 /tools/migrate.py --apply   do it
    docker compose run --rm --no-deps podburrow python3 /tools/migrate.py --undo                                    put back

Files go straight into <Show>/. Per episode: journal "start", copy the file next to its new place, write the Plex tags on the COPY (tagger.py, memory
capped), fsync, check it is the same length of audio, rename it into place, keep the old mtime, delete the original,
journal "done". The original ID3 block (+ v1 trailer) is saved first, so --undo restores names, folders, tags, mtimes.

Duplicates (the same episode saved twice because the feed moved hosts and got new IDs) keep ONE file: the biggest
(= best quality), filed under the ID the feed uses now. The other copies, and broken files (empty, HTML error pages),
are moved aside to MEDIA/.podgrab-leftovers/ (hidden: Plex ignores it), journaled, so --undo puts them back too.
A file that can't be moved is reported and left as it was; the run carries on. New episodes stay "pending" (the server
won't download them) until a run finishes. Every step is safe to kill and re-run. Podgrab's database is only read.
"""
import fcntl, hashlib, json, os, re, shutil, sqlite3, sys, time
from datetime import datetime, timezone

sys.path.insert(0, "/app")
import server as S                                                # noqa: E402  (same naming/tag code as new downloads)

PODGRAB_DB = os.environ.get("PODGRAB_DB", "/podgrab/podgrab.db")
PODGRAB_MEDIA = "/assets"                                          # where Podgrab saw MEDIA
JOURNAL = os.path.join(S.DATA, "migrate-journal.jsonl")
ORIG = os.path.join(S.DATA, "migrate-orig-tags")
LEFTOVERS = ".podgrab-leftovers"


class Skip(Exception):
    """This one file can't be migrated safely: leave it as it is, report it, carry on."""


def iso(s):
    d = datetime.fromisoformat(str(s).replace(" ", "T"))
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).isoformat()


def audio_length(path):
    """Seconds of audio, or 0.0 if the file isn't readable audio."""
    import mutagen
    try:
        m = mutagen.File(path)
    except Exception:
        return 0.0
    if m is None or m.info is None:
        return 0.0
    return float(getattr(m.info, "length", 0) or 0)


def readable(path):
    try:
        with open(path, "rb") as f:
            f.read(16)
        return True
    except OSError:
        return False


def good(path):
    return os.path.isfile(path) and os.path.getsize(path) >= 100_000 and audio_length(path) > 0


def copy_lowmem(src, dst):
    """Copy without filling the container's memory with page cache: on a slow HDD a plain copy of a 400 MB episode
    let dirty pages pile up until the 256 MB cgroup was OOM-killed (2026-10-28). Flush + drop cache every 64 MB."""
    step = 64 << 20
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        done = 0
        while True:
            b = fi.read(8 << 20)
            if not b:
                break
            fo.write(b)
            done += len(b)
            if done % step < len(b):
                fo.flush(); os.fsync(fo.fileno())
                os.posix_fadvise(fo.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
                os.posix_fadvise(fi.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
        fo.flush(); os.fsync(fo.fileno())
        os.posix_fadvise(fo.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)


def drop_cache(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    finally:
        os.close(fd)


def journal():
    """Last journal state per original path. Torn lines (crash) are skipped."""
    last = {}
    if os.path.exists(JOURNAL):
        with open(JOURNAL) as f:
            for line in f:
                try:
                    j = json.loads(line)
                except ValueError:
                    continue
                last[j["old"]] = j
    return last


def log(j):
    with open(JOURNAL, "a") as f:
        f.write(json.dumps(j) + "\n")
        f.flush(); os.fsync(f.fileno())


def read_podgrab():
    src = sqlite3.connect(f"file:{PODGRAB_DB}?mode=ro&immutable=1", uri=True)
    src.row_factory = sqlite3.Row
    shows = [dict(r) for r in src.execute("SELECT id, title, author, image, url FROM podcasts WHERE deleted_at IS NULL")]
    for s in shows:
        rows = src.execute("""SELECT guid, title, summary, pub_date, file_url, download_path, download_status, created_at
                              FROM podcast_items WHERE podcast_id=? AND deleted_at IS NULL""", (s["id"],)).fetchall()
        s["items"] = sorted((dict(r) for r in rows), key=lambda r: iso(r["pub_date"]))
    return shows


def podgrab_file(it):
    p = it["download_path"] or ""
    if it["download_status"] == 2 and p.startswith(PODGRAB_MEDIA + "/"):
        return S.under_media(p[len(PODGRAB_MEDIA) + 1:])
    return None


def plan():
    """Everything the migration would do, computed without touching anything."""
    jr = journal()
    claimed, out, folders = set(), [], set()
    try:
        with S.db() as c:                                          # a re-run keeps its folders; another show's stay taken
            taken = {r["folder"]: r["feed_url"] for r in c.execute("SELECT folder, feed_url FROM shows")}
    except sqlite3.Error:
        taken = {}
    for s in read_podgrab():
        title = S.clean_text(s["title"], 200)
        folder, n = S.safe_name(title, 150), 2
        while folder in folders or taken.get(folder, s["url"]) != s["url"]:   # "Show" and "Show?" clean to one name
            folder, n = f"{S.safe_name(title, 140)} ({n})", n + 1
        folders.add(folder)
        show = {"title": title, "folder": folder, "author": S.clean_text(s["author"], 200),
                "image_url": s["image"] or "", "feed_url": s["url"]}
        groups = {}                                                # same episode = same local date + title
        for it in s["items"]:
            k = (S.local(iso(it["pub_date"])).date(), S.clean_text(it["title"], 300).lower().strip())
            groups.setdefault(k, []).append(it)
        eps, seen, broken, dupes, stuck, num = [], set(), [], [], [], 0
        for items in groups.values():
            kept = max(items, key=lambda it: str(it["created_at"]))   # the row Podgrab added last = the feed's ID now
            guid = (kept["guid"] or kept["file_url"] or "").strip()[:500]
            if not guid or guid in seen:
                continue
            seen.add(guid)
            num += 1
            ep = {"guid": guid, "title": S.clean_text(kept["title"], 300) or "Untitled episode", "pub": iso(kept["pub_date"]),
                  "audio_url": kept["file_url"], "summary": S.clean_text(kept["summary"]), "num": num,
                  "old": None, "new": None, "resume": False}
            files = []
            for it in items:
                try:
                    f = podgrab_file(it)
                except S.Blocked:                                  # a path outside the media folder: skip this row, not the run
                    f = None
                if f and f not in files and f not in claimed:
                    files.append(f)
            done = [f for f in files if jr.get(f, {}).get("state") in ("start", "done")
                    and not os.path.exists(f) and os.path.exists(jr[f]["new"])]
            if any(os.path.isfile(f) and not readable(f) for f in files) and not done:
                # can't even read one of its files (permissions, disk error): don't judge it, leave the episode alone
                stuck += [f for f in files if os.path.isfile(f)]
                ep["stuck"] = True
                claimed.update(files)
                eps.append(ep)
                continue
            if done:                                               # moved in an earlier (maybe interrupted) run
                f = done[0]
                ep["old"], ep["new"], ep["resume"] = f, os.path.relpath(jr[f]["new"], S.MEDIA), True
            else:
                ok = [f for f in files if good(f)]
                if ok:
                    f = max(ok, key=os.path.getsize)               # duplicates: keep the biggest = best quality
                    ep["old"], ep["new"] = f, S.episode_path(show, ep, os.path.splitext(f)[1].lower().lstrip(".") or "mp3")
            claimed.update(files)
            for f in files:
                if f != ep["old"] and os.path.isfile(f):
                    if not readable(f):
                        stuck.append(f)                            # can't judge an unreadable copy: leave it alone
                    else:
                        (dupes if good(f) else broken).append(f)
            eps.append(ep)
        out.append((show, eps, broken, dupes, stuck))
    return out


def report(p):
    total = moves = 0
    biggest = 0
    for show, eps, broken, dupes, stuck in p:
        have = [e for e in eps if e["old"]]
        total += len(eps); moves += len(have)
        biggest = max([biggest] + [os.path.getsize(e["old"]) for e in have if os.path.exists(e["old"])])
        years = sorted({S.local(e["pub"]).year for e in eps})
        size = lambda fs: sum(os.path.getsize(f) for f in fs) >> 20
        print(f'\n== {show["title"]}  ->  folder "{show["folder"]}", albums {years[0]} .. {years[-1]} ({len(years)} years)')
        print(f"   {len(eps)} episodes: {len(have)} files to move + retag, {len(eps) - len(have)} to download")
        for e in have[:2] + have[-1:]:
            print(f'   {os.path.relpath(e["old"], S.MEDIA)}\n     -> {e["new"]}')
        if dupes:
            print(f"   {len(dupes)} duplicate copies ({size(dupes)} MB, the smaller/worse copy of an episode) -> {LEFTOVERS}/duplicates/")
        if broken:
            print(f"   {len(broken)} broken files ({size(broken)} MB: empty or not audio) -> {LEFTOVERS}/broken/, episode downloaded again")
        if stuck:
            print(f"   !! {len(stuck)} files can't be read (permissions?) and are left alone: " +
                  ", ".join(os.path.basename(f) for f in stuck[:5]))
        on_disk = set()
        for root, _, files in os.walk(os.path.join(S.MEDIA, show["folder"])):
            on_disk |= {os.path.join(root, f) for f in files}
        extra = sorted(on_disk - {e["old"] for e in have} - set(broken) - set(dupes) - set(stuck))
        if extra:
            print(f"   {len(extra)} other files in the show folder stay where they are, e.g. {os.path.relpath(extra[0], S.MEDIA)}")
    print(f"\nTOTAL {total} episodes: {moves} files to move + retag, {total - moves} to download.")
    print(f"Free space {shutil.disk_usage(S.MEDIA).free >> 30} GB; needs ~{biggest >> 20} MB spare at a time.")


def orig_tag_block(path):
    """The raw ID3v2 block at the start of an MP3 (header + body + footer), or b'' if there is none."""
    with open(path, "rb") as f:
        h = f.read(10)
        if len(h) < 10 or h[:3] != b"ID3":
            return b""
        size = (h[6] << 21) | (h[7] << 14) | (h[8] << 7) | h[9]
        if size > S.TAG_MAX:
            raise Skip(f"{size >> 20} MB tag block")
        footer = 10 if h[5] & 0x10 else 0
        return h + f.read(size + footer)


def tail128(path):
    """The last 128 bytes if they are an ID3v1 tag, else b''."""
    with open(path, "rb") as f:
        f.seek(0, 2)
        if f.tell() < 128:
            return b""
        f.seek(-128, 2)
        t = f.read(128)
    return t if t[:3] == b"TAG" else b""


def take_lock():
    """Refuse to run next to the Podburrow server or another migration."""
    os.makedirs(S.DATA, exist_ok=True)
    f = open(os.path.join(S.DATA, ".server.lock"), "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise SystemExit("STOP: the Podburrow server (or another migration) is running. Stop it first.")
    return f


def set_mtime(path, j):
    try:
        os.utime(path, ns=(j["atime_ns"], j["mtime_ns"]))
    except (KeyError, PermissionError):                           # root-owned originals: can't set their times as uid 1000
        pass


def move_one(show, e, j):
    """Copy, tag, check and swap one episode. Raises Skip if this file can't be done safely (nothing changed then)."""
    dest = S.under_media(e["new"])
    owned = j and j["new"] == dest and j["state"] == "start" and not done_owner(dest, e["old"])
    if os.path.exists(dest) and not owned:                         # checked BEFORE anything is journaled
        raise Skip("destination already exists")
    work = dest + ".migrating"
    try:
        st = os.stat(e["old"])
        before = audio_length(e["old"])
        tagfile = os.path.join(ORIG, hashlib.sha256(e["old"].encode()).hexdigest()[:24] + ".id3")
        with open(tagfile, "wb") as f:
            f.write(orig_tag_block(e["old"]))
        with open(tagfile + ".v1", "wb") as f:
            f.write(tail128(e["old"]))
        rec = {"old": e["old"], "new": dest, "tags": tagfile, "size": st.st_size,
               "mtime_ns": st.st_mtime_ns, "atime_ns": st.st_atime_ns, "len": before}
        log(dict(rec, state="start"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        copy_lowmem(e["old"], work)
        S.write_tags(work, os.path.splitext(dest)[1].lstrip("."), show, e, S.cover_file(show["id"]))
        drop_cache(work)
        after = audio_length(work)
        if abs(after - before) > 1.5:
            raise Skip(f"audio length changed {before:.1f}s -> {after:.1f}s after tagging")
        os.replace(work, dest)
        set_mtime(dest, rec)
        os.unlink(e["old"])
        log(dict(rec, state="done"))
    except (S.Blocked, S.Offline, OSError) as err:
        raise Skip(f"{type(err).__name__}: {err}") from err
    finally:
        if os.path.exists(work):
            os.unlink(work)
        d = os.path.dirname(dest)
        if os.path.isdir(d) and not os.listdir(d):
            os.rmdir(d)
    return dest


def done_owner(dest, but):
    """Another original whose finished ('done') copy is this dest: then dest is not ours to overwrite or delete."""
    return any(j["new"] == dest and j["state"] == "done" and o != but for o, j in journal().items())


def put_aside(kind, show, f, jr):
    """Move a duplicate/broken file into the hidden leftovers folder (same drive: a rename)."""
    j = jr.get(f)
    if j and j.get("state") == "aside":
        target = j["new"]
    else:
        base = os.path.join(S.MEDIA, LEFTOVERS, kind, show["folder"])
        target, n = os.path.join(base, os.path.basename(f)), 2
        while os.path.exists(target):
            stem, ext = os.path.splitext(os.path.basename(f))
            target, n = os.path.join(base, f"{stem} ({n}){ext}"), n + 1
        log({"state": "aside", "old": f, "new": target})
    if os.path.exists(f) and not os.path.exists(target):
        os.makedirs(os.path.dirname(target), exist_ok=True)
        os.rename(f, target)


def apply(p):
    lk = take_lock()
    S.init_db()
    os.makedirs(ORIG, exist_ok=True)
    if not os.path.exists(os.path.join(S.MEDIA, S.SENTINEL)):      # never decide on its own that this is the real drive
        raise SystemExit(f"{S.MEDIA} has no {S.SENTINEL} file: is the media drive mounted? If it is, create that empty file and run this again.")
    if os.path.exists(JOURNAL) and os.path.getsize(JOURNAL):
        with open(JOURNAL, "rb+") as f:                            # a crash can leave a half line: end it
            f.seek(-1, 2)
            if f.read(1) != b"\n":
                f.write(b"\n")
    for show, *_ in p:                                        # .migrating leftovers from a kill -9
        for root, _, files in os.walk(os.path.join(S.MEDIA, show["folder"])):
            for f in files:
                if f.endswith(".migrating"):
                    os.unlink(os.path.join(root, f))
    with S.lock, S.db() as c:                                      # shows + episodes into the new database (idempotent)
        for show, eps, *_ in p:
            r = c.execute("SELECT id FROM shows WHERE feed_url=?", (show["feed_url"],)).fetchone()
            sid = r["id"] if r else c.execute(
                "INSERT INTO shows (title, folder, feed_url, author, image_url, added_at, last_check) VALUES (?,?,?,?,?,?,0)",
                (show["title"], show["folder"], show["feed_url"], show["author"], show["image_url"], time.time())).lastrowid
            show["id"] = sid
            for e in eps:                                          # 'pending' = the server leaves it alone for now
                c.execute("""INSERT OR IGNORE INTO episodes (show_id, guid, title, pub, audio_url, summary, num, status)
                             VALUES (?,?,?,?,?,?,?,'pending')""", (sid, e["guid"], e["title"], e["pub"], e["audio_url"], e["summary"], e["num"]))
    for show, *_ in p:
        for _ in range(3):
            if S.cover_bytes(show["id"]) or not show["image_url"]:
                break
            S.save_cover(show["id"], show["image_url"])
        if show["image_url"] and not S.cover_bytes(show["id"]):
            raise SystemExit(f'STOP: couldn\'t download the cover for {show["title"]}; nothing was moved. Try again later.')
    jr = journal()
    n, failed, t0 = 0, [], time.time()
    for show, eps, *_ in p:
        cover = S.cover_bytes(show["id"])
        for e in eps:
            if not e["old"]:
                continue
            j = jr.get(e["old"])
            dest = S.under_media(e["new"])
            if (e["resume"] or (j and j["state"] == "done")) and os.path.exists(dest):
                if j["state"] != "done":                           # finish an interrupted file: journal + database
                    log(dict(j, state="done"))
            else:
                try:
                    dest = move_one(show, e, j)
                    n += 1
                except Skip as err:
                    failed.append((e, str(err)))
                    print(f'  !! left as it was: {os.path.relpath(e["old"], S.MEDIA)}: {err}', flush=True)
                    continue
            S.place_covers(os.path.dirname(dest), cover)
            mark_downloaded(show["id"], e, dest)
            if n and n % 25 == 0:
                print(f"  {n} files moved ({time.time() - t0:.0f} s)", flush=True)
    aside = 0
    for show, _, broken, dupes, _ in p:
        for kind, files in (("duplicates", dupes), ("broken", broken)):
            for f in files:
                try:
                    put_aside(kind, show, f, jr)
                    aside += 1
                except OSError as err:
                    print(f"  !! couldn't set aside {os.path.relpath(f, S.MEDIA)}: {err} (left where it is)", flush=True)
    keep_pending = {e["guid"] for e, _ in failed}                  # their file is still where it was: don't download
    keep_pending |= {e["guid"] for _, eps, *_ in p for e in eps if e.get("stuck")}
    with S.lock, S.db() as c:
        for show, eps, *_ in p:
            for e in eps:
                if e["guid"] not in keep_pending:
                    c.execute("UPDATE episodes SET status='queued' WHERE show_id=? AND guid=? AND status='pending'",
                              (show["id"], e["guid"]))
    print(f"done: {n} files moved and retagged this run, {aside} duplicate/broken files set aside in {LEFTOVERS}/"
          f" ({time.time() - t0:.0f} s)")
    stuck = sum(1 for _, eps, *_ in p for e in eps if e.get("stuck"))
    if failed or stuck:
        print(f"!! {len(failed) + stuck} episodes were left as they were (kept 'pending'): fix the file (e.g. permissions)"
              f" and run --apply again.")
    lk.close()


def mark_downloaded(sid, e, dest):
    with S.lock, S.db() as c:
        c.execute("UPDATE episodes SET status='downloaded', path=?, size=?, done_at=? WHERE show_id=? AND guid=?",
                  (os.path.relpath(dest, S.MEDIA), os.path.getsize(dest), time.time(), sid, e["guid"]))


def undo():
    """Every journaled move back to its old name, with its original tags (v2 block + v1 trailer) and mtime, and every
    set-aside file back in place. Safe to kill and run again at any point."""
    if not os.path.exists(os.path.join(S.MEDIA, S.SENTINEL)):      # unmounted: every file would look gone and the journal would retire
        raise SystemExit(f"{S.MEDIA} has no {S.SENTINEL} file: is the media drive mounted?")
    lk = take_lock()
    if not os.path.exists(JOURNAL):
        print("nothing to undo (no journal)")
        return
    from mutagen.id3 import delete as id3_delete
    entries = list(journal().values())
    print(f"undoing {len(entries)} journaled files")
    for j in reversed(entries):
        new, old = j["new"], j["old"]
        if j["state"] == "aside":
            if os.path.exists(new) and not os.path.exists(old):
                os.rename(new, old)
            continue
        for leftover in (new + ".migrating", old + ".undo", old + ".undo2"):
            if os.path.exists(leftover):
                os.unlink(leftover)
        if os.path.exists(old):
            # the original was never deleted (crash during apply: 'start'), or a previous undo already put it back and
            # was killed before removing the new copy (size matches): either way the new copy is ours to drop
            if os.path.exists(new) and not done_owner(new, old) and (j["state"] == "start" or os.path.getsize(old) == j.get("size", -1)):
                set_mtime(old, j)
                os.unlink(new)
            continue
        if not os.path.exists(new):
            print(f"  !! neither {old} nor {new} exists; skipped")
            continue
        work = old + ".undo"
        try:
            copy_lowmem(new, work)
            if new.endswith(".mp3"):
                id3_delete(work, delete_v1=True, delete_v2=True)
                with open(j["tags"], "rb") as f:
                    block = f.read()
                v1 = b""
                if os.path.exists(j["tags"] + ".v1"):
                    with open(j["tags"] + ".v1", "rb") as f:
                        v1 = f.read()
                with open(work, "rb") as src, open(old + ".undo2", "wb") as dst:   # streamed: episodes can be 400+ MB
                    dst.write(block)
                    shutil.copyfileobj(src, dst, 1 << 20)
                    dst.write(v1)
                os.replace(old + ".undo2", work)
            with open(work, "rb+") as f:
                os.fsync(f.fileno())
            os.replace(work, old)
            set_mtime(old, j)
            os.unlink(new)
        finally:
            for leftover in (work, old + ".undo2"):
                if os.path.exists(leftover):
                    os.unlink(leftover)
    for album in sorted({os.path.dirname(j["new"]) for j in entries if j["state"] != "aside"}):   # year folders, if empty
        left = set(os.listdir(album)) if os.path.isdir(album) else {"?"}
        if left <= {"cover.jpg", "cover.jpg.part"}:
            for f in left:
                os.unlink(os.path.join(album, f))
            os.rmdir(album)
            show_dir = os.path.dirname(album)
            if not any(d for d in os.listdir(show_dir) if os.path.isdir(os.path.join(show_dir, d)) and d != "images"):
                for f in ("artist.jpg", "artist.jpg.part"):
                    try:
                        os.unlink(os.path.join(show_dir, f))
                    except OSError:
                        pass
    for show_dir in sorted({os.path.dirname(j["new"]) for j in entries if j["state"] != "aside"}):
        if os.path.isdir(show_dir) and not any(re.match(r"\d{3,} - \d{4}-\d\d-\d\d - ", f) for f in os.listdir(show_dir)):
            for f in ("cover.jpg", "artist.jpg", "cover.jpg.part", "artist.jpg.part"):
                try:
                    os.unlink(os.path.join(show_dir, f))
                except OSError:
                    pass
    lo = os.path.join(S.MEDIA, LEFTOVERS)
    for root, dirs, files in os.walk(lo, topdown=False):           # the leftovers folder, if now empty
        if not os.listdir(root):
            os.rmdir(root)
    os.replace(JOURNAL, JOURNAL + f".undone-{int(time.time())}")
    print("undo done. The new database still lists the shows (delete data/podcasts.db to forget them).")
    lk.close()


if __name__ == "__main__":
    if "--undo" in sys.argv:
        undo()
    else:
        p = plan()
        report(p)
        if "--apply" in sys.argv:
            print("\nAPPLYING ...", flush=True)
            apply(p)
        else:
            print("\nDry run only: nothing was changed. Add --apply to do it.")
