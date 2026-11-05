#!/usr/bin/env python3
"""Writes the Plex tags into one audio file, in its own process with a hard memory cap (Claude, 2026-10-27).

server.write_tags() runs this as `python3 -I tagger.py` with a JSON job on stdin. A hostile file (e.g. a compressed ID3
frame that inflates to hundreds of MB) then only kills this helper with MemoryError, never the podcasts server.
Exit code 0 = tagged; anything else = refuse the file. Only these fields are replaced: chapters etc. stay.
"""
import json, resource, sys

MEM = 200 << 20                                   # address-space cap for this helper


def tag(job):
    path, ext = job["path"], job["ext"]
    show, title, num, date, summary = job["show"], job["title"], job["num"], job["date"], job["summary"]
    album = f"{show} {date[:4]}"                  # one album per year
    cover = b""
    if job.get("cover"):
        with open(job["cover"], "rb") as f:
            cover = f.read()
    png = cover.startswith(b"\x89PNG")
    if ext == "mp3":
        from mutagen.id3 import ID3, ID3NoHeaderError, TPE1, TPE2, TALB, TIT2, TRCK, TPOS, TDRC, TCON, COMM, APIC
        try:
            t = ID3(path)
        except ID3NoHeaderError:
            t = ID3()
        for k in ("TPE1", "TPE2", "TALB", "TIT2", "TRCK", "TPOS", "TDRC", "TCON", "TCMP", "TSO2", "TSOP", "TSOA", "TSOT",
                  "COMM", "APIC", "TXXX:compilation"):
            t.delall(k)
        t.add(TPE1(encoding=3, text=show)); t.add(TPE2(encoding=3, text=show))
        t.add(TALB(encoding=3, text=album)); t.add(TIT2(encoding=3, text=title))
        t.add(TRCK(encoding=3, text=str(num))); t.add(TPOS(encoding=3, text="1"))
        t.add(TDRC(encoding=3, text=date)); t.add(TCON(encoding=3, text="Podcast"))
        if summary:
            t.add(COMM(encoding=3, lang="eng", desc="", text=summary[:1000]))
        if cover:
            t.add(APIC(encoding=3, mime="image/png" if png else "image/jpeg", type=3, desc="Cover", data=cover))
        t.save(path, v2_version=4)                # v1=1 (default): an existing ID3v1 tag is rewritten to match
    elif ext == "m4a":
        from mutagen.mp4 import MP4, MP4Cover
        m = MP4(path)
        if m.tags is None:
            m.add_tags()
        for k in ("soar", "soaa", "soal", "sonm", "cpil"):
            m.tags.pop(k, None)
        m.tags["\xa9ART"] = [show]; m.tags["aART"] = [show]; m.tags["\xa9alb"] = [album]
        m.tags["\xa9nam"] = [title]; m.tags["trkn"] = [(num, 0)]; m.tags["disk"] = [(1, 1)]
        m.tags["\xa9day"] = [date]; m.tags["\xa9gen"] = ["Podcast"]
        if summary:
            m.tags["\xa9cmt"] = [summary[:1000]]
        if cover:
            m.tags["covr"] = [MP4Cover(cover, MP4Cover.FORMAT_PNG if png else MP4Cover.FORMAT_JPEG)]
        m.save()
    elif ext in ("ogg", "opus"):
        import mutagen
        m = mutagen.File(path)
        if m is None:
            raise ValueError("not readable audio")
        if m.tags is None:
            m.add_tags()
        for k in ("albumartistsort", "artistsort", "albumsort", "compilation"):
            if k in m.tags:                       # VComment is a list: no pop(k, default)
                del m.tags[k]
        m.tags.update({"artist": show, "albumartist": show, "album": album, "title": title, "tracknumber": str(num),
                       "discnumber": "1", "date": date, "genre": "Podcast"})
        m.save()
    # aac (raw ADTS) has no tag format; Plex then goes by the folders


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_AS, (MEM, MEM))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 65))
    try:
        tag(json.loads(sys.stdin.read(1 << 20)))
    except MemoryError:
        print("tagging needed too much memory (hostile or broken file)", file=sys.stderr)
        sys.exit(3)
    except Exception as e:
        print(f"{type(e).__name__}: {e}"[:300], file=sys.stderr)
        sys.exit(2)
