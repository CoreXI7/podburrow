"""Failure handling of server.py.

These tests never touch the network, never start the worker loop and never start
the HTTP server.  DATA and MEDIA are pointed at throwaway temp folders *before*
server is imported, because server reads both at import time.

Run with:  python -m unittest test_failures   (or: python test_failures.py)
"""
import atexit
import errno
import os
import shutil
import socket
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

_DATA = tempfile.mkdtemp(prefix="podcasts-test-data-")
_MEDIA = tempfile.mkdtemp(prefix="podcasts-test-media-")
os.environ["DATA"] = _DATA
os.environ["MEDIA"] = _MEDIA
os.environ.setdefault("ALLOWED_HOSTS", "localhost:8000")

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
sys.path.insert(0, _HERE)

import server  # noqa: E402  (the environment above is part of the setup)


def _drop_temps():
    for d in (_DATA, _MEDIA):
        shutil.rmtree(d, ignore_errors=True)


atexit.register(_drop_temps)

PUB = "2024-05-06T12:00:00+00:00"
MP3_HEAD = b"ID3" + b"\x00" * 4093          # exactly one 4096-byte sniff window


class FakeResponse:
    """Just the part of server.Response that download() uses."""

    def __init__(self, chunks, headers=None, url="http://localhost/ep.mp3"):
        self.chunks = list(chunks)
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.url = url
        self.closed = False

    def header(self, k):
        return self.headers.get(k.lower())

    def set_deadline(self, deadline, final=None):
        pass

    def read(self, n):
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if isinstance(chunk, BaseException):
            raise chunk
        return chunk

    def close(self):
        self.closed = True


class FailureHandlingTest(unittest.TestCase):
    def setUp(self):
        lockf = getattr(server, "_lockf", None)
        if lockf is not None:
            try:
                lockf.close()
            except OSError:
                pass
            server._lockf = None
        shutil.rmtree(server.DATA, ignore_errors=True)
        shutil.rmtree(server.MEDIA, ignore_errors=True)
        os.makedirs(server.DATA, exist_ok=True)
        os.makedirs(server.MEDIA, exist_ok=True)
        with open(os.path.join(server.MEDIA, server.SENTINEL), "w"):
            pass
        server.init_db()

    def tearDown(self):
        lockf = getattr(server, "_lockf", None)
        if lockf is not None:
            try:
                lockf.close()
            except OSError:
                pass
            server._lockf = None

    # ---------------------------------------------------------------- helpers
    def add_show(self, title="Show", folder=None, checking=0, paused=0, last_error=""):
        with server.lock, server.db() as c:
            return c.execute(
                "INSERT INTO shows (title, folder, feed_url, added_at, last_check, paused, checking, last_error) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (title, folder or title, "http://localhost/%s.xml" % title.lower().replace(" ", "-"),
                 time.time(), time.time(), paused, checking, last_error)).lastrowid

    def add_episode(self, sid, status="queued", path="", error="", tries=0, num=1,
                    title="Episode", pub=PUB, audio_url="http://localhost/a.mp3"):
        with server.lock, server.db() as c:
            return c.execute(
                "INSERT INTO episodes (show_id, guid, title, pub, audio_url, summary, num, status, path, error, tries) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (sid, "%s-%s" % (title, num), title, pub, audio_url, "", num, status, path, error, tries)).lastrowid

    def row_show(self, sid):
        with server.db() as c:
            return c.execute("SELECT * FROM shows WHERE id=?", (sid,)).fetchone()

    def row_episode(self, eid):
        with server.db() as c:
            return c.execute("SELECT * FROM episodes WHERE id=?", (eid,)).fetchone()

    def dest_for(self, sid, eid, ext="mp3"):
        return os.path.join(server.MEDIA, server.episode_path(self.row_show(sid), self.row_episode(eid), ext))

    # ---------------------------------------------------------------- media_ok / mark_missing
    def test_media_ok_requires_the_sentinel(self):
        sentinel = os.path.join(server.MEDIA, server.SENTINEL)
        self.assertTrue(server.media_ok())
        os.unlink(sentinel)
        self.assertFalse(server.media_ok())

    def test_mark_missing_does_nothing_when_the_drive_is_not_mounted(self):
        os.unlink(os.path.join(server.MEDIA, server.SENTINEL))
        sid = self.add_show()
        eid = self.add_episode(sid, status="downloaded", path="Show/2024/gone.mp3")
        server.mark_missing()
        self.assertEqual(self.row_episode(eid)["status"], "downloaded")

    def test_mark_missing_flags_deleted_files_only(self):
        sid = self.add_show()
        present = os.path.join(server.MEDIA, "Show", "2024", "here.mp3")
        os.makedirs(os.path.dirname(present))
        with open(present, "wb") as f:
            f.write(b"x")
        ok = self.add_episode(sid, status="downloaded", path=os.path.join("Show", "2024", "here.mp3"))
        gone = self.add_episode(sid, status="downloaded", path=os.path.join("Show", "2024", "gone.mp3"), num=2)
        blank = self.add_episode(sid, status="downloaded", path="", num=3)
        server.mark_missing()
        self.assertEqual(self.row_episode(ok)["status"], "downloaded")
        self.assertEqual(self.row_episode(gone)["status"], "missing")
        self.assertEqual(self.row_episode(gone)["error"], "file deleted from disk")
        self.assertEqual(self.row_episode(blank)["status"], "missing")

    # ---------------------------------------------------------------- stalls / oversized downloads
    def test_response_read_turns_a_stalled_socket_into_offline(self):
        inner, conn, guard = mock.Mock(), mock.Mock(), mock.Mock()
        guard.expired = False
        resp = server.Response(inner, conn, "http://localhost/a.mp3", guard)
        inner.read.side_effect = socket.timeout("timed out")
        with self.assertRaises(server.Offline):
            resp.read(10)

    def test_response_read_uses_the_guard_reason_once_it_expired(self):
        inner, conn, guard = mock.Mock(), mock.Mock(), mock.Mock()
        guard.expired = True
        guard.why.return_value = server.Blocked("took too long (over the time limit)")
        resp = server.Response(inner, conn, "http://localhost/a.mp3", guard)
        inner.read.side_effect = OSError("connection reset")
        with self.assertRaises(server.Blocked) as caught:
            resp.read(10)
        self.assertIn("took too long", str(caught.exception))

    def test_stalled_download_keeps_nothing_on_disk(self):
        sid = self.add_show(folder="Show")
        eid = self.add_episode(sid, status="downloading")
        dest = self.dest_for(sid, eid)
        resp = FakeResponse([MP3_HEAD, server.Offline("no data for 10 minutes")])
        with mock.patch.object(server, "fetch", return_value=resp):
            with self.assertRaises(server.Offline):
                server.download(eid)
        self.assertTrue(resp.closed)
        self.assertFalse(os.path.exists(dest + ".part"))
        self.assertFalse(os.path.exists(dest))

    def test_oversized_download_is_refused_from_content_length(self):
        sid = self.add_show(folder="Show")
        eid = self.add_episode(sid, status="downloading")
        dest = self.dest_for(sid, eid)
        resp = FakeResponse([MP3_HEAD], headers={"Content-Length": str(server.AUDIO_MAX + 1)})
        with mock.patch.object(server, "fetch", return_value=resp):
            with self.assertRaises(server.Blocked) as caught:
                server.download(eid)
        self.assertIn("bigger than 2 GB", str(caught.exception))
        self.assertTrue(resp.closed)
        self.assertFalse(os.path.exists(dest + ".part"))

    def test_oversized_download_is_stopped_while_streaming(self):
        sid = self.add_show(folder="Show")
        eid = self.add_episode(sid, status="downloading")
        dest = self.dest_for(sid, eid)
        resp = FakeResponse([MP3_HEAD, b"\x02" * 8000])
        with mock.patch.object(server, "fetch", return_value=resp), \
                mock.patch.object(server, "AUDIO_MAX", 10_000):
            with self.assertRaises(server.Blocked) as caught:
                server.download(eid)
        self.assertIn("bigger than 2 GB", str(caught.exception))
        self.assertFalse(os.path.exists(dest + ".part"))

    # ---------------------------------------------------------------- full disk
    def test_full_disk_during_download_leaves_no_part_file(self):
        sid = self.add_show(folder="Show")
        eid = self.add_episode(sid, status="downloading")
        dest = self.dest_for(sid, eid)
        resp = FakeResponse([MP3_HEAD, b"\x01" * 1000])
        no_space = OSError(errno.ENOSPC, "No space left on device")
        # The worker pauses when shutil.disk_usage(MEDIA).free < MIN_FREE; if the disk fills between that
        # check and the write, the write itself raises ENOSPC.  Force both halves of the scenario here.
        with mock.patch.object(server, "fetch", return_value=resp), \
                mock.patch.object(server.shutil, "disk_usage",
                                  return_value=types.SimpleNamespace(free=0, total=0, used=0)), \
                mock.patch.object(server.os, "fsync", side_effect=no_space):
            with self.assertRaises(OSError) as caught:
                server.download(eid)
        self.assertEqual(caught.exception.errno, errno.ENOSPC)
        self.assertTrue(resp.closed)
        self.assertFalse(os.path.exists(dest))
        self.assertFalse(os.path.exists(dest + ".part"))
        # download() leaves the row for the worker's exception handler to mark failed.
        self.assertEqual(self.row_episode(eid)["status"], "downloading")

    # ---------------------------------------------------------------- startup: crash looping
    def test_startup_pauses_a_show_whose_check_crashed_twice(self):
        repeat = self.add_show("Repeat", checking=1, last_error=server.CRASH_CHECK + " (crash?)")
        first = self.add_show("First", checking=1)
        user = self.add_show("UserPaused", checking=1, paused=1, last_error="paused by hand")
        server.startup()
        r = self.row_show(repeat)
        self.assertEqual(r["paused"], 1)
        self.assertTrue(r["last_error"].startswith("paused automatically"))
        self.assertEqual(r["checking"], 0)
        f = self.row_show(first)
        self.assertEqual(f["paused"], 0)
        self.assertEqual(f["last_error"], server.CRASH_CHECK + " (crash?)")
        self.assertEqual(f["checking"], 0)
        u = self.row_show(user)
        self.assertEqual(u["paused"], 1)
        self.assertEqual(u["last_error"], "paused by hand")
        self.assertEqual(u["checking"], 0)

    def test_startup_fails_interrupted_downloads_and_pauses_the_repeat_offender(self):
        repeat = self.add_show("Repeat")
        e1 = self.add_episode(repeat, status="downloading", tries=2,
                              error=server.CRASH_DL + " (during this download)")
        first = self.add_show("FirstDownload")
        e2 = self.add_episode(first, status="downloading", tries=1)
        server.startup()
        r = self.row_show(repeat)
        self.assertEqual(r["paused"], 1)
        self.assertTrue(r["last_error"].startswith("paused automatically"))
        self.assertEqual(self.row_show(first)["paused"], 0)
        for eid in (e1, e2):
            ep = self.row_episode(eid)
            self.assertEqual(ep["status"], "failed")
            self.assertIn(server.CRASH_DL, ep["error"])
            self.assertGreater(ep["next_try"], time.time() + 800)

    # ---------------------------------------------------------------- startup: clean restart
    def test_clean_restart_requeues_an_interrupted_download(self):
        with open(server.CLEAN, "w"):
            pass
        sid = self.add_show(folder="Show", checking=1)
        eid = self.add_episode(sid, status="downloading", tries=3)
        eid0 = self.add_episode(sid, status="downloading", tries=0, num=2)
        server.startup()
        self.assertFalse(os.path.exists(server.CLEAN))
        show = self.row_show(sid)
        self.assertEqual(show["checking"], 0)
        self.assertEqual(show["paused"], 0)
        self.assertEqual(show["last_error"], "")
        ep = self.row_episode(eid)
        self.assertEqual(ep["status"], "queued")
        self.assertEqual(ep["tries"], 2)
        self.assertEqual(self.row_episode(eid0)["tries"], 0)

    # ---------------------------------------------------------------- startup: .part leftovers
    def test_startup_removes_part_files_only_inside_show_folders(self):
        self.add_show("Show", folder="Show")
        year = os.path.join(server.MEDIA, "Show", "2024")
        os.makedirs(year)
        in_year = os.path.join(year, "001 - 2024-01-01 - Ep.mp3.part")
        in_show = os.path.join(server.MEDIA, "Show", "cover.jpg.part")
        outside = os.path.join(server.MEDIA, "NotAShow", "keep.part")
        os.makedirs(os.path.dirname(outside))
        for p in (in_year, in_show, outside):
            with open(p, "wb") as f:
                f.write(b"x")
        server.startup()
        self.assertFalse(os.path.exists(in_year))
        self.assertFalse(os.path.exists(in_show))
        self.assertTrue(os.path.exists(outside))

    # ---------------------------------------------------------------- restart + resume
    def test_restart_clears_stale_part_then_resume_downloads(self):
        sid = self.add_show(folder="Show")
        eid = self.add_episode(sid, status="downloading", tries=1)
        rel = server.episode_path(self.row_show(sid), self.row_episode(eid), "mp3")
        dest = os.path.join(server.MEDIA, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest + ".part", "wb") as f:
            f.write(b"partial")

        server.startup()                                    # crash path: no .clean-exit
        self.assertFalse(os.path.exists(dest + ".part"))
        self.assertEqual(self.row_episode(eid)["status"], "failed")

        server.act({"action": "retry", "id": eid})          # user clicks Retry / the app resumes it
        self.assertEqual(self.row_episode(eid)["status"], "queued")

        resp = FakeResponse([MP3_HEAD, b"\x33" * 200_000])
        with mock.patch.object(server, "fetch", return_value=resp), \
                mock.patch.object(server, "write_tags"):
            server.download(eid)

        done = self.row_episode(eid)
        self.assertEqual(done["status"], "downloaded")
        self.assertEqual(done["path"], rel)
        self.assertTrue(os.path.exists(dest))
        self.assertFalse(os.path.exists(dest + ".part"))
        self.assertGreaterEqual(done["size"], 100_000)


if __name__ == "__main__":
    unittest.main()
