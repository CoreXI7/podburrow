"""Conditional feed checks: an unchanged feed answers 304 and isn't downloaded or parsed again."""
import atexit
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

_ROOT = tempfile.mkdtemp(prefix="podburrow-cond-")
os.environ["DATA"] = os.path.join(_ROOT, "data")
os.environ["MEDIA"] = os.path.join(_ROOT, "media")
os.makedirs(os.environ["DATA"])
os.makedirs(os.environ["MEDIA"])
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

import server

atexit.register(shutil.rmtree, _ROOT, True)

ETAG = '"abc123"'
DATE = "Wed, 04 Nov 2026 08:00:01 GMT"


class FakeResponse:
    def __init__(self, status=200, headers=None):
        self.status, self.headers, self.closed = status, dict(headers or {}), False

    def getheader(self, k, default=None):
        return next((v for key, v in self.headers.items() if key.lower() == k.lower()), default)

    def read(self, n=-1):
        return b""

    def close(self):
        self.closed = True


class FakeConn:
    responses, instances = [], []

    def __init__(self, host, port, addr, timeout):
        self.host, self.requests, self.closed = host, [], False
        FakeConn.instances.append(self)

    def request(self, method, path, headers=None):
        self.requests.append(dict(headers or {}))

    def getresponse(self):
        return FakeConn.responses.pop(0)

    def close(self):
        self.closed = True


class FakeGuard:
    def __init__(self, conn, deadline):
        self.expired = False

    def cancel(self):
        pass


class FetchTests(unittest.TestCase):
    def setUp(self):
        FakeConn.responses, FakeConn.instances = [], []
        self.patches = [mock.patch.object(server, "_PinnedHTTP", FakeConn),
                        mock.patch.object(server, "_PinnedHTTPS", FakeConn),
                        mock.patch.object(server, "Guard", FakeGuard),
                        mock.patch.object(server, "public_addr", return_value=("93.184.216.34", 443))]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()

    def test_validators_are_sent_and_304_is_returned(self):
        FakeConn.responses = [FakeResponse(304)]
        r = server.fetch("https://example.com/feed", validators={"etag": ETAG, "modified": DATE})
        self.assertEqual(r.status, 304)
        h = FakeConn.instances[0].requests[0]
        self.assertEqual((h["If-None-Match"], h["If-Modified-Since"]), (ETAG, DATE))
        r.close()

    def test_validators_follow_redirects(self):
        FakeConn.responses = [FakeResponse(301, {"Location": "https://example.com/new"}), FakeResponse(304)]
        server.fetch("https://example.com/old", validators={"etag": ETAG}).close()
        self.assertEqual(FakeConn.instances[1].requests[0]["If-None-Match"], ETAG)

    def test_304_without_asking_is_an_error(self):
        for v in (None, {}, {"etag": "", "modified": ""}):
            with self.subTest(v=v):
                FakeConn.responses = [FakeResponse(304)]
                with self.assertRaises(server.Blocked):
                    server.fetch("https://example.com/feed", validators=v)

    def test_no_validators_means_no_conditional_headers(self):
        FakeConn.responses = [FakeResponse(200)]
        server.fetch("https://example.com/feed").close()
        h = FakeConn.instances[0].requests[0]
        self.assertNotIn("If-None-Match", h)
        self.assertNotIn("If-Modified-Since", h)

    def test_bad_validator_values_are_dropped(self):
        for bad in ('"a"\r\nX-Evil: 1', '"a"\n', "x" * 201, " leading", "café", "\x00", 123, None, ["x"]):
            with self.subTest(bad=bad):
                self.assertEqual(server.validator(bad), "")
        for wild in ("*", " *", "* "):
            self.assertEqual(server.validator(wild), "")       # If-None-Match: * matches any version: never 304 on it
        self.assertEqual(server.validator('"*"'), '"*"')
        self.assertEqual(server.validator(ETAG), ETAG)
        self.assertEqual(server.validator('W/"x y"'), 'W/"x y"')


class CheckShowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="podburrow-cond-case-")
        server.DATA = self.tmp
        server.DB = os.path.join(self.tmp, "podcasts.db")
        server.COVERS = os.path.join(self.tmp, "covers")
        server.init_db()
        with server.db() as c:
            self.sid = c.execute("INSERT INTO shows (title, folder, feed_url, added_at) VALUES ('S','S','https://e.test/f',0)").lastrowid
        os.makedirs(server.COVERS, exist_ok=True)
        with open(os.path.join(server.COVERS, f"{self.sid}.jpg"), "wb") as f:
            f.write(b"\xff\xd8cover")                         # a cover exists: check_show doesn't fetch one
        self.calls = []

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def row(self):
        with server.db() as c:
            return c.execute("SELECT * FROM shows WHERE id=?", (self.sid,)).fetchone()

    def run_check(self, status, headers=None, eps=None):
        def fake_fetch(url, validators=None, **kw):
            self.calls.append(validators)
            self.resp = FakeResponse(status, headers)
            return server.Response(self.resp, FakeConn("e.test", 443, None, 1), url, FakeGuard(None, 0))
        parsed = mock.Mock(return_value=({"title": "S", "author": "", "image_url": ""}, eps or []))
        with mock.patch.object(server, "fetch", side_effect=fake_fetch), \
                mock.patch.object(server, "read_capped", return_value=b"<rss/>"), \
                mock.patch.object(server, "parse_feed_safe", parsed):
            server.check_show(self.sid)
        return parsed

    def test_first_check_stores_validators(self):
        self.run_check(200, {"ETag": ETAG, "Last-Modified": DATE})
        r = self.row()
        self.assertEqual((r["etag"], r["modified"]), (ETAG, DATE))
        self.assertGreater(r["fetched_at"], 0)
        self.assertIsNone(self.calls[0])                       # nothing known yet: a plain GET

    def test_unchanged_feed_is_not_parsed(self):
        self.run_check(200, {"ETag": ETAG, "Last-Modified": DATE})
        fetched = self.row()["fetched_at"]
        parsed = self.run_check(304)
        self.assertEqual(self.calls[1], {"etag": ETAG, "modified": DATE})
        parsed.assert_not_called()
        self.assertTrue(self.resp.closed)                      # the 304's connection isn't left open
        r = self.row()
        self.assertEqual((r["last_error"], r["etag"], r["fetched_at"]), ("", ETAG, fetched))

    def test_full_fetch_at_least_daily(self):
        self.run_check(200, {"ETag": ETAG})
        with server.db() as c:
            c.execute("UPDATE shows SET fetched_at=? WHERE id=?", (time.time() - 86401, self.sid))
        self.run_check(200, {"ETag": ETAG})
        self.assertIsNone(self.calls[1])

    def test_changed_feed_replaces_validators(self):
        self.run_check(200, {"ETag": ETAG})
        self.run_check(200, {"ETag": '"new"'})
        self.assertEqual((self.row()["etag"], self.row()["modified"]), ('"new"', ""))

    def test_capped_check_keeps_no_validators(self):
        eps = [{"guid": f"g{i}", "title": f"E{i}", "pub": f"2020-01-01T00:{i // 60:02d}:{i % 60:02d}+00:00",
                "audio_url": f"https://e.test/{i}.mp3", "summary": ""} for i in range(server.NEW_PER_CHECK + 5)]
        self.run_check(200, {"ETag": ETAG, "Last-Modified": DATE}, eps)
        self.assertEqual((self.row()["etag"], self.row()["modified"]), ("", ""))   # the rest must come next check
        self.run_check(200, {"ETag": ETAG}, eps)
        self.assertEqual(self.calls[1], {"etag": "", "modified": ""})
        with server.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM episodes").fetchone()[0], server.NEW_PER_CHECK + 5)

    def test_bad_etag_from_host_is_not_stored_or_sent(self):
        self.run_check(200, {"ETag": '"a"\r\nX-Evil: 1', "Last-Modified": "caf\u00e9"})
        self.assertEqual((self.row()["etag"], self.row()["modified"]), ("", ""))
        with mock.patch.object(server, "validator", side_effect=lambda v: v if isinstance(v, str) else ""):
            self.run_check(200)                                # even with the send-side check gone, nothing bad was kept
        self.assertEqual(self.calls[1], {"etag": "", "modified": ""})

    def test_check_now_is_a_full_fetch(self):
        self.run_check(200, {"ETag": ETAG})
        def fake_fetch(url, validators=None, **kw):
            self.calls.append(validators)
            return server.Response(FakeResponse(200), FakeConn("e.test", 443, None, 1), url, FakeGuard(None, 0))
        with mock.patch.object(server, "fetch", side_effect=fake_fetch), \
                mock.patch.object(server, "read_capped", return_value=b"<rss/>"), \
                mock.patch.object(server, "parse_feed_safe", return_value=({"title": "S", "author": "", "image_url": ""}, [])):
            server.check_show(self.sid, full=True)
        self.assertIsNone(self.calls[1])
        server.full_now.clear()
        server.act({"action": "check"})
        self.assertTrue(server.full_now.is_set())
        for e in (server.full_now, server.check_now, server.queue_now):
            e.clear()

    def test_future_fetched_at_is_not_fresh(self):
        self.run_check(200, {"ETag": ETAG})
        with server.db() as c:
            c.execute("UPDATE shows SET fetched_at=? WHERE id=?", (time.time() + 30 * 86400, self.sid))
        self.run_check(200, {"ETag": ETAG})
        self.assertIsNone(self.calls[1])

    def test_failed_check_makes_the_next_one_full(self):
        self.run_check(200, {"ETag": ETAG})
        with mock.patch.object(server, "parse_feed_safe", side_effect=server.Blocked("bad xml")), \
                mock.patch.object(server, "read_capped", return_value=b"x"), \
                mock.patch.object(server, "fetch", return_value=server.Response(
                    FakeResponse(200), FakeConn("e.test", 443, None, 1), "u", FakeGuard(None, 0))):
            server.check_show(self.sid)
        self.run_check(200)                                    # the next check sends no validators: no 304 can hide it
        self.assertIsNone(self.calls[1])

    def test_failed_parse_keeps_old_validators_and_reports(self):
        self.run_check(200, {"ETag": ETAG})
        with mock.patch.object(server, "fetch", return_value=server.Response(
                FakeResponse(200, {"ETag": '"broken"'}), FakeConn("e.test", 443, None, 1), "u", FakeGuard(None, 0))), \
                mock.patch.object(server, "read_capped", return_value=b"x"), \
                mock.patch.object(server, "parse_feed_safe", side_effect=server.Blocked("feed isn't valid XML")):
            server.check_show(self.sid)
        r = self.row()
        self.assertEqual((r["etag"], r["last_error"]), (ETAG, "feed isn't valid XML"))


if __name__ == "__main__":
    unittest.main()
