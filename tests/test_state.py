import atexit
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager

_ROOT = tempfile.mkdtemp(prefix="podcasts-state-env-")
os.makedirs(os.path.join(_ROOT, "data"))
os.makedirs(os.path.join(_ROOT, "media"))
os.environ["DATA"] = os.path.join(_ROOT, "data")
os.environ["MEDIA"] = os.path.join(_ROOT, "media")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

import server

atexit.register(shutil.rmtree, _ROOT, True)


@contextmanager
def conn():
    c = server.db()
    try:
        with server.lock:
            yield c
        c.commit()
    finally:
        c.close()


class StateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="podcasts-state-")
        self.data = os.path.join(self.tmp, "data")
        self.media = os.path.join(self.tmp, "media")
        os.makedirs(self.data)
        os.makedirs(self.media)
        server.DATA = self.data
        server.DB = os.path.join(self.data, "podcasts.db")
        server.COVERS = os.path.join(self.data, "covers")
        server.MEDIA = self.media
        server.check_now.clear()
        server.queue_now.clear()
        server.init_db()

    def tearDown(self):
        server.check_now.clear()
        server.queue_now.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def add_show(self, title="Show", folder="Show",
                 feed_url="https://example.test/feed", paused=0, last_error=""):
        with conn() as c:
            return c.execute(
                "INSERT INTO shows (title, folder, feed_url, added_at, paused, last_error) "
                "VALUES (?,?,?,?,?,?)",
                (title, folder, feed_url, time.time(), paused, last_error)).lastrowid

    def add_ep(self, sid, guid="g1", title="Ep", pub="2024-01-02T00:00:00+00:00",
               audio_url="https://example.test/a.mp3", num=1, status="queued",
               path="", size=0, tries=0, next_try=0.0, error="", net_fails=0):
        with conn() as c:
            return c.execute(
                "INSERT INTO episodes (show_id, guid, title, pub, audio_url, num, status, "
                "path, size, tries, next_try, error, net_fails) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, guid, title, pub, audio_url, num, status, path, size, tries,
                 next_try, error, net_fails)).lastrowid

    def ep(self, guid="g1", title="Ep", pub="2024-01-02T00:00:00+00:00",
           url="https://example.test/a.mp3", summary=""):
        return {"guid": guid, "title": title, "pub": pub,
                "audio_url": url, "summary": summary}

    def rows(self, sql, args=()):
        with conn() as c:
            return c.execute(sql, args).fetchall()

    def row(self, sql, args=()):
        found = self.rows(sql, args)
        return found[0] if found else None

    def one(self, sql, args=()):
        with conn() as c:
            found = c.execute(sql, args).fetchone()
        if found is None:
            self.fail("no row for: " + sql)
        return found

    def test_init_db_creates_schema_defaults_and_covers(self):
        self.assertTrue(os.path.isdir(server.COVERS))
        self.assertTrue(os.path.exists(server.DB))
        names = {r["name"] for r in self.rows("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertLessEqual({"settings", "shows", "episodes"}, names)
        self.assertEqual(server.setting("check_minutes"), 240)
        self.assertEqual(server.setting("new_show"), "all")
        self.assertEqual(len(self.rows("SELECT k FROM settings")), 2)

    def test_init_db_is_idempotent(self):
        server.init_db()
        server.init_db()
        self.assertEqual(len(self.rows("SELECT k FROM settings")), 2)
        self.assertEqual(server.setting("check_minutes"), 240)

    def test_init_db_migrates_old_database(self):
        server.DB = os.path.join(self.data, "legacy.db")
        raw = sqlite3.connect(server.DB)
        raw.executescript("""
        CREATE TABLE shows (
            id INTEGER PRIMARY KEY, title TEXT NOT NULL, folder TEXT NOT NULL UNIQUE,
            feed_url TEXT NOT NULL UNIQUE, author TEXT DEFAULT '', image_url TEXT DEFAULT '',
            paused INTEGER DEFAULT 0, added_at REAL NOT NULL, last_check REAL DEFAULT 0,
            last_error TEXT DEFAULT '');
        CREATE TABLE episodes (
            id INTEGER PRIMARY KEY, show_id INTEGER NOT NULL REFERENCES shows(id) ON DELETE CASCADE,
            guid TEXT NOT NULL, title TEXT NOT NULL, pub TEXT NOT NULL, audio_url TEXT NOT NULL,
            summary TEXT DEFAULT '', num INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
            path TEXT DEFAULT '', size INTEGER DEFAULT 0, error TEXT DEFAULT '',
            tries INTEGER DEFAULT 0, done_at REAL DEFAULT 0, UNIQUE(show_id, guid));
        """)
        raw.commit()
        raw.close()
        server.init_db()
        show_cols = {r["name"] for r in self.rows("PRAGMA table_info(shows)")}
        ep_cols = {r["name"] for r in self.rows("PRAGMA table_info(episodes)")}
        self.assertIn("checking", show_cols)
        self.assertLessEqual({"next_try", "net_fails"}, ep_cols)
        self.assertEqual(server.setting("check_minutes"), 240)

    def test_setting_returns_defaults(self):
        self.assertEqual(server.setting("check_minutes"), 240)
        self.assertEqual(server.setting("new_show"), "all")

    def test_setting_returns_stored_value(self):
        with conn() as c:
            c.execute("UPDATE settings SET v=? WHERE k='check_minutes'", (json.dumps(45),))
        self.assertEqual(server.setting("check_minutes"), 45)
        self.assertIsInstance(server.setting("check_minutes"), int)

    def test_setting_unknown_key_raises_keyerror(self):
        with self.assertRaises(KeyError):
            server.setting("nope")

    def test_setting_bad_json_raises(self):
        with conn() as c:
            c.execute("UPDATE settings SET v='not json' WHERE k='check_minutes'")
        with self.assertRaises(json.JSONDecodeError):
            server.setting("check_minutes")

    def test_store_episodes_numbers_oldest_first_and_queues(self):
        sid = self.add_show()
        eps = [self.ep(guid="new", title="New", pub="2024-05-01T00:00:00+00:00", url="u2"),
               self.ep(guid="old", title="Old", pub="2023-01-01T00:00:00+00:00", url="u1")]
        with conn() as c:
            n = server.store_episodes(c, sid, eps)
        self.assertEqual(n, 2)
        rows = self.rows("SELECT guid, num, status FROM episodes WHERE show_id=? ORDER BY num", (sid,))
        self.assertEqual([r["guid"] for r in rows], ["old", "new"])
        self.assertEqual([r["num"] for r in rows], [1, 2])
        self.assertEqual({r["status"] for r in rows}, {"queued"})

    def test_store_episodes_queue_false_marks_skipped(self):
        sid = self.add_show()
        with conn() as c:
            n = server.store_episodes(c, sid, [self.ep()], queue=False)
        self.assertEqual(n, 1)
        self.assertEqual(self.one("SELECT status FROM episodes")["status"], "skipped")

    def test_store_episodes_limit_keeps_oldest(self):
        sid = self.add_show()
        eps = [self.ep(guid="c", pub="2022-01-01T00:00:00+00:00"),
               self.ep(guid="a", pub="2020-01-01T00:00:00+00:00"),
               self.ep(guid="b", pub="2021-01-01T00:00:00+00:00")]
        with conn() as c:
            n = server.store_episodes(c, sid, eps, limit=2)
        self.assertEqual(n, 2)
        rows = self.rows("SELECT guid, num FROM episodes ORDER BY num")
        self.assertEqual([r["guid"] for r in rows], ["a", "b"])
        self.assertEqual([r["num"] for r in rows], [1, 2])

    def test_store_episodes_dedupes_same_guid(self):
        sid = self.add_show()
        with conn() as c:
            server.store_episodes(c, sid, [self.ep(guid="same")])
        with conn() as c:
            n = server.store_episodes(c, sid, [self.ep(guid="same")])
        self.assertEqual(n, 0)
        self.assertEqual(len(self.rows("SELECT id FROM episodes")), 1)

    def test_store_episodes_dedupes_new_guid_same_date_and_title(self):
        sid = self.add_show()
        pub = "2024-01-02T00:00:00+00:00"
        with conn() as c:
            server.store_episodes(c, sid, [self.ep(guid="first", title="Same", pub=pub)])
        with conn() as c:
            n = server.store_episodes(c, sid, [self.ep(guid="second", title="Same", pub=pub)])
        self.assertEqual(n, 0)
        rows = self.rows("SELECT guid FROM episodes")
        self.assertEqual([r["guid"] for r in rows], ["first"])

    def test_store_episodes_numbering_continues(self):
        sid = self.add_show()
        self.add_ep(sid, guid="old", num=5, pub="2023-01-01T00:00:00+00:00")
        with conn() as c:
            server.store_episodes(c, sid, [self.ep(guid="new", pub="2024-01-01T00:00:00+00:00")])
        self.assertEqual(self.one("SELECT num FROM episodes WHERE guid='old'")["num"], 5)
        self.assertEqual(self.one("SELECT num FROM episodes WHERE guid='new'")["num"], 6)

    def test_store_episodes_skips_episode_missing_from_feed(self):
        sid = self.add_show()
        self.add_ep(sid, guid="gone", status="queued", audio_url="https://example.test/old")
        with conn() as c:
            server.store_episodes(c, sid, [self.ep(guid="fresh", title="Fresh", pub="2030-06-01T00:00:00+00:00")])
        gone = self.one("SELECT status, error FROM episodes WHERE guid='gone'")
        self.assertEqual(gone["status"], "skipped")
        self.assertEqual(gone["error"], "no longer in the feed")
        self.assertEqual(self.one("SELECT status FROM episodes WHERE guid='fresh'")["status"], "queued")

    def test_store_episodes_missing_show_raises_integrityerror(self):
        with conn() as c:
            with self.assertRaises(sqlite3.IntegrityError):
                server.store_episodes(c, 9999, [self.ep()])

    def test_store_episodes_missing_pub_raises_keyerror(self):
        sid = self.add_show()
        bad = {"guid": "g", "title": "t", "audio_url": "u", "summary": ""}
        with conn() as c:
            with self.assertRaises(KeyError):
                server.store_episodes(c, sid, [bad])

    def test_store_episodes_wrong_pub_type_raises_typeerror(self):
        sid = self.add_show()
        bad = {"guid": "g", "title": "t", "pub": None,
               "audio_url": "u", "summary": ""}
        with conn() as c:
            with self.assertRaises(TypeError):
                server.store_episodes(c, sid, [bad])

    def test_store_episodes_keeps_long_text_as_given(self):
        sid = self.add_show()
        title = "x" * 5000
        with conn() as c:
            n = server.store_episodes(c, sid, [self.ep(title=title)])
        self.assertEqual(n, 1)
        self.assertEqual(self.one("SELECT title FROM episodes")["title"], title)

    def test_refresh_links_updates_changed_url_and_requeues_failed(self):
        sid = self.add_show()
        pub = "2024-01-02T00:00:00+00:00"
        eid = self.add_ep(sid, guid="g", pub=pub, audio_url="https://old.test/a",
                          status="failed", tries=3, net_fails=2, error="boom",
                          next_try=time.time() + 5000)
        with conn() as c:
            server.refresh_links(c, sid, [self.ep(guid="g", pub=pub, url="https://new.test/a")])
        r = self.one("SELECT audio_url, status, tries, net_fails, next_try, error "
                     "FROM episodes WHERE id=?", (eid,))
        self.assertEqual(r["audio_url"], "https://new.test/a")
        self.assertEqual(r["status"], "queued")
        self.assertEqual(r["tries"], 0)
        self.assertEqual(r["net_fails"], 0)
        self.assertEqual(r["next_try"], 0)
        self.assertEqual(r["error"], "")

    def test_refresh_links_keeps_queued_status_when_url_changed(self):
        sid = self.add_show()
        pub = "2024-01-02T00:00:00+00:00"
        eid = self.add_ep(sid, guid="g", pub=pub, audio_url="https://old.test/a", tries=2)
        with conn() as c:
            server.refresh_links(c, sid, [self.ep(guid="g", pub=pub, url="https://new.test/a")])
        r = self.one("SELECT audio_url, status, tries FROM episodes WHERE id=?", (eid,))
        self.assertEqual(r["audio_url"], "https://new.test/a")
        self.assertEqual(r["status"], "queued")
        self.assertEqual(r["tries"], 0)

    def test_refresh_links_skips_episode_no_longer_in_feed(self):
        sid = self.add_show()
        eid = self.add_ep(sid, guid="gone", status="queued")
        with conn() as c:
            server.refresh_links(c, sid, [self.ep(guid="other", title="Other", pub="2031-01-01T00:00:00+00:00")])
        r = self.one("SELECT status, error FROM episodes WHERE id=?", (eid,))
        self.assertEqual(r["status"], "skipped")
        self.assertEqual(r["error"], "no longer in the feed")

    def test_refresh_links_skips_failed_episode_no_longer_in_feed(self):
        sid = self.add_show()
        eid = self.add_ep(sid, guid="gone", status="failed")
        with conn() as c:
            server.refresh_links(c, sid, [self.ep(guid="other", pub="2024-09-09T00:00:00+00:00")])
        self.assertEqual(self.one("SELECT status FROM episodes WHERE id=?", (eid,))["status"], "skipped")

    def test_refresh_links_leaves_downloaded_episodes_alone(self):
        sid = self.add_show()
        pub = "2024-01-02T00:00:00+00:00"
        eid = self.add_ep(sid, guid="g", pub=pub, audio_url="https://old.test/a", status="downloaded")
        with conn() as c:
            server.refresh_links(c, sid, [self.ep(guid="g", pub=pub, url="https://new.test/a")])
        r = self.one("SELECT audio_url, status FROM episodes WHERE id=?", (eid,))
        self.assertEqual(r["audio_url"], "https://old.test/a")
        self.assertEqual(r["status"], "downloaded")

    def test_refresh_links_matches_new_guid_by_date_and_title(self):
        sid = self.add_show()
        pub = "2024-01-02T00:00:00+00:00"
        eid = self.add_ep(sid, guid="old-id", title="Ep", pub=pub,
                          audio_url="https://old.test/a")
        with conn() as c:
            server.refresh_links(c, sid, [self.ep(guid="new-id", title="Ep", pub=pub,
                                                 url="https://new.test/a")])
        r = self.one("SELECT guid, audio_url FROM episodes WHERE id=?", (eid,))
        self.assertEqual(r["audio_url"], "https://new.test/a")
        self.assertEqual(r["guid"], "old-id")

    def test_refresh_links_does_not_judge_a_full_feed(self):
        sid = self.add_show()
        eid = self.add_ep(sid, guid="gone", status="queued")
        old = server.FEED_ITEMS
        server.FEED_ITEMS = 1
        try:
            with conn() as c:
                server.refresh_links(c, sid, [self.ep(guid="other", pub="2024-09-09T00:00:00+00:00")])
        finally:
            server.FEED_ITEMS = old
        self.assertEqual(self.one("SELECT status FROM episodes WHERE id=?", (eid,))["status"], "queued")

    def test_backoff_doubles_up_to_a_day(self):
        self.assertEqual(server.backoff(0), 900)
        self.assertEqual(server.backoff(1), 900)
        self.assertEqual(server.backoff(2), 1800)
        self.assertEqual(server.backoff(3), 3600)
        self.assertEqual(server.backoff(4), 7200)
        self.assertEqual(server.backoff(8), 86400)
        self.assertEqual(server.backoff(100), 86400)

    def test_backoff_caps_huge_tries(self):
        self.assertEqual(server.backoff(10 ** 6), 86400)

    def test_backoff_hopeless_errors_wait_a_week(self):
        self.assertEqual(server.backoff(1, "episode is bigger than 2 GB"), 7 * 86400)
        self.assertEqual(server.backoff(1, "took too long (over the time limit)"), 7 * 86400)
        self.assertEqual(server.backoff(1, "some other error"), 900)

    def test_mark_missing_does_nothing_without_media_sentinel(self):
        sid = self.add_show()
        eid = self.add_ep(sid, status="downloaded", path="Show/2024/a.mp3")
        server.mark_missing()
        self.assertEqual(self.one("SELECT status FROM episodes WHERE id=?", (eid,))["status"], "downloaded")

    def test_mark_missing_marks_deleted_files(self):
        open(os.path.join(server.MEDIA, server.SENTINEL), "w").close()
        sid = self.add_show()
        gone = self.add_ep(sid, guid="gone", status="downloaded", path="Show/2024/gone.mp3")
        kept_rel = "Show/2024/kept.mp3"
        os.makedirs(os.path.join(server.MEDIA, "Show", "2024"))
        open(os.path.join(server.MEDIA, kept_rel), "wb").close()
        kept = self.add_ep(sid, guid="kept", status="downloaded", path=kept_rel)
        server.mark_missing()
        g = self.one("SELECT status, error FROM episodes WHERE id=?", (gone,))
        self.assertEqual(g["status"], "missing")
        self.assertEqual(g["error"], "file deleted from disk")
        self.assertEqual(self.one("SELECT status FROM episodes WHERE id=?", (kept,))["status"], "downloaded")

    def test_mark_missing_empty_path_is_missing(self):
        open(os.path.join(server.MEDIA, server.SENTINEL), "w").close()
        sid = self.add_show()
        eid = self.add_ep(sid, status="downloaded", path="")
        server.mark_missing()
        self.assertEqual(self.one("SELECT status FROM episodes WHERE id=?", (eid,))["status"], "missing")

    def test_mark_missing_ignores_other_statuses(self):
        open(os.path.join(server.MEDIA, server.SENTINEL), "w").close()
        sid = self.add_show()
        eid = self.add_ep(sid, guid="q", status="queued", path="Show/2024/gone.mp3")
        server.mark_missing()
        self.assertEqual(self.one("SELECT status FROM episodes WHERE id=?", (eid,))["status"], "queued")

    def test_state_empty(self):
        s = server.state()
        self.assertEqual(s["shows"], [])
        self.assertIsInstance(s["free"], int)
        self.assertGreater(s["free"], 0)
        self.assertGreaterEqual(s["total"], s["free"])
        self.assertEqual(s["settings"], {"check_minutes": 240, "new_show": "all"})
        self.assertIs(s["status"], server.status)
        self.assertLess(abs(s["now"] - time.time()), 10)

    def test_state_counts_size_latest_and_cover(self):
        sid = self.add_show(title="Show A", folder="Show A", feed_url="https://example.test/a")
        self.add_ep(sid, guid="1", pub="2024-01-01T00:00:00+00:00", status="downloaded", size=10, num=1)
        self.add_ep(sid, guid="2", pub="2024-02-01T00:00:00+00:00", status="downloaded", size=20, num=2)
        self.add_ep(sid, guid="3", pub="2024-03-01T00:00:00+00:00", status="queued", size=30, num=3)
        open(os.path.join(server.COVERS, "%s.jpg" % sid), "wb").close()
        show = server.state()["shows"][0]
        self.assertEqual(show["counts"], {"downloaded": 2, "queued": 1})
        self.assertEqual(show["size"], 30)
        self.assertEqual(show["latest"], "2024-03-01T00:00:00+00:00")
        self.assertTrue(show["has_cover"])
        self.assertFalse(show["paused"])
        self.assertEqual(show["id"], sid)

    def test_state_sorts_shows_by_title_ignoring_case(self):
        self.add_show(title="beta", folder="beta", feed_url="https://example.test/b")
        self.add_show(title="Alpha", folder="Alpha", feed_url="https://example.test/a")
        titles = [x["title"] for x in server.state()["shows"]]
        self.assertEqual(titles, ["Alpha", "beta"])

    def test_episodes_newest_first_and_fields(self):
        sid = self.add_show()
        self.add_ep(sid, guid="jan", pub="2024-01-01T00:00:00+00:00", num=1)
        self.add_ep(sid, guid="mar", pub="2024-03-01T00:00:00+00:00", num=3)
        self.add_ep(sid, guid="feb", pub="2024-02-01T00:00:00+00:00", num=2)
        other = self.add_show(title="Other", folder="Other", feed_url="https://example.test/o")
        self.add_ep(other, guid="elsewhere", pub="2024-12-01T00:00:00+00:00")
        out = server.episodes(sid)
        self.assertEqual([e["pub"] for e in out],
                         ["2024-03-01T00:00:00+00:00", "2024-02-01T00:00:00+00:00",
                          "2024-01-01T00:00:00+00:00"])
        self.assertEqual(set(out[0]),
                         {"id", "num", "title", "pub", "status", "size", "error",
                          "tries", "next_try", "path"})

    def test_episodes_unknown_show_returns_empty(self):
        self.assertEqual(server.episodes(999), [])
        self.assertEqual(server.episodes("not-an-int"), [])

    def test_act_unknown_action_raises(self):
        with self.assertRaises(server.Blocked) as caught:
            server.act({"action": "bogus"})
        self.assertIn("unknown action", str(caught.exception))
        with self.assertRaises(server.Blocked):
            server.act({})

    def test_act_non_dict_body_raises(self):
        with self.assertRaises(AttributeError):
            server.act(None)
        with self.assertRaises(AttributeError):
            server.act([])

    def test_act_add_without_url_is_blocked(self):
        with self.assertRaises(server.Blocked) as caught:
            server.act({"action": "add"})
        self.assertIn("http", str(caught.exception))

    def test_act_check_sets_events(self):
        server.check_now.clear()
        server.queue_now.clear()
        self.assertEqual(server.act({"action": "check"}), {})
        self.assertTrue(server.check_now.is_set())
        self.assertTrue(server.queue_now.is_set())

    def test_act_pause_and_unpause(self):
        sid = self.add_show(title="S", folder="S", feed_url="https://example.test/s",
                            paused=0, last_error="paused automatically: twice")
        server.act({"action": "pause", "id": sid, "paused": True})
        r = self.one("SELECT paused, last_error FROM shows WHERE id=?", (sid,))
        self.assertEqual(r["paused"], 1)
        self.assertEqual(r["last_error"], "")
        server.act({"action": "pause", "id": sid, "paused": False})
        self.assertEqual(self.one("SELECT paused FROM shows WHERE id=?", (sid,))["paused"], 0)

    def test_act_unknown_show_id_is_noop(self):
        self.assertEqual(server.act({"action": "pause", "id": 9999, "paused": True}), {})
        self.assertEqual(server.act({"action": "remove", "id": 9999}), {})
        self.assertEqual(server.act({"action": "retry", "id": 9999}), {})
        self.assertEqual(server.act({"action": "retry_all", "id": 9999}), {})
        self.assertEqual(server.act({"action": "get_all", "id": 9999}), {})

    def test_act_remove_deletes_show_episodes_and_cover(self):
        sid = self.add_show(title="S", folder="S", feed_url="https://example.test/s")
        self.add_ep(sid, guid="e")
        cover = os.path.join(server.COVERS, "%s.jpg" % sid)
        open(cover, "wb").close()
        server.act({"action": "remove", "id": sid})
        self.assertEqual(self.rows("SELECT id FROM shows WHERE id=?", (sid,)), [])
        self.assertEqual(self.rows("SELECT id FROM episodes WHERE show_id=?", (sid,)), [])
        self.assertFalse(os.path.exists(cover))

    def test_act_retry_requeues_failed_episode(self):
        sid = self.add_show()
        eid = self.add_ep(sid, guid="f", status="failed", tries=3, net_fails=2,
                          error="boom", next_try=time.time() + 5000)
        server.act({"action": "retry", "id": eid})
        r = self.one("SELECT status, tries, net_fails, next_try, error FROM episodes WHERE id=?", (eid,))
        self.assertEqual(r["status"], "queued")
        self.assertEqual(r["tries"], 0)
        self.assertEqual(r["net_fails"], 0)
        self.assertEqual(r["next_try"], 0)
        self.assertEqual(r["error"], "")

    def test_act_retry_leaves_downloaded_episode(self):
        sid = self.add_show()
        eid = self.add_ep(sid, guid="d", status="downloaded")
        server.act({"action": "retry", "id": eid})
        self.assertEqual(self.one("SELECT status FROM episodes WHERE id=?", (eid,))["status"], "downloaded")

    def test_act_retry_all_only_failed(self):
        sid = self.add_show()
        failed = self.add_ep(sid, guid="f", status="failed")
        skipped = self.add_ep(sid, guid="s", status="skipped")
        queued = self.add_ep(sid, guid="q", status="queued")
        server.act({"action": "retry_all", "id": sid})
        self.assertEqual(self.one("SELECT status FROM episodes WHERE id=?", (failed,))["status"], "queued")
        self.assertEqual(self.one("SELECT status FROM episodes WHERE id=?", (skipped,))["status"], "skipped")
        self.assertEqual(self.one("SELECT status FROM episodes WHERE id=?", (queued,))["status"], "queued")

    def test_act_get_all_queues_skipped(self):
        sid = self.add_show()
        skipped = self.add_ep(sid, guid="s", status="skipped")
        queued = self.add_ep(sid, guid="q", status="queued")
        failed = self.add_ep(sid, guid="f", status="failed")
        server.act({"action": "get_all", "id": sid})
        self.assertEqual(self.one("SELECT status FROM episodes WHERE id=?", (skipped,))["status"], "queued")
        self.assertEqual(self.one("SELECT status FROM episodes WHERE id=?", (queued,))["status"], "queued")
        self.assertEqual(self.one("SELECT status FROM episodes WHERE id=?", (failed,))["status"], "failed")

    def test_act_settings_updates_values(self):
        self.assertEqual(server.act({"action": "settings", "check_minutes": 60, "new_show": "new"}), {})
        self.assertEqual(server.setting("check_minutes"), 60)
        self.assertEqual(server.setting("new_show"), "new")

    def test_act_settings_accepts_bounds(self):
        for minutes in (30, 1440):
            server.act({"action": "settings", "check_minutes": minutes})
            self.assertEqual(server.setting("check_minutes"), minutes)

    def test_act_settings_rejects_out_of_range_and_huge(self):
        for minutes in (0, 29, 1441, 10 ** 9):
            with self.assertRaises(server.Blocked):
                server.act({"action": "settings", "check_minutes": minutes})
        self.assertEqual(server.setting("check_minutes"), 240)

    def test_act_settings_missing_value_is_blocked(self):
        with self.assertRaises(server.Blocked):
            server.act({"action": "settings"})

    def test_act_settings_wrong_type_raises(self):
        with self.assertRaises(ValueError):
            server.act({"action": "settings", "check_minutes": "many"})

    def test_act_settings_ignores_bad_new_show(self):
        server.act({"action": "settings", "check_minutes": 90, "new_show": "bogus"})
        self.assertEqual(server.setting("check_minutes"), 90)
        self.assertEqual(server.setting("new_show"), "all")


if __name__ == "__main__":
    unittest.main()
