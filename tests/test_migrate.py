import atexit
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

BASE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(BASE, "..", "app")
TOOLS_DIR = os.path.join(BASE, "..", "tools")

DATA = tempfile.mkdtemp(prefix="migrate-test-data-")
MEDIA = tempfile.mkdtemp(prefix="migrate-test-media-")
os.environ["DATA"] = DATA
os.environ["MEDIA"] = MEDIA

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
sys.path.insert(0, TOOLS_DIR)

import migrate  # noqa: E402

S = migrate.S

atexit.register(shutil.rmtree, DATA, True)
atexit.register(shutil.rmtree, MEDIA, True)

try:
    import mutagen  # noqa: F401
    HAVE_MUTAGEN = True
except ImportError:
    HAVE_MUTAGEN = False


PODGRAB_SCHEMA = """
CREATE TABLE podcasts (
    id INTEGER PRIMARY KEY, title TEXT, author TEXT, image TEXT, url TEXT, deleted_at TEXT
);
CREATE TABLE podcast_items (
    id INTEGER PRIMARY KEY, podcast_id INTEGER NOT NULL, guid TEXT, title TEXT, summary TEXT,
    pub_date TEXT, file_url TEXT, download_path TEXT, download_status INTEGER,
    created_at TEXT, deleted_at TEXT
);
"""

ITEM_COLUMNS = ("podcast_id, guid, title, summary, pub_date, file_url, download_path, "
                "download_status, created_at, deleted_at")


def make_podgrab_db(path, shows, items):
    con = sqlite3.connect(path)
    try:
        con.executescript(PODGRAB_SCHEMA)
        con.executemany("INSERT INTO podcasts VALUES (?,?,?,?,?,?)", shows)
        con.executemany(f"INSERT INTO podcast_items ({ITEM_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?)", items)
        con.commit()
    finally:
        con.close()


class ReadPodgrabTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(dir=DATA)
        self.db_path = os.path.join(self.tmp, "podgrab.db")
        self._old_db = migrate.PODGRAB_DB
        migrate.PODGRAB_DB = self.db_path

    def tearDown(self):
        migrate.PODGRAB_DB = self._old_db
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_returns_live_shows_with_their_items(self):
        make_podgrab_db(
            self.db_path,
            [(1, "Show A", "Author A", "http://img/a.jpg", "http://feed/a", None),
             (2, "Gone Show", "", "", "http://feed/b", "2024-05-01 00:00:00")],
            [(1, "g1", "Ep One", "summary", "2024-01-01 00:00:00", "http://a/1.mp3",
              "/assets/Show A/ep1.mp3", 2, "2024-01-02 00:00:00", None),
             (2, "g2", "Deleted Ep", "", "2024-01-03 00:00:00", "http://a/2.mp3",
              "/assets/Gone Show/ep2.mp3", 2, "2024-01-04 00:00:00", "2024-06-01 00:00:00"),
             (3, "g3", "Deleted Item", "", "2024-01-05 00:00:00", "http://a/3.mp3",
              "/assets/Show A/ep3.mp3", 2, "2024-01-06 00:00:00", "2024-06-02 00:00:00")],
        )
        shows = migrate.read_podgrab()
        self.assertEqual([s["title"] for s in shows], ["Show A"])
        show = shows[0]
        self.assertEqual(show["author"], "Author A")
        self.assertEqual(show["image"], "http://img/a.jpg")
        self.assertEqual(show["url"], "http://feed/a")
        self.assertEqual([it["guid"] for it in show["items"]], ["g1"])
        self.assertEqual(set(show["items"][0]),
                         {"guid", "title", "summary", "pub_date", "file_url", "download_path",
                          "download_status", "created_at"})

    def test_sorts_items_by_publication_date(self):
        make_podgrab_db(
            self.db_path,
            [(1, "Show A", "", "", "http://feed/a", None)],
            [(1, "late", "Late", "", "2024-03-01 10:00:00", "http://a/3.mp3", None, 0, "2024-01-01 00:00:00", None),
             (1, "early", "Early", "", "2024-01-01T00:00:00+00:00", "http://a/1.mp3", None, 0, "2024-01-01 00:00:00", None),
             (1, "mid", "Mid", "", "2024-02-01 00:00:00", "http://a/2.mp3", None, 0, "2024-01-01 00:00:00", None)],
        )
        items = migrate.read_podgrab()[0]["items"]
        self.assertEqual([it["guid"] for it in items], ["early", "mid", "late"])

    def test_missing_database_raises(self):
        migrate.PODGRAB_DB = os.path.join(self.tmp, "missing.db")
        with self.assertRaises(sqlite3.OperationalError):
            migrate.read_podgrab()


class PodgrabFileTest(unittest.TestCase):
    def test_downloaded_file_inside_media(self):
        it = {"download_status": 2, "download_path": "/assets/My Show/2024/001 - A.mp3"}
        path = migrate.podgrab_file(it)
        self.assertEqual(path, os.path.realpath(os.path.join(MEDIA, "My Show", "2024", "001 - A.mp3")))

    def test_missing_file_still_returns_its_path(self):
        it = {"download_status": 2, "download_path": "/assets/Gone/2020/nope.mp3"}
        path = migrate.podgrab_file(it)
        assert path is not None
        self.assertFalse(os.path.exists(path))
        self.assertEqual(path, os.path.realpath(os.path.join(MEDIA, "Gone", "2020", "nope.mp3")))

    def test_not_downloaded_returns_none(self):
        for status in (0, 1, 3, None):
            it = {"download_status": status, "download_path": "/assets/x.mp3"}
            self.assertIsNone(migrate.podgrab_file(it))

    def test_path_outside_assets_returns_none(self):
        it = {"download_status": 2, "download_path": "/somewhere/x.mp3"}
        self.assertIsNone(migrate.podgrab_file(it))

    def test_relative_escape_is_blocked(self):
        it = {"download_status": 2, "download_path": "/assets/../../outside.mp3"}
        with self.assertRaises(S.Blocked):
            migrate.podgrab_file(it)

    def test_absolute_escape_is_blocked(self):
        it = {"download_status": 2, "download_path": "/assets//etc/passwd"}
        with self.assertRaises(S.Blocked):
            migrate.podgrab_file(it)


class JournalHelper(unittest.TestCase):
    def setUp(self):
        try:
            os.unlink(migrate.JOURNAL)
        except FileNotFoundError:
            pass

    def write_journal(self, *entries):
        with open(migrate.JOURNAL, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

    def read(self, path):
        with open(path, "rb") as f:
            return f.read()

    def write(self, path, data):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)


class JournalTest(JournalHelper):
    def test_last_state_wins_and_torn_lines_are_skipped(self):
        with open(migrate.JOURNAL, "w", encoding="utf-8") as f:
            f.write(json.dumps({"old": "/a", "new": "/b", "state": "start"}) + "\n")
            f.write('{"torn line\n')
            f.write(json.dumps({"old": "/a", "new": "/b", "state": "done"}) + "\n")
            f.write(json.dumps({"old": "/c", "new": "/d", "state": "aside"}) + "\n")
        journal = migrate.journal()
        self.assertEqual(journal["/a"]["state"], "done")
        self.assertEqual(journal["/c"]["new"], "/d")
        self.assertEqual(len(journal), 2)


class UndoTest(JournalHelper):
    def setUp(self):
        open(os.path.join(S.MEDIA, S.SENTINEL), "a").close()
        super().setUp()
        self.base = tempfile.mkdtemp(dir=MEDIA)

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_no_journal_is_a_no_op(self):
        migrate.undo()
        self.assertFalse(os.path.exists(migrate.JOURNAL))

    @unittest.skipUnless(HAVE_MUTAGEN, "migrate.undo() imports mutagen.id3")
    def test_restores_aside_file(self):
        old = os.path.join(self.base, "Podgrab", "Show", "ep.mp3")
        new = os.path.join(self.base, "leftovers", "duplicates", "Show", "ep.mp3")
        os.makedirs(os.path.dirname(old))
        self.write(new, b"duplicate")
        self.write_journal({"state": "aside", "old": old, "new": new})

        migrate.undo()

        self.assertEqual(self.read(old), b"duplicate")
        self.assertFalse(os.path.exists(new))
        self.assertFalse(os.path.exists(migrate.JOURNAL))

    @unittest.skipUnless(HAVE_MUTAGEN, "migrate.undo() imports mutagen.id3")
    def test_start_entry_keeps_original_and_drops_unfinished_copy(self):
        old = os.path.join(self.base, "Podgrab", "Show", "ep.mp3")
        new = os.path.join(self.base, "Show", "2024", "ep.mp3")
        self.write(old, b"original")
        self.write(new, b"half-tagged copy")
        self.write_journal({"state": "start", "old": old, "new": new, "size": len(b"original")})

        migrate.undo()

        self.assertEqual(self.read(old), b"original")
        self.assertFalse(os.path.exists(new))
        self.assertFalse(os.path.exists(migrate.JOURNAL))

    @unittest.skipUnless(HAVE_MUTAGEN, "migrate.undo() imports mutagen.id3")
    def test_copies_back_finished_non_mp3_move(self):
        old = os.path.join(self.base, "Podgrab", "Show", "ep.m4a")
        new = os.path.join(self.base, "Show", "2024", "ep.m4a")
        os.makedirs(os.path.dirname(old))
        self.write(new, b"tagged audio")
        self.write_journal({"state": "done", "old": old, "new": new, "size": len(b"tagged audio")})

        migrate.undo()

        self.assertEqual(self.read(old), b"tagged audio")
        self.assertFalse(os.path.exists(new))
        self.assertFalse(os.path.exists(migrate.JOURNAL))

    @unittest.skipUnless(HAVE_MUTAGEN, "migrate.undo() imports mutagen.id3")
    def test_missing_old_and_new_files_are_skipped(self):
        old = os.path.join(self.base, "Podgrab", "Show", "gone.mp3")
        new = os.path.join(self.base, "Show", "2024", "gone.mp3")
        self.write_journal({"state": "done", "old": old, "new": new})

        migrate.undo()

        self.assertFalse(os.path.exists(old))
        self.assertFalse(os.path.exists(new))
        self.assertFalse(os.path.exists(migrate.JOURNAL))


if __name__ == "__main__":
    unittest.main()
