import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

TMP = tempfile.mkdtemp(prefix="podcasts-test-")
os.environ["DATA"] = os.path.join(TMP, "data")
os.environ["MEDIA"] = os.path.join(TMP, "media")
os.makedirs(os.environ["DATA"], exist_ok=True)
os.makedirs(os.environ["MEDIA"], exist_ok=True)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import mutagen
    HAVE_MUTAGEN = True
except ImportError:
    HAVE_MUTAGEN = False

try:
    import tagger
except Exception:
    tagger = None

try:
    import server
except Exception:
    server = None


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


@unittest.skipUnless(HAVE_MUTAGEN and tagger is not None, "mutagen or tagger not available")
class TaggerTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=TMP)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def path(self, name="ep.mp3", data=b""):
        p = os.path.join(self.dir, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def job(self, path, ext="mp3", **kw):
        job = {"path": path, "ext": ext, "show": "Show", "title": "Episode", "num": 7,
               "date": "2024-03-04", "summary": "Summary", "cover": ""}
        job.update(kw)
        return job

    def test_mp3_writes_expected_tags(self):
        from mutagen.id3 import ID3
        p = self.path()
        tagger.tag(self.job(p))
        t = ID3(p)
        self.assertEqual(t["TPE1"].text, ["Show"])
        self.assertEqual(t["TPE2"].text, ["Show"])
        self.assertEqual(t["TALB"].text, ["Show 2024"])
        self.assertEqual(t["TIT2"].text, ["Episode"])
        self.assertEqual(t["TRCK"].text, ["7"])
        self.assertEqual(t["TPOS"].text, ["1"])
        self.assertEqual([str(x) for x in t["TDRC"].text], ["2024-03-04"])
        self.assertEqual(t["TCON"].text, ["Podcast"])
        self.assertEqual(t.getall("COMM")[0].text, ["Summary"])

    def test_mp3_album_uses_date_year(self):
        from mutagen.id3 import ID3
        p = self.path()
        tagger.tag(self.job(p, date="2021-12-31"))
        self.assertEqual(ID3(p)["TALB"].text, ["Show 2021"])

    def test_mp3_summary_capped_at_1000(self):
        from mutagen.id3 import ID3
        p = self.path()
        tagger.tag(self.job(p, summary="s" * 1500))
        self.assertEqual(ID3(p).getall("COMM")[0].text, ["s" * 1000])

    def test_mp3_without_summary_has_no_comment(self):
        from mutagen.id3 import ID3
        p = self.path()
        tagger.tag(self.job(p, summary=""))
        self.assertEqual(ID3(p).getall("COMM"), [])

    def test_mp3_replaces_old_tags(self):
        from mutagen.id3 import ID3, TCMP, TCON, TPE1
        p = self.path()
        old = ID3()
        old.add(TPE1(encoding=3, text=["Old artist"]))
        old.add(TCMP(encoding=3, text=["1"]))
        old.add(TCON(encoding=3, text=["Old genre"]))
        old.save(p)
        tagger.tag(self.job(p))
        t = ID3(p)
        self.assertEqual(t["TPE1"].text, ["Show"])
        self.assertEqual(t["TCON"].text, ["Podcast"])
        self.assertEqual(t.getall("TCMP"), [])

    def test_mp3_embeds_cover(self):
        from mutagen.id3 import ID3
        for name, mime, data in (("cover.png", "image/png", b"\x89PNG\r\n\x1a\nxy"),
                                 ("cover.jpg", "image/jpeg", b"\xff\xd8\xffxy")):
            with self.subTest(mime=mime):
                p = self.path(name=name + ".mp3")
                c = self.path(name=name, data=data)
                tagger.tag(self.job(p, cover=c))
                pic = ID3(p).getall("APIC")[0]
                self.assertEqual(pic.mime, mime)
                self.assertEqual(pic.data, data)

    def test_mp3_without_cover_has_no_picture(self):
        from mutagen.id3 import ID3
        p = self.path()
        tagger.tag(self.job(p))
        self.assertEqual(ID3(p).getall("APIC"), [])

    def test_corrupt_m4a_rejected(self):
        from mutagen import MutagenError
        p = self.path("bad.m4a", b"this is not an mp4 file")
        with self.assertRaises(MutagenError):
            tagger.tag(self.job(p, ext="m4a"))

    def test_corrupt_ogg_rejected(self):
        from mutagen import MutagenError
        p = self.path("bad.ogg", b"definitely not ogg data")
        with self.assertRaises((ValueError, MutagenError)):
            tagger.tag(self.job(p, ext="ogg"))

    def test_wrong_extension_m4a_rejects_mp3_bytes(self):
        from mutagen import MutagenError
        p = self.path("wrong.m4a", b"ID3\x04\x00\x00\x00\x00\x00\x00not audio")
        with self.assertRaises(MutagenError):
            tagger.tag(self.job(p, ext="m4a"))

    def test_aac_is_left_untouched(self):
        data = b"\xff\xf1\x50\x80" + b"\x00" * 100
        p = self.path("ep.aac", data)
        tagger.tag(self.job(p, ext="aac"))
        with open(p, "rb") as f:
            self.assertEqual(f.read(), data)


@unittest.skipUnless(server is not None, "server.py could not be imported")
class ServerTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=TMP)
        os.makedirs(server.COVERS, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def file(self, name, data):
        p = os.path.join(self.dir, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def show(self):
        return {"id": 1, "title": "Show", "folder": "Show"}

    def ep(self):
        return {"num": "12", "title": "Episode", "pub": "2024-03-04T12:00:00+00:00", "summary": ""}

    def album(self):
        show = os.path.join(self.dir, "Show")
        album = os.path.join(show, "2024")
        os.makedirs(album)
        return show, album

    def test_id3_size_zero_without_header(self):
        self.assertEqual(server.id3_size(self.file("a.mp3", b"not an id3 file")), 0)
        self.assertEqual(server.id3_size(self.file("b.mp3", b"ID3")), 0)

    def test_id3_size_reads_syncsafe_number(self):
        p = self.file("a.mp3", b"ID3\x04\x00\x00\x00\x00\x02\x01")
        self.assertEqual(server.id3_size(p), 257)

    def test_id3_size_reports_oversized_claim(self):
        p = self.file("a.mp3", b"ID3\x04\x00\x00\x7f\x7f\x7f\x7f")
        self.assertEqual(server.id3_size(p), 0x0FFFFFFF)
        self.assertGreater(server.id3_size(p), server.TAG_MAX)

    def test_cover_file_missing_is_empty(self):
        self.assertEqual(server.cover_file(999999), "")

    def test_cover_file_returns_existing_file(self):
        p = os.path.join(server.COVERS, "42.jpg")
        with open(p, "wb") as f:
            f.write(b"\xff\xd8")
        self.addCleanup(lambda: os.path.exists(p) and os.unlink(p))
        self.assertEqual(server.cover_file(42), p)
        self.assertEqual(server.cover_file("42"), p)

    def test_create_new_replaces_existing_file(self):
        p = self.file("x.mp3", b"old contents")
        with server.create_new(p) as f:
            f.write(b"new")
        with open(p, "rb") as f:
            self.assertEqual(f.read(), b"new")

    def test_create_new_does_not_follow_symlink(self):
        target = self.file("target.bin", b"keep me")
        link = os.path.join(self.dir, "link.mp3")
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not available")
        with server.create_new(link) as f:
            f.write(b"fresh")
        self.assertFalse(os.path.islink(link))
        with open(link, "rb") as f:
            self.assertEqual(f.read(), b"fresh")
        with open(target, "rb") as f:
            self.assertEqual(f.read(), b"keep me")

    def test_place_covers_writes_album_and_artist(self):
        show, album = self.album()
        cover = b"\xff\xd8cover"
        server.place_covers(album, cover)
        for p in (os.path.join(album, "cover.jpg"), os.path.join(show, "artist.jpg")):
            with open(p, "rb") as f:
                self.assertEqual(f.read(), cover)
        self.assertFalse(os.path.exists(os.path.join(album, "cover.jpg.part")))

    def test_place_covers_keeps_existing_files(self):
        show, album = self.album()
        with open(os.path.join(album, "cover.jpg"), "wb") as f:
            f.write(b"old cover")
        server.place_covers(album, b"new cover")
        with open(os.path.join(album, "cover.jpg"), "rb") as f:
            self.assertEqual(f.read(), b"old cover")
        with open(os.path.join(show, "artist.jpg"), "rb") as f:
            self.assertEqual(f.read(), b"new cover")
        with open(os.path.join(show, "artist.jpg"), "wb") as f:
            f.write(b"old artist")
        server.place_covers(album, b"newer cover")
        with open(os.path.join(show, "artist.jpg"), "rb") as f:
            self.assertEqual(f.read(), b"old artist")

    def test_place_covers_without_cover_does_nothing(self):
        show, album = self.album()
        server.place_covers(album, b"")
        self.assertEqual(os.listdir(album), [])

    def test_write_tags_refuses_oversized_id3(self):
        p = self.file("big.mp3", b"ID3\x04\x00\x00\x7f\x7f\x7f\x7f")
        with mock.patch.object(server.subprocess, "run") as run:
            with self.assertRaises(server.Blocked):
                server.write_tags(p, "mp3", self.show(), self.ep(), "")
            run.assert_not_called()

    def test_write_tags_passes_job_to_tagger(self):
        p = self.file("ep.mp3", b"no tag here")
        done = mock.Mock(returncode=0, stderr=b"")
        with mock.patch.object(server.subprocess, "run", return_value=done) as run:
            server.write_tags(p, "mp3", self.show(), self.ep(), "")
        cmd = run.call_args.args[0]
        self.assertEqual(os.path.basename(cmd[-1]), "tagger.py")
        job = json.loads(run.call_args.kwargs["input"].decode())
        self.assertEqual(job["path"], p)
        self.assertEqual(job["ext"], "mp3")
        self.assertEqual(job["show"], "Show")
        self.assertEqual(job["title"], "Episode")
        self.assertEqual(job["num"], 12)
        self.assertEqual(job["date"], server.local(self.ep()["pub"]).date().isoformat())
        self.assertEqual(job["summary"], "")
        self.assertEqual(job["cover"], "")

    def test_write_tags_embeds_small_cover(self):
        p = self.file("ep.mp3", b"no tag here")
        c = self.file("cover.jpg", b"\xff\xd8small")
        done = mock.Mock(returncode=0, stderr=b"")
        with mock.patch.object(server.subprocess, "run", return_value=done) as run:
            server.write_tags(p, "mp3", self.show(), self.ep(), c)
        job = json.loads(run.call_args.kwargs["input"].decode())
        self.assertEqual(job["cover"], c)

    def test_write_tags_drops_big_cover(self):
        p = self.file("ep.mp3", b"no tag here")
        c = self.file("big.jpg", b"\xff\xd8" + b"x" * server.EMBED_MAX)
        done = mock.Mock(returncode=0, stderr=b"")
        with mock.patch.object(server.subprocess, "run", return_value=done) as run:
            server.write_tags(p, "mp3", self.show(), self.ep(), c)
        job = json.loads(run.call_args.kwargs["input"].decode())
        self.assertEqual(job["cover"], "")

    def test_write_tags_drops_missing_cover(self):
        p = self.file("ep.mp3", b"no tag here")
        done = mock.Mock(returncode=0, stderr=b"")
        with mock.patch.object(server.subprocess, "run", return_value=done) as run:
            server.write_tags(p, "mp3", self.show(), self.ep(), os.path.join(self.dir, "gone.jpg"))
        job = json.loads(run.call_args.kwargs["input"].decode())
        self.assertEqual(job["cover"], "")

    def test_write_tags_reports_tagger_failure(self):
        p = self.file("ep.mp3", b"no tag here")
        bad = mock.Mock(returncode=2, stderr=b"ValueError: bad\n")
        with mock.patch.object(server.subprocess, "run", return_value=bad):
            with self.assertRaises(server.Blocked) as cm:
                server.write_tags(p, "mp3", self.show(), self.ep(), "")
        self.assertIn("ValueError: bad", str(cm.exception))

    def test_write_tags_killed_tagger_is_offline(self):
        p = self.file("ep.mp3", b"no tag here")
        bad = mock.Mock(returncode=-9, stderr=b"")
        with mock.patch.object(server.subprocess, "run", return_value=bad):
            with self.assertRaises(server.Offline) as cm:
                server.write_tags(p, "mp3", self.show(), self.ep(), "")
        self.assertIn("signal 9", str(cm.exception))

    def test_write_tags_timeout_is_offline(self):
        p = self.file("ep.mp3", b"no tag here")
        with mock.patch.object(server.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("tagger.py", 300)):
            with self.assertRaises(server.Offline):
                server.write_tags(p, "mp3", self.show(), self.ep(), "")


if __name__ == "__main__":
    unittest.main()
