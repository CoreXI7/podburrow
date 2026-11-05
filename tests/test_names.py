"""Tests for the naming/path/date helpers in server.py.

The app modules live in ../app when the suite runs, so that folder is put on
sys.path before importing. DATA and MEDIA point at throwaway folders; nothing
here touches the network or the real library.
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

_TMP = tempfile.TemporaryDirectory(prefix="podcasts-test-")
os.environ["DATA"] = os.path.join(_TMP.name, "data")
os.environ["MEDIA"] = os.path.join(_TMP.name, "media")
os.makedirs(os.environ["DATA"])
os.makedirs(os.environ["MEDIA"])

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

import server


def _write(path, data):
    with open(path, "wb") as f:
        f.write(data)
    return path


class SafeNameTest(unittest.TestCase):
    def test_plain_name_kept(self):
        self.assertEqual(server.safe_name("My Show"), "My Show")

    def test_whitespace_collapsed(self):
        self.assertEqual(server.safe_name("a    b   c"), "a b c")

    def test_slashes_removed(self):
        self.assertEqual(server.safe_name("a/b\\c"), "abc")

    def test_parent_traversal_removed(self):
        self.assertEqual(server.safe_name("../etc/passwd"), "etcpasswd")
        self.assertEqual(server.safe_name("../"), "_")

    def test_absolute_path_becomes_plain_name(self):
        self.assertEqual(server.safe_name("/etc/passwd"), "etcpasswd")

    def test_windows_path_becomes_plain_name(self):
        self.assertEqual(server.safe_name("C:\\Windows\\System32"), "CWindowsSystem32")

    def test_control_chars_removed(self):
        self.assertEqual(server.safe_name("a\x00b\x1fc\x7fd"), "abcd")
        self.assertEqual(server.safe_name("a\tb\nc"), "abc")

    def test_colon_star_quotes_pipe_removed(self):
        self.assertEqual(server.safe_name('a:b*c?"d<e>f|g'), "abcdefg")

    def test_reserved_dos_names_prefixed(self):
        for name in ("CON", "con", "PRN", "AUX", "NUL", "COM0", "COM9", "LPT0", "LPT9"):
            self.assertEqual(server.safe_name(name), "_" + name)
        self.assertEqual(server.safe_name("con.txt"), "_con.txt")

    def test_non_reserved_dos_lookalikes_kept(self):
        self.assertEqual(server.safe_name("COM10"), "COM10")
        self.assertEqual(server.safe_name("CONSOLE"), "CONSOLE")

    def test_empty_and_dots_only_become_placeholder(self):
        self.assertEqual(server.safe_name(""), "_")
        self.assertEqual(server.safe_name("."), "_")
        self.assertEqual(server.safe_name(".."), "_")

    def test_trailing_dots_and_spaces_stripped(self):
        self.assertEqual(server.safe_name("  name...  "), "name")

    def test_long_ascii_name_capped_to_bytes(self):
        name = server.safe_name("a" * 300)
        self.assertEqual(name, "a" * server.NAME_BYTES)
        self.assertLessEqual(len(name.encode("utf-8")), server.NAME_BYTES)

    def test_long_utf8_name_capped_by_bytes(self):
        name = server.safe_name("\u00fc" * 200)
        self.assertEqual(len(name.encode("utf-8")), server.NAME_BYTES)
        self.assertEqual(name, "\u00fc" * (server.NAME_BYTES // 2))

    def test_custom_cap_respected(self):
        self.assertEqual(server.safe_name("abcdefgh", 3), "abc")


class CleanTextTest(unittest.TestCase):
    def test_tags_replaced_with_space(self):
        self.assertEqual(server.clean_text("<b>Hi</b> <i>there</i>"), "Hi there")
        self.assertEqual(server.clean_text("a<br>b"), "a b")

    def test_html_entities_decoded(self):
        self.assertEqual(server.clean_text("Tom &amp; Jerry &lt;3"), "Tom & Jerry <3")

    def test_control_chars_removed(self):
        self.assertEqual(server.clean_text("a\x00b\x07c\x0bd\x0ce\x7ff"), "abcdef")

    def test_whitespace_collapsed(self):
        self.assertEqual(server.clean_text("a\t b\n\nc\r\nd"), "a b c d")

    def test_cap_applied(self):
        self.assertEqual(server.clean_text("x" * 5000, 10), "x" * 10)

    def test_empty_and_none(self):
        self.assertEqual(server.clean_text(None), "")
        self.assertEqual(server.clean_text(""), "")


class ParseDateTest(unittest.TestCase):
    def test_rfc2822(self):
        self.assertEqual(
            server.parse_date("Mon, 01 Jan 2024 00:00:00 +0000"),
            datetime(2024, 1, 1, tzinfo=timezone.utc),
        )

    def test_rfc2822_offset(self):
        self.assertEqual(
            server.parse_date("Tue, 02 Jan 2024 03:00:00 +0300"),
            datetime(2024, 1, 2, tzinfo=timezone.utc),
        )

    def test_iso_with_z(self):
        self.assertEqual(
            server.parse_date("2024-01-01T12:00:00Z"),
            datetime(2024, 1, 1, 12, tzinfo=timezone.utc),
        )

    def test_iso_naive_is_utc(self):
        self.assertEqual(
            server.parse_date("2024-01-01T00:00:00"),
            datetime(2024, 1, 1, tzinfo=timezone.utc),
        )

    def test_date_only(self):
        self.assertEqual(
            server.parse_date("2024-01-01"),
            datetime(2024, 1, 1, tzinfo=timezone.utc),
        )

    def test_empty_and_junk_return_none(self):
        self.assertIsNone(server.parse_date(""))
        self.assertIsNone(server.parse_date(None))
        self.assertIsNone(server.parse_date("not a date"))

    def test_year_before_1970_rejected(self):
        self.assertIsNone(server.parse_date("1900-01-01T00:00:00Z"))

    def test_year_after_2100_rejected(self):
        self.assertIsNone(server.parse_date("2999-01-01T00:00:00Z"))

    def test_future_date_clamped_to_now(self):
        got = server.parse_date("2099-01-01T00:00:00Z")
        self.assertIsNotNone(got)
        if got is not None:
            self.assertLessEqual(got, datetime.now(timezone.utc))

    def test_result_is_aware_utc(self):
        got = server.parse_date("2024-06-01T00:00:00Z")
        self.assertIsNotNone(got)
        if got is not None:
            self.assertEqual(got.tzinfo, timezone.utc)


class LocalTest(unittest.TestCase):
    def test_aware_input_keeps_instant(self):
        got = server.local("2024-03-05T12:00:00+00:00")
        self.assertIsInstance(got, datetime)
        self.assertIsNotNone(got.tzinfo)
        self.assertIsNotNone(got.utcoffset())
        self.assertEqual(got.astimezone(timezone.utc), datetime(2024, 3, 5, 12, tzinfo=timezone.utc))

    def test_naive_input_gets_local_zone(self):
        got = server.local("2024-03-05T12:00:00")
        self.assertIsNotNone(got.tzinfo)
        self.assertIsNotNone(got.utcoffset())


class EpisodePathTest(unittest.TestCase):
    SHOW = {"folder": "My Show"}
    PUB = "2024-03-05T12:00:00+00:00"

    def _ep(self, title="An Episode", num=7, pub=None):
        return {"num": num, "title": title, "pub": pub or self.PUB}

    def test_layout(self):
        got = server.episode_path(self.SHOW, self._ep(), "mp3")
        d = server.local(self.PUB)
        parts = got.split(os.sep)
        self.assertEqual(len(parts), 3)
        self.assertEqual(parts[0], "My Show")
        self.assertEqual(parts[1], str(d.year))
        self.assertTrue(parts[2].startswith("007 - " + d.date().isoformat() + " - "))
        self.assertTrue(parts[2].endswith(".mp3"))

    def test_relative_path(self):
        got = server.episode_path(self.SHOW, self._ep(), "m4a")
        self.assertFalse(os.path.isabs(got))
        self.assertTrue(got.startswith("My Show" + os.sep))

    def test_number_padding(self):
        self.assertTrue(server.episode_path(self.SHOW, self._ep(num=1), "mp3").split(os.sep)[2].startswith("001 - "))
        self.assertTrue(server.episode_path(self.SHOW, self._ep(num=1234), "mp3").split(os.sep)[2].startswith("1234 - "))

    def test_traversal_title_cannot_escape(self):
        got = server.episode_path(self.SHOW, self._ep(title="../../../etc/passwd"), "mp3")
        parts = got.split(os.sep)
        self.assertEqual(len(parts), 3)
        self.assertNotIn("..", parts)
        self.assertNotIn("/", parts[2])
        self.assertNotIn("\\", parts[2])
        self.assertTrue(os.path.normpath(got).startswith("My Show" + os.sep))

    def test_absolute_title_stays_inside_show(self):
        got = server.episode_path(self.SHOW, self._ep(title="/etc/passwd"), "mp3")
        self.assertEqual(len(got.split(os.sep)), 3)
        self.assertNotIn("/", got.split(os.sep)[2])

    def test_control_chars_removed_from_title(self):
        got = server.episode_path(self.SHOW, self._ep(title="a\x00b\x1fc"), "mp3")
        for ch in ("\x00", "\x1f"):
            self.assertNotIn(ch, got)

    def test_very_long_title_keeps_name_under_byte_limit(self):
        got = server.episode_path(self.SHOW, self._ep(title="x" * 1000), "mp3")
        name = got.split(os.sep)[2]
        self.assertLessEqual(len(name.encode("utf-8")), server.NAME_BYTES)

    def test_bidi_title_stays_confined(self):
        got = server.episode_path(self.SHOW, self._ep(title="a\u202eb"), "mp3")
        parts = got.split(os.sep)
        self.assertEqual(len(parts), 3)
        self.assertEqual(parts[0], "My Show")


class UnderMediaTest(unittest.TestCase):
    def setUp(self):
        self.media = os.path.realpath(server.MEDIA)

    def test_inside_path_resolved(self):
        rel = os.path.join("Show", "2024", "001 - a.mp3")
        self.assertEqual(server.under_media(rel), os.path.realpath(os.path.join(server.MEDIA, rel)))

    def test_returns_absolute_path(self):
        got = server.under_media(os.path.join("Show", "x.mp3"))
        self.assertTrue(os.path.isabs(got))
        self.assertTrue(got.startswith(self.media + os.sep))

    def test_dotdot_escape_refused(self):
        with self.assertRaises(server.Blocked):
            server.under_media(os.path.join("..", "outside.mp3"))

    def test_absolute_path_refused(self):
        absolute = os.path.abspath(os.sep + "etc") + os.sep + "passwd"
        with self.assertRaises(server.Blocked):
            server.under_media(absolute)

    def test_dotdot_that_stays_inside_allowed(self):
        rel = os.path.join("Show", "..", "inside.mp3")
        self.assertEqual(server.under_media(rel), os.path.join(self.media, "inside.mp3"))

    def test_media_root_itself_refused(self):
        with self.assertRaises(server.Blocked):
            server.under_media("")

    def test_symlink_escaping_media_refused(self):
        outside = tempfile.mkdtemp(prefix="outside-", dir=_TMP.name)
        link = os.path.join(server.MEDIA, "escape-link")
        try:
            os.symlink(outside, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not supported here")
        with self.assertRaises(server.Blocked):
            server.under_media(os.path.join("escape-link", "secret.mp3"))

    def test_symlink_inside_media_allowed(self):
        target = os.path.join(server.MEDIA, "real-show")
        os.makedirs(target, exist_ok=True)
        link = os.path.join(server.MEDIA, "show-link")
        if not os.path.lexists(link):
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported here")
        got = server.under_media(os.path.join("show-link", "x.mp3"))
        self.assertEqual(got, os.path.realpath(os.path.join(target, "x.mp3")))


class SniffExtTest(unittest.TestCase):
    def test_html_head_is_not_audio(self):
        self.assertIsNone(server.sniff_ext(b"<!DOCTYPE html><html>", "", "http://x/a.mp3"))

    def test_leading_space_before_html_still_rejected(self):
        self.assertIsNone(server.sniff_ext(b"   \n<html>", "audio/mpeg", "http://x/a.mp3"))

    def test_html_content_type_wins_over_audio_head(self):
        self.assertIsNone(server.sniff_ext(b"\xff\xfb\x90\x00", "text/html; charset=utf-8", "http://x/a.mp3"))

    def test_id3_is_mp3(self):
        self.assertEqual(server.sniff_ext(b"ID3\x04\x00\x00\x00\x00\x00\x00", "", "http://x/a"), "mp3")

    def test_mpeg_frame_is_mp3(self):
        self.assertEqual(server.sniff_ext(b"\xff\xfb\x90\x64", "", "http://x/a"), "mp3")

    def test_adts_aac(self):
        self.assertEqual(server.sniff_ext(b"\xff\xf1\x50\x80", "", "http://x/a"), "aac")

    def test_ftyp_is_m4a(self):
        self.assertEqual(server.sniff_ext(b"\x00\x00\x00\x18ftypM4A \x00\x00\x00\x00", "", "http://x/a"), "m4a")

    def test_ogg(self):
        self.assertEqual(server.sniff_ext(b"OggS" + b"\x00" * 24, "", "http://x/a"), "ogg")

    def test_ogg_opus(self):
        self.assertEqual(server.sniff_ext(b"OggS" + b"\x00" * 20 + b"OpusHead", "", "http://x/a"), "opus")

    def test_mpeg_content_type(self):
        self.assertEqual(server.sniff_ext(b"", "audio/mpeg", "http://x/a"), "mp3")

    def test_mp4_content_type(self):
        self.assertEqual(server.sniff_ext(b"", "audio/mp4", "http://x/a"), "m4a")

    def test_url_extension_mp3(self):
        self.assertEqual(server.sniff_ext(b"\x00" * 8, "", "http://x/a.MP3"), "mp3")

    def test_url_extension_m4a(self):
        self.assertEqual(server.sniff_ext(b"\x00" * 8, "", "http://x/a.M4A"), "m4a")

    def test_url_extension_mp4(self):
        self.assertEqual(server.sniff_ext(b"\x00" * 8, "", "http://x/a.mp4"), "m4a")

    def test_unknown_is_none(self):
        self.assertIsNone(server.sniff_ext(b"hello", "application/octet-stream", "https://x/a.bin"))
        self.assertIsNone(server.sniff_ext(b"", "", "https://x/a"))
        self.assertIsNone(server.sniff_ext(b"\x00\x00", None, "https://x/a"))


class Id3SizeTest(unittest.TestCase):
    def _file(self, data):
        path = os.path.join(_TMP.name, "id3-%d.bin" % id(data))
        return _write(path, data)

    def test_no_tag_returns_zero(self):
        self.assertEqual(server.id3_size(self._file(b"RIFF" + b"\x00" * 20)), 0)

    def test_short_file_returns_zero(self):
        self.assertEqual(server.id3_size(self._file(b"ID3\x03")), 0)
        self.assertEqual(server.id3_size(self._file(b"")), 0)

    def test_zero_size_tag(self):
        self.assertEqual(server.id3_size(self._file(b"ID3\x03\x00\x00\x00\x00\x00\x00")), 0)

    def test_small_size(self):
        self.assertEqual(server.id3_size(self._file(b"ID3\x03\x00\x00\x00\x00\x02\x01")), 0x101)

    def test_syncsafe_decoding(self):
        self.assertEqual(server.id3_size(self._file(b"ID3\x04\x00\x00\x01\x00\x00\x00")), 1 << 21)
        self.assertEqual(server.id3_size(self._file(b"ID3\x04\x00\x00\x7f\x7f\x7f\x7f")), (1 << 28) - 1)

    def test_only_header_read(self):
        path = self._file(b"ID3\x03\x00\x00\x00\x00\x01\x00" + b"\x00" * 5000)
        self.assertEqual(server.id3_size(path), 0x80)


if __name__ == "__main__":
    unittest.main()
