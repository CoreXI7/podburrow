import json
import os
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from typing import Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
_TMP = tempfile.mkdtemp(prefix="podcasts-feeds-")
os.environ["DATA"] = os.path.join(_TMP, "data")
os.environ["MEDIA"] = os.path.join(_TMP, "media")
os.makedirs(os.environ["DATA"], exist_ok=True)
os.makedirs(os.environ["MEDIA"], exist_ok=True)
sys.path.insert(0, os.path.join(_HERE, "..", "app"))

import server

ITUNES_NS = "http://www.itunes.com/dtds/podcast-1.0.dtd"
FEEDPARSE = os.path.join(os.path.dirname(os.path.abspath(server.__file__)), "feedparse.py")

BILLION_LAUGHS = (
    b'<?xml version="1.0"?>'
    b"<!DOCTYPE lolz ["
    b'<!ENTITY lol "lol">'
    b'<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
    b"]>"
    b"<lolz>&lol1;</lolz>"
)

EXTERNAL_DTD = (
    b'<?xml version="1.0"?>'
    b'<!DOCTYPE rss SYSTEM "evil.dtd">'
    b"<rss><channel><title>x</title></channel></rss>"
)

SHIFT_JIS_FEED = (
    b'<?xml version="1.0" encoding="Shift_JIS"?>'
    b"<rss><channel><title>x</title></channel></rss>"
)

LATIN1_FEED = (
    '<?xml version="1.0" encoding="iso-8859-1"?>'
    "<rss><channel><title>Café</title></channel></rss>"
).encode("iso-8859-1")


def rss_doc(body="", title="Test Show"):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<rss xmlns:itunes="{ITUNES_NS}"><channel>'
        f"<title>{title}</title>{body}</channel></rss>"
    ).encode("utf-8")


def item_xml(url: Optional[str] = "http://example.com/ep1.mp3",
             pub: Optional[str] = "Mon, 01 Jan 2024 12:00:00 GMT",
             title: Optional[str] = "Episode 1", guid=None, description=None, itunes_summary=None):
    parts = ["<item>"]
    if title is not None:
        parts.append(f"<title>{title}</title>")
    if pub is not None:
        parts.append(f"<pubDate>{pub}</pubDate>")
    if guid is not None:
        parts.append(f"<guid>{guid}</guid>")
    if url is not None:
        parts.append(f'<enclosure url="{url}" type="audio/mpeg" length="1"/>')
    if description is not None:
        parts.append(f"<description>{description}</description>")
    if itunes_summary is not None:
        parts.append(f"<itunes:summary>{itunes_summary}</itunes:summary>")
    parts.append("</item>")
    return "".join(parts)


def raw_item(**kwargs):
    root = ET.fromstring(rss_doc(item_xml(**kwargs)))
    return server.item(root.find("channel/item"), "http://example.com/feed.xml")


def parsed_item(**kwargs):
    ep = raw_item(**kwargs)
    if ep is None:
        raise AssertionError("item was skipped")
    return ep


def run_feedparse(data, base="http://example.com/feed.xml"):
    return subprocess.run(
        [sys.executable, "-I", FEEDPARSE, base],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )


class CheckXmlTests(unittest.TestCase):
    def test_valid_feed_ok(self):
        server.check_xml(rss_doc(item_xml()))

    def test_utf16_refused(self):
        data = '<?xml version="1.0" encoding="utf-16"?><rss/>'.encode("utf-16")
        with self.assertRaises(server.Blocked) as caught:
            server.check_xml(data)
        self.assertIn("UTF-16", str(caught.exception))

    def test_utf32_refused(self):
        with self.assertRaises(server.Blocked) as caught:
            server.check_xml(b"\x00\x00\xfe\xff")
        self.assertIn("UTF-16/32", str(caught.exception))

    def test_unsupported_encoding_refused(self):
        with self.assertRaises(server.Blocked) as caught:
            server.check_xml(SHIFT_JIS_FEED)
        self.assertIn("not supported", str(caught.exception))

    def test_latin1_allowed(self):
        server.check_xml(LATIN1_FEED)

    def test_doctype_refused(self):
        with self.assertRaises(server.Blocked) as caught:
            server.check_xml(BILLION_LAUGHS)
        self.assertIn("DOCTYPE", str(caught.exception))

    def test_external_doctype_refused(self):
        with self.assertRaises(server.Blocked) as caught:
            server.check_xml(EXTERNAL_DTD)
        self.assertIn("DOCTYPE", str(caught.exception))

    def test_malformed_refused(self):
        with self.assertRaises(server.Blocked):
            server.check_xml(b"<rss><channel></rss>")

    def test_empty_refused(self):
        with self.assertRaises(server.Blocked):
            server.check_xml(b"")


class ParseFeedTests(unittest.TestCase):
    def test_show_and_one_episode(self):
        show, eps = server.parse_feed(rss_doc(item_xml()))
        self.assertEqual(show["title"], "Test Show")
        self.assertEqual(len(eps), 1)
        ep = eps[0]
        self.assertEqual(ep["title"], "Episode 1")
        self.assertEqual(ep["audio_url"], "http://example.com/ep1.mp3")
        self.assertEqual(ep["pub"], "2024-01-01T12:00:00+00:00")
        self.assertEqual(ep["guid"], "http://example.com/ep1.mp3")

    def test_empty_channel_refused(self):
        with self.assertRaises(server.Blocked):
            server.parse_feed(
                b'<?xml version="1.0" encoding="UTF-8"?><rss><channel></channel></rss>'
            )

    def test_non_rss_root_refused(self):
        with self.assertRaises(server.Blocked):
            server.parse_feed(
                b'<?xml version="1.0" encoding="UTF-8"?>'
                b"<html><channel><title>x</title></channel></html>"
            )

    def test_junk_under_rss_dropped(self):
        data = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b"<rss><junk><x>1</x></junk>"
            b"<channel><title>Good</title></channel></rss>"
        )
        show, eps = server.parse_feed(data)
        self.assertEqual(show["title"], "Good")
        self.assertEqual(eps, [])

    def test_missing_fields_are_skipped(self):
        body = item_xml(url=None) + item_xml(pub=None) + item_xml(pub="not a date")
        show, eps = server.parse_feed(rss_doc(body))
        self.assertEqual(show["title"], "Test Show")
        self.assertEqual(eps, [])

    def test_missing_title_gets_default(self):
        show, eps = server.parse_feed(rss_doc(item_xml(title=None)))
        self.assertEqual(eps[0]["title"], "Untitled episode")

    def test_large_item_fields_are_capped(self):
        body = item_xml(title="T" * 100000, description="S" * 1000000)
        show, eps = server.parse_feed(rss_doc(body))
        self.assertEqual(len(eps[0]["title"]), 300)
        self.assertEqual(len(eps[0]["summary"]), 2000)

    def test_large_channel_title_capped(self):
        data = (
            '<?xml version="1.0" encoding="UTF-8"?><rss><channel><title>'
            + "Z" * 100000
            + "</title></channel></rss>"
        ).encode("utf-8")
        show, eps = server.parse_feed(data)
        self.assertEqual(len(show["title"]), 200)

    def test_element_flood_refused(self):
        body = "<item>" + "<x/>" * 20001 + "</item>"
        with self.assertRaises(server.Blocked) as caught:
            server.parse_feed(rss_doc(body))
        self.assertIn("absurdly large", str(caught.exception))

    def test_doctype_feed_refused(self):
        with self.assertRaises(server.Blocked):
            server.parse_feed(BILLION_LAUGHS)

    def test_latin1_feed_parsed(self):
        show, eps = server.parse_feed(LATIN1_FEED)
        self.assertEqual(show["title"], "Café")


class ItemTests(unittest.TestCase):
    def test_relative_enclosure_url_joined(self):
        ep = parsed_item(url="/audio/ep1.mp3")
        self.assertEqual(ep["audio_url"], "http://example.com/audio/ep1.mp3")

    def test_missing_enclosure_returns_none(self):
        self.assertIsNone(raw_item(url=None))

    def test_missing_pubdate_returns_none(self):
        self.assertIsNone(raw_item(pub=None))

    def test_bad_pubdate_returns_none(self):
        self.assertIsNone(raw_item(pub="not a date"))

    def test_missing_title_gets_default(self):
        self.assertEqual(parsed_item(title=None)["title"], "Untitled episode")

    def test_guid_falls_back_to_url_without_query(self):
        ep = parsed_item(guid=None, url="http://example.com/e.mp3?x=1#part")
        self.assertEqual(ep["guid"], "http://example.com/e.mp3")

    def test_given_guid_is_used(self):
        self.assertEqual(parsed_item(guid="my-guid")["guid"], "my-guid")

    def test_itunes_summary_preferred(self):
        ep = parsed_item(description="plain", itunes_summary="rich summary")
        self.assertEqual(ep["summary"], "rich summary")

    def test_description_fallback(self):
        ep = parsed_item(description="plain")
        self.assertEqual(ep["summary"], "plain")

    def test_giant_fields_capped(self):
        ep = parsed_item(
            guid="g" * 1000,
            title="T" * 100000,
            description="S" * 100000,
            url="http://example.com/" + "a" * 5000,
        )
        self.assertEqual(len(ep["guid"]), 500)
        self.assertEqual(len(ep["title"]), 300)
        self.assertEqual(len(ep["summary"]), 2000)
        self.assertEqual(len(ep["audio_url"]), 2000)

    def test_fetch_rejects_non_http_urls(self):
        for url in ("javascript:alert(1)", "file:///etc/passwd"):
            with self.assertRaises(server.Blocked):
                server.fetch(url)


class ParseFeedSafeTests(unittest.TestCase):
    def test_valid_feed(self):
        show, eps = server.parse_feed_safe(rss_doc(item_xml()))
        self.assertEqual(show["title"], "Test Show")
        self.assertEqual(len(eps), 1)

    def test_doctype_refused(self):
        with self.assertRaises(server.Blocked):
            server.parse_feed_safe(BILLION_LAUGHS)

    def test_non_rss_refused(self):
        with self.assertRaises(server.Blocked):
            server.parse_feed_safe(b"this is not xml")

    def test_latin1_feed(self):
        show, eps = server.parse_feed_safe(LATIN1_FEED)
        self.assertEqual(show["title"], "Café")


class FeedparseScriptTests(unittest.TestCase):
    def test_valid_feed_exits_0(self):
        p = run_feedparse(rss_doc(item_xml()))
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertEqual(out["show"]["title"], "Test Show")
        self.assertEqual(len(out["eps"]), 1)

    def test_doctype_exits_2(self):
        p = run_feedparse(BILLION_LAUGHS)
        self.assertEqual(p.returncode, 2)
        self.assertIn(b"DOCTYPE", p.stderr)
        self.assertEqual(p.stdout, b"")

    def test_garbage_exits_2(self):
        p = run_feedparse(b"not xml at all")
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stdout, b"")

    def test_element_flood_exits_2(self):
        p = run_feedparse(rss_doc("<item>" + "<x/>" * 20001 + "</item>"))
        self.assertEqual(p.returncode, 2)
        self.assertIn(b"absurdly large", p.stderr)

    def test_giant_fields_capped(self):
        p = run_feedparse(rss_doc(item_xml(title="T" * 100000, description="S" * 1000000)))
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertEqual(len(out["eps"][0]["title"]), 300)
        self.assertEqual(len(out["eps"][0]["summary"]), 2000)


if __name__ == "__main__":
    unittest.main()
