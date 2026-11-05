"""Security review fixes: each test failed before its fix."""
import os, re, sqlite3, sys, tempfile, unittest, xml.etree.ElementTree as ET
T = tempfile.mkdtemp()
os.environ.update(DATA=T, MEDIA=T)
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "app"))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import server


def page(name):
    with open(os.path.join(HERE, "..", "app", "static", name), encoding="utf-8") as f:
        return f.read()


class Fixes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.init_db()

    def add_show(self):
        with server.db() as c:
            return c.execute("INSERT INTO shows(title, folder, feed_url, added_at) VALUES('S', ?, ?, 1)", (f"S{os.urandom(4).hex()}", f"https://e.test/{os.urandom(4).hex()}")).lastrowid

    def test_empty_feed_keeps_queued_episodes(self):
        sid = self.add_show()
        with server.db() as c:
            c.execute("INSERT INTO episodes(show_id, guid, title, pub, audio_url, num, status) VALUES(?, 'g', 't', '2024-01-01T00:00:00+00:00', 'https://e.test/a', 1, 'queued')", (sid,))
            server.refresh_links(c, sid, [])
            self.assertEqual(c.execute("SELECT status FROM episodes WHERE show_id=?", (sid,)).fetchone()[0], "queued")

    def test_unknown_action_with_bad_id_is_refused_cleanly(self):
        with self.assertRaises(server.Blocked):
            server.act({"action": "nope", "id": "abc"})

    def test_settings_ignore_a_bad_id(self):
        self.assertEqual(server.act({"action": "settings", "id": "abc", "check_minutes": 60}), {})

    def test_bad_id_is_refused(self):
        with self.assertRaises(server.Blocked):
            server.act({"action": "retry", "id": "abc"})

    def test_pause_needs_a_real_boolean(self):
        sid = self.add_show()
        for bad in ("false", 1, None):
            with self.assertRaises(server.Blocked):
                server.act({"action": "pause", "id": sid, "paused": bad})
        server.act({"action": "pause", "id": sid, "paused": True})
        with server.db() as c:
            self.assertEqual(c.execute("SELECT paused FROM shows WHERE id=?", (sid,)).fetchone()[0], 1)

    def test_only_web_links_become_episodes(self):
        for url in ("javascript:alert(1)", "file:///etc/passwd", "ftp://e.test/a.mp3", "data:audio/mp3,x"):
            it = ET.fromstring(f'<item><title>t</title><pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate><enclosure url="{url}"/></item>')
            self.assertIsNone(server.item(it, ""), url)
        it = ET.fromstring('<item><title>t</title><pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate><enclosure url="https://e.test/a.mp3"/></item>')
        self.assertEqual(server.item(it, "")["audio_url"], "https://e.test/a.mp3")

    def test_names_drop_invisible_direction_characters(self):
        self.assertEqual(server.safe_name("a‮b‏⁦c"), "abc")

    def test_dates_are_escaped_in_the_page(self):
        js = page("app.js")
        self.assertRegex(js, r"const day = iso => iso \? esc\(")

    def test_page_has_no_inline_or_outside_code(self):
        html = page("index.html")
        self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)")
        self.assertNotIn("<style", html)
        self.assertNotRegex(html, r"https?://")
        self.assertNotRegex(html, r"\son[a-z]+=")

    def test_csp_blocks_inline_scripts(self):
        self.assertNotRegex(re.search(r"script-src[^;]*", server.CSP).group(0), "unsafe")
        self.assertIn("default-src 'none'", server.CSP)
        self.assertNotIn("googleapis", server.CSP)


class ReviewRound1(unittest.TestCase):
    def test_second_channel_refused(self):
        with self.assertRaises(server.Blocked):
            server.parse_feed(b"<rss><channel><title>a</title></channel><channel/></rss>")

    def test_image_url_capped(self):
        feed = b'<rss xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd"><channel><title>a</title><itunes:image href="https://e.test/' + b"x" * 5000 + b'"/></channel></rss>'
        self.assertLessEqual(len(server.parse_feed(feed)[0]["image_url"]), 2000)

    def test_one_broken_item_keeps_the_rest(self):
        good = b'<item><title>ok</title><pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate><enclosure url="https://e.test/a.mp3"/></item>'
        bad = b'<item><title>bad</title><pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate><enclosure url="http://[x/a.mp3"/></item>'
        self.assertEqual([e["title"] for e in server.parse_feed(b"<rss><channel><title>a</title>" + bad + good + b"</channel></rss>")[1]], ["ok"])

    def test_trailing_space_and_dot_removed(self):
        self.assertEqual(server.safe_name("Foo ."), "Foo")

    def test_azure_host_service_blocked(self):
        import socket
        real, socket.getaddrinfo = socket.getaddrinfo, lambda *a, **k: [(2, 1, 6, "", ("168.63.129.16", 443))]
        try:
            with self.assertRaises(server.Blocked):
                server.public_addr("x.test", 443)
        finally:
            socket.getaddrinfo = real

    def test_unreadable_folder_isnt_called_missing(self):
        real, server.os.stat = server.os.stat, lambda *a, **k: (_ for _ in ()).throw(PermissionError())
        try:
            self.assertFalse(server.file_gone("/x"))
        finally:
            server.os.stat = real
        self.assertTrue(server.file_gone(os.path.join(T, "no-such-file")))

    def test_deadline_stops_a_stalled_connection(self):
        conn = server._PinnedHTTP("x.test", 80, ("127.0.0.1", 9), 1)
        g = server.Guard(conn, __import__("time").monotonic() + 60)
        g.expired = True
        g.cancel()
        class S:
            closed = False
            def close(self): S.closed = True
        conn.sock = S()
        with self.assertRaises(TimeoutError):
            conn._check_deadline()
        self.assertTrue(S.closed)

    def test_failed_lookup_keeps_known_home_addresses(self):
        import socket
        names, home = server.HOME_NAMES, dict(server._home)
        real = socket.getaddrinfo
        def boom(*a, **k):
            raise socket.gaierror(-3, "x")
        try:
            server.HOME_NAMES = ["home.test"]
            server._home.update(ips={"203.0.113.9"}, at=0)
            socket.getaddrinfo = boom
            self.assertEqual(server.home_ips(), {"203.0.113.9"})
        finally:
            socket.getaddrinfo = real
            server.HOME_NAMES = names
            server._home.clear(); server._home.update(home)

    def test_cpu_failures_arent_retried_forever(self):
        self.assertTrue(any("too much CPU" in h for h in server.HOPELESS))

    def test_tagger_has_a_cpu_limit(self):
        self.assertIn("RLIMIT_CPU", page("../tagger.py"))
        self.assertIn("RLIMIT_CPU", page("../feedparse.py"))


class Container(unittest.TestCase):
    def test_image_contains_the_app(self):
        with open(os.path.join(HERE, "..", "Dockerfile")) as f:
            d = f.read()
        self.assertIn("COPY app /app", d)
        self.assertIn("COPY tools /tools", d)


class Migrate(unittest.TestCase):
    def test_apply_refuses_without_the_drive_marker(self):
        import migrate as M
        with self.assertRaises(SystemExit):
            M.apply([])

    def test_undo_refuses_without_the_drive_marker(self):
        import migrate as M
        with self.assertRaises(SystemExit):
            M.undo()

    def test_same_clean_name_gets_its_own_folder(self):
        import migrate as M
        show = lambda t: {"title": t, "author": "", "image": "", "url": "https://e.test/" + t.strip("?"), "items": []}
        real, M.read_podgrab = M.read_podgrab, lambda: [show("Show"), show("Show?")]
        try:
            folders = [x[0]["folder"] for x in M.plan()]
        finally:
            M.read_podgrab = real
        self.assertEqual(len(set(folders)), 2)


    def test_one_bad_row_doesnt_stop_the_plan(self):
        import migrate as M
        row = {"pub_date": "2024-01-01T00:00:00+00:00", "title": "t", "guid": "g", "created_at": "2024-01-01", "file_url": "https://e.test/a.mp3",
               "summary": "", "download_status": 2, "download_path": "/assets/../../etc/passwd"}
        show = {"title": "S", "author": "", "image": "", "url": "https://e.test/f", "items": [row]}
        real, M.read_podgrab = M.read_podgrab, lambda: [show]
        try:
            self.assertEqual(len(M.plan()[0] if isinstance(M.plan(), tuple) else M.plan()), 1)
        finally:
            M.read_podgrab = real


if __name__ == "__main__":
    unittest.main()
