import os
import socket
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ["DATA"] = tempfile.mkdtemp(prefix="podcasts-test-data-")
os.environ["MEDIA"] = tempfile.mkdtemp(prefix="podcasts-test-media-")
sys.path.insert(0, os.path.join(HERE, "..", "app"))

import server


def addr(ip, port=443):
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))


class PublicAddrTests(unittest.TestCase):
    def resolve(self, ip, port=443, host="feed.example", infos=None):
        records = infos if infos is not None else [addr(ip, port)]
        with mock.patch.object(server.socket, "getaddrinfo", return_value=records), \
                mock.patch.object(server, "home_ips", return_value=set()):
            return server.public_addr(host, port)

    def test_public_address_accepted(self):
        for ip in ("8.8.8.8", "1.1.1.1", "93.184.216.34"):
            with self.subTest(ip=ip):
                self.assertEqual(self.resolve(ip), (ip, 443))

    def test_loopback_blocked(self):
        for ip in ("127.0.0.1", "127.0.0.53", "127.255.255.254"):
            with self.subTest(ip=ip), self.assertRaises(server.Blocked):
                self.resolve(ip)

    def test_private_ranges_blocked(self):
        for ip in ("10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.254", "192.168.0.1", "192.168.255.255"):
            with self.subTest(ip=ip), self.assertRaises(server.Blocked):
                self.resolve(ip)

    def test_link_local_and_metadata_blocked(self):
        for ip in ("169.254.1.1", "169.254.169.254"):
            with self.subTest(ip=ip), self.assertRaises(server.Blocked):
                self.resolve(ip, port=80)

    def test_other_non_global_addresses_blocked(self):
        for ip in ("0.0.0.0", "192.0.2.1", "198.51.100.9", "203.0.113.9", "255.255.255.255"):
            with self.subTest(ip=ip), self.assertRaises(server.Blocked):
                self.resolve(ip)

    def test_multicast_blocked(self):
        for ip in ("224.0.0.1", "239.255.255.250"):
            with self.subTest(ip=ip), self.assertRaises(server.Blocked):
                self.resolve(ip)

    def test_ipv6_is_never_resolved(self):
        with mock.patch.object(server.socket, "getaddrinfo", return_value=[addr("::1")]) as gai:
            with self.assertRaises(server.Blocked):
                server.public_addr("v6.example", 443)
        self.assertEqual(gai.call_args.args[2], socket.AF_INET)

    def test_odd_ipv4_forms_blocked(self):
        for host in ("127.1", "2130706433", "0x7f.0.0.1", "0177.0.0.1", "127.0.0.1."):
            with self.subTest(host=host):
                with mock.patch.object(server.socket, "getaddrinfo", return_value=[addr("127.0.0.1")]) as gai, \
                        mock.patch.object(server, "home_ips", return_value=set()), \
                        self.assertRaises(server.Blocked):
                    server.public_addr(host, 80)
                self.assertEqual(gai.call_args.args[0], host)

    def test_any_private_answer_blocks_the_whole_name(self):
        infos = [addr("93.184.216.34"), addr("10.0.0.7")]
        with self.assertRaises(server.Blocked):
            self.resolve("93.184.216.34", infos=infos)

    def test_only_ports_80_and_443(self):
        for port in (0, 21, 22, 25, 8080, 8443, 65535):
            with self.subTest(port=port):
                with mock.patch.object(server.socket, "getaddrinfo") as gai, \
                        self.assertRaises(server.Blocked):
                    server.public_addr("feed.example", port)
                gai.assert_not_called()

    def test_dns_temporary_failure_is_offline(self):
        err = socket.gaierror(socket.EAI_AGAIN, "try again")
        with mock.patch.object(server.socket, "getaddrinfo", side_effect=err):
            with self.assertRaises(server.Offline):
                server.public_addr("feed.example", 443)

    def test_dns_unknown_name_is_blocked(self):
        err = socket.gaierror(socket.EAI_NONAME, "unknown")
        with mock.patch.object(server.socket, "getaddrinfo", side_effect=err):
            with self.assertRaises(server.Blocked):
                server.public_addr("feed.example", 443)

    def test_empty_dns_answer_is_blocked(self):
        with mock.patch.object(server.socket, "getaddrinfo", return_value=[]), \
                mock.patch.object(server, "home_ips", return_value=set()):
            with self.assertRaises(server.Blocked):
                server.public_addr("feed.example", 443)

    def test_home_names_refuse_our_own_public_ip(self):
        old_names = server.HOME_NAMES
        old_home = {"ips": set(server._home["ips"]), "at": server._home["at"]}
        try:
            server.HOME_NAMES = ["home.example"]
            server._home.update(ips=set(), at=0.0)
            with mock.patch.object(server.socket, "getaddrinfo", return_value=[addr("93.184.216.34")]):
                self.assertEqual(server.home_ips(), {"93.184.216.34"})
                with self.assertRaises(server.Blocked):
                    server.public_addr("feed.example", 443)
        finally:
            server.HOME_NAMES = old_names
            server._home.clear()
            server._home.update(old_home)

    def test_no_home_names_turns_the_check_off(self):
        old_names = server.HOME_NAMES
        old_home = {"ips": set(server._home["ips"]), "at": server._home["at"]}
        try:
            server.HOME_NAMES = []
            server._home.update(ips=set(), at=0.0)
            self.assertEqual(server.home_ips(), set())
        finally:
            server.HOME_NAMES = old_names
            server._home.clear()
            server._home.update(old_home)


class FakeGuard:
    def __init__(self, conn, deadline):
        self.conn = conn
        self.final = deadline
        self.deadline = deadline
        self.cancelled = False

    def arm(self, deadline):
        self.deadline = deadline

    def cancel(self):
        self.cancelled = True

    def why(self):
        return server.Offline("fake guard")


class FakeResponse:
    def __init__(self, status=200, headers=None):
        self.status = status
        self.headers = dict(headers or {})
        self.closed = False

    def getheader(self, k, default=None):
        for key, value in self.headers.items():
            if key.lower() == k.lower():
                return value
        return default

    def read(self, n=-1):
        return b""

    def close(self):
        self.closed = True


class FakeConn:
    responses = []
    instances = []

    def __init__(self, host, port, addr, timeout):
        self.host = host
        self.port = port
        self.addr = addr
        self.timeout = timeout
        self.requests = []
        self.closed = False
        FakeConn.instances.append(self)

    def request(self, method, path, headers=None):
        self.requests.append((method, path, dict(headers or {})))

    def getresponse(self):
        return FakeConn.responses.pop(0)

    def close(self):
        self.closed = True


class FetchTests(unittest.TestCase):
    def setUp(self):
        FakeConn.responses = []
        FakeConn.instances = []
        self.publics = {"example.com": "93.184.216.34", "rebind.example": "93.184.216.34",
                        "cdn.example": "93.184.216.34"}
        self.public_patch = mock.patch.object(server, "public_addr", side_effect=self.public)
        self.patches = [
            mock.patch.object(server, "_PinnedHTTP", FakeConn),
            mock.patch.object(server, "_PinnedHTTPS", FakeConn),
            mock.patch.object(server, "Guard", FakeGuard),
            self.public_patch,
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()

    def public(self, host, port):
        if host in self.publics:
            return (self.publics[host], port)
        raise server.Blocked(f"{host}: address not allowed or not found")

    def test_success_returns_open_response_and_pinned_connection(self):
        resp = FakeResponse(200, {"Content-Type": "text/xml"})
        FakeConn.responses = [resp]
        r = server.fetch("http://example.com/feed?x=1")
        self.assertIs(r.r, resp)
        conn = FakeConn.instances[0]
        self.assertEqual((conn.host, conn.port, conn.addr), ("example.com", 80, ("93.184.216.34", 80)))
        method, path, headers = conn.requests[0]
        self.assertEqual(method, "GET")
        self.assertEqual(path, "/feed?x=1")
        self.assertEqual(headers["User-Agent"], server.UA)
        self.assertFalse(conn.closed)
        r.close()
        self.assertTrue(conn.closed)
        self.assertTrue(resp.closed)

    def test_https_uses_port_443_by_default(self):
        FakeConn.responses = [FakeResponse(200)]
        r = server.fetch("https://example.com/")
        self.assertEqual(FakeConn.instances[0].port, 443)
        r.close()

    def test_bad_schemes_are_blocked_before_connecting(self):
        for url in ("file:///etc/passwd", "file://example.com/x", "ftp://example.com/a.mp3",
                    "gopher://example.com/"):
            with self.subTest(url=url), self.assertRaises(server.Blocked):
                server.fetch(url)
        self.assertEqual(FakeConn.instances, [])

    def test_url_with_login_is_blocked(self):
        for url in ("http://user:pass@example.com/", "http://user@example.com/"):
            with self.subTest(url=url), self.assertRaises(server.Blocked):
                server.fetch(url)
        self.assertEqual(FakeConn.instances, [])

    def test_missing_host_and_bad_port_are_blocked(self):
        for url in ("http:///path", "http://example.com:abc/"):
            with self.subTest(url=url), self.assertRaises(server.Blocked):
                server.fetch(url)
        self.assertEqual(FakeConn.instances, [])

    def test_redirect_to_private_or_metadata_is_blocked(self):
        targets = ("http://127.0.0.1/admin", "http://10.1.2.3/x", "http://192.168.1.1/",
                   "http://169.254.169.254/latest/meta-data/")
        for target in targets:
            with self.subTest(target=target):
                FakeConn.instances = []
                FakeConn.responses = [FakeResponse(302, {"Location": target})]
                with self.assertRaises(server.Blocked):
                    server.fetch("http://example.com/feed")
                self.assertEqual(len(FakeConn.instances), 1)

    def test_relative_redirect_is_followed(self):
        FakeConn.responses = [FakeResponse(302, {"Location": "/next"}), FakeResponse(200)]
        r = server.fetch("http://example.com/old")
        self.assertEqual(FakeConn.instances[1].requests[0][1], "/next")
        self.assertEqual(r.url, "http://example.com/next")
        r.close()

    def test_redirect_without_location_is_blocked(self):
        FakeConn.responses = [FakeResponse(301)]
        with self.assertRaises(server.Blocked):
            server.fetch("http://example.com/")

    def test_too_many_redirects_is_blocked(self):
        FakeConn.responses = [FakeResponse(302, {"Location": "/again"}) for _ in range(9)]
        with self.assertRaises(server.Blocked):
            server.fetch("http://example.com/")
        self.assertEqual(len(FakeConn.instances), 9)

    def test_http_errors(self):
        for status in (400, 401, 403, 404, 410):
            with self.subTest(status=status):
                FakeConn.responses = [FakeResponse(status)]
                with self.assertRaises(server.Blocked):
                    server.fetch("http://example.com/")
        for status in (429, 500, 502, 503, 504):
            with self.subTest(status=status):
                FakeConn.responses = [FakeResponse(status)]
                with self.assertRaises(server.Offline):
                    server.fetch("http://example.com/")

    def test_dns_rebinding_connects_to_the_checked_address(self):
        FakeConn.responses = [FakeResponse(200)]
        r = server.fetch("http://rebind.example/")
        conn = FakeConn.instances[0]
        self.assertEqual(conn.host, "rebind.example")
        self.assertEqual(conn.addr, ("93.184.216.34", 80))
        r.close()


class FetchPortTests(unittest.TestCase):
    def test_nonstandard_port_is_blocked_before_dns_or_connect(self):
        original = server.public_addr
        for port in (21, 22, 8080, 8443):
            with self.subTest(port=port):
                FakeConn.instances = []
                with mock.patch.object(server, "_PinnedHTTP", FakeConn), \
                        mock.patch.object(server.socket, "getaddrinfo") as gai, \
                        self.assertRaises(server.Blocked):
                    server.fetch(f"http://example.com:{port}/")
                gai.assert_not_called()
                self.assertEqual(FakeConn.instances, [])
        self.assertIs(server.public_addr, original)


class GuardTests(unittest.TestCase):
    class Sock:
        def __init__(self):
            self.calls = []

        def shutdown(self, how):
            self.calls.append(how)

    class Conn:
        def __init__(self, with_sock=True):
            self.sock = GuardTests.Sock() if with_sock else None

    def test_kill_marks_expired_and_shuts_the_socket_down(self):
        conn = self.Conn()
        g = server.Guard(conn, time.monotonic() + 60)
        try:
            g._kill()
            self.assertTrue(g.expired)
            sock = conn.sock
            assert sock is not None
            self.assertEqual(sock.calls, [socket.SHUT_RDWR])
        finally:
            g.cancel()

    def test_kill_is_safe_without_a_socket(self):
        g = server.Guard(self.Conn(with_sock=False), time.monotonic() + 60)
        try:
            g._kill()
            self.assertTrue(g.expired)
        finally:
            g.cancel()

    def test_why_reports_hard_deadline_as_blocked(self):
        g = server.Guard(self.Conn(), time.monotonic() + 60)
        try:
            g.final = time.monotonic() - 2
            err = g.why()
            self.assertIsInstance(err, server.Blocked)
            self.assertIn("time limit", str(err))
        finally:
            g.cancel()

    def test_why_reports_stall_as_offline(self):
        g = server.Guard(self.Conn(), time.monotonic() + 60)
        try:
            err = g.why()
            self.assertIsInstance(err, server.Offline)
            self.assertIn("10 minutes", str(err))
        finally:
            g.cancel()

    def test_arm_sets_the_earlier_deadline(self):
        g = server.Guard(self.Conn(), time.monotonic() + 60)
        try:
            deadline = time.monotonic() + 5
            g.arm(deadline)
            self.assertEqual(g.deadline, deadline)
        finally:
            g.cancel()


class ReadCappedTests(unittest.TestCase):
    class Body:
        def __init__(self, chunks):
            self.chunks = list(chunks)
            self.closed = False
            self.read_sizes = []

        def read(self, n):
            self.read_sizes.append(n)
            return self.chunks.pop(0) if self.chunks else b""

        def close(self):
            self.closed = True

    class ErrorBody:
        def __init__(self):
            self.closed = False

        def read(self, n):
            raise OSError("connection broke")

        def close(self):
            self.closed = True

    def test_reads_all_chunks_and_closes(self):
        body = self.Body([b"abc", b"def", b""])
        self.assertEqual(server.read_capped(body, 100), b"abcdef")
        self.assertTrue(body.closed)
        self.assertEqual(body.read_sizes[0], 1 << 16)

    def test_exactly_at_cap_is_allowed(self):
        body = self.Body([b"abc", b"def", b""])
        self.assertEqual(server.read_capped(body, 6), b"abcdef")
        self.assertTrue(body.closed)

    def test_oversize_body_is_blocked_and_closed(self):
        body = self.Body([b"abc", b"def"])
        with self.assertRaises(server.Blocked):
            server.read_capped(body, 5)
        self.assertTrue(body.closed)

    def test_single_oversize_chunk_is_blocked(self):
        body = self.Body([b"x" * 100])
        with self.assertRaises(server.Blocked):
            server.read_capped(body, 99)
        self.assertTrue(body.closed)

    def test_empty_body_returns_empty_bytes(self):
        body = self.Body([])
        self.assertEqual(server.read_capped(body, 10), b"")
        self.assertTrue(body.closed)

    def test_read_error_still_closes(self):
        body = self.ErrorBody()
        with self.assertRaises(OSError):
            server.read_capped(body, 10)
        self.assertTrue(body.closed)


if __name__ == "__main__":
    unittest.main()
