"""AUTH=proxy never opens the app to anyone but the named proxy, and a bad setup falls back to the login. Each case is its own process."""
import json, os, subprocess, sys, tempfile, unittest
CODE = r"""
import http.client, os, sys, threading
sys.path.insert(0, sys.argv[1])
import server
server.init_db()
srv = server.Server(("127.0.0.1", 0), server.Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
port = srv.server_address[1]
c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
c.request("GET", "/api/state", headers={"Host": "app.test", "Remote-User": "x", "X-Forwarded-For": "127.0.0.1"})
print(c.getresponse().status)
"""


def status(**env):
    with tempfile.TemporaryDirectory() as t:
        e = {**os.environ, "DATA": t, "MEDIA": t, "ALLOWED_HOSTS": "app.test", **env}
        app = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app")
        r = subprocess.run([sys.executable, "-c", CODE, app], env=e, capture_output=True, text=True, timeout=60)
        return r.stdout.strip().splitlines()[-1], r.stdout


SLOW = r"""
import http.client, os, socket, sys, threading, time
sys.path.insert(0, sys.argv[1])
import server
server.init_db()
server.Server.READ_DEADLINE = 2
srv = server.Server(("127.0.0.1", 0), server.Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
port = srv.server_address[1]
def raw(data):
    s = socket.create_connection(("127.0.0.1", port), timeout=10); s.sendall(data); return s
# a client dripping its login: cut at the read deadline, however often it sends
s = raw(b"POST /api/login HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/json\r\nOrigin: http://app.test\r\nContent-Length: 100\r\n\r\n")
t0, cut = time.time(), False
try:
    while time.time() - t0 < 8:
        s.sendall(b"x"); time.sleep(0.5)
except OSError:
    cut = True
print("cut", cut, time.time() - t0 < 7)
# oversized headers refused
s = raw(b"GET /health HTTP/1.1\r\nHost: app.test\r\n" + b"X-A: " + b"a" * 65000 + b"\r\nX-B: " + b"b" * 65000 + b"\r\n\r\n")
print("big", s.recv(64)[:12])
# HTTP/0.9 gets headers or a status, never a bare page
s = raw(b"GET /login\r\n\r\n")
print("old", s.recv(64)[:8])
c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
c.request("GET", "/api/state", headers={"Host": "app.test", "Sec-Fetch-Site": "cross-site"})
print("xsite", c.getresponse().status)
c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
c.request("PUT", "/", headers={"Host": "app.test"})
r = c.getresponse()
print("put", r.status, bool(r.getheader("Content-Security-Policy")))
"""


class Hardening(unittest.TestCase):
    def test_slow_big_and_odd_requests(self):
        with tempfile.TemporaryDirectory() as t:
            e = {**os.environ, "DATA": t, "MEDIA": t, "ALLOWED_HOSTS": "app.test", "AUTH": "login", "TRUSTED_PROXY": ""}
            app = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app")
            out = subprocess.run([sys.executable, "-c", SLOW, app], env=e, capture_output=True, text=True, timeout=60).stdout
        self.assertIn("cut True True", out)
        self.assertIn("big b'HTTP/1.0 431", out.replace("HTTP/1.1", "HTTP/1.0"))
        self.assertIn("old b'HTTP/1", out)
        self.assertIn("xsite 403", out)
        self.assertIn("put 501 True", out)


class ProxyMode(unittest.TestCase):
    def test_login_is_default(self):
        self.assertEqual(status()[0], "401")

    def test_proxy_without_trusted_proxy_uses_login(self):
        code, out = status(AUTH="proxy", TRUSTED_PROXY="")
        self.assertEqual(code, "401")
        self.assertIn("using login", out)

    def test_unknown_mode_uses_login(self):
        self.assertEqual(status(AUTH="off")[0], "401")

    def test_stranger_refused_in_proxy_mode(self):
        self.assertEqual(status(AUTH="proxy", TRUSTED_PROXY="10.9.9.9")[0], "403")

    def test_sessions_dont_survive_a_switch_to_proxy(self):
        code = "import sys,os;sys.path.insert(0,sys.argv[1]);import server,authweb;open(authweb.auth.SESSIONS_FILE,'w').close();server.MEDIA=os.environ['MEDIA'];server.startup();print(os.path.exists(authweb.auth.SESSIONS_FILE))"
        with tempfile.TemporaryDirectory() as t:
            e = {**os.environ, "DATA": t, "MEDIA": t, "AUTH": "proxy", "TRUSTED_PROXY": "127.0.0.1"}
            app = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app")
            self.assertIn("False", subprocess.run([sys.executable, "-c", code, app], env=e, capture_output=True, text=True, timeout=30).stdout)

    def test_named_proxy_is_let_through(self):
        self.assertEqual(status(AUTH="proxy", TRUSTED_PROXY="127.0.0.1")[0], "200")


if __name__ == "__main__":
    unittest.main()
