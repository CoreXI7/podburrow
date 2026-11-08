"""Sign-in and access control, end to end against a real server on 127.0.0.1."""
import http.client, json, os, re, sys, tempfile, threading, time, unittest
T = tempfile.mkdtemp()
os.environ.update(DATA=T, MEDIA=T, AUTH="login", ALLOWED_HOSTS="127.0.0.1:18095", TRUSTED_PROXY="", ORIGIN="")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
import server, authweb, auth
from signin_core import web

HOST = "127.0.0.1:18095"
srv = None


def setUpModule():
    global srv
    server.init_db()
    srv = server.Server(("127.0.0.1", 18095), server.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def tearDownModule():
    srv.shutdown()
    srv.server_close()


def req(method, path, body=None, cookie="", headers=None):
    c = http.client.HTTPConnection("127.0.0.1", 18095, timeout=20)
    h = {"Host": HOST}
    if body is not None:
        h.update({"Content-Type": "application/json", "Origin": f"http://{HOST}", "X-Podburrow": "1"})
    if cookie:
        h["Cookie"] = cookie
    h.update(headers or {})
    c.request(method, path, json.dumps(body) if body is not None else None, h)
    r = c.getresponse()
    data = r.read()
    out = (r.status, data, r.getheader("Location"), [v for k, v in r.getheaders() if k == "Set-Cookie"])
    c.close()
    return out


def cookie_of(cookies, name="podburrow"):
    for c in cookies:
        m = re.match(rf"{name}=([^;]+)", c)
        if m:
            return f"{name}={m.group(1)}"
    return ""


def forgive():
    """Clears the wrong-try waits, so one test's failures don't slow the next."""
    authweb.THROTTLE.__init__()
    authweb.ACCOUNT.update(lambda x: x.update(failures=0, last_fail=0))
    web._session_tries.clear()


class A_NoAccount(unittest.TestCase):
    def test_a_everything_private_is_closed(self):
        self.assertEqual(req("GET", "/")[0], 303)
        self.assertIn("/login", req("GET", "/")[2])
        for p in ("/api/state", "/api/episodes?id=1", "/api/search?q=x", "/api/cover/1", "/api/account"):
            self.assertEqual(req("GET", p)[0], 401, p)
        self.assertEqual(req("POST", "/api/act", {"action": "settings"})[0], 401)

    def test_b_public_paths(self):
        for p in ("/login", "/js/login.js", "/login.css", "/api/auth/state"):
            self.assertEqual(req("GET", p)[0], 200, p)
        self.assertEqual(req("GET", "/health")[0], 200)

    def test_c_setup_needs_code(self):
        s = req("POST", "/api/setup-account", {"code": "wrong", "user": "owner", "password": "a long enough passphrase 42"})
        self.assertEqual(s[0], 403)
        self.assertFalse(authweb.ACCOUNT.exists())


class B_Account(unittest.TestCase):
    PW = "correct horse battery staple 42"

    @classmethod
    def setUpClass(cls):
        code = auth.new_setup_code()
        s = req("POST", "/api/setup-account", {"code": code, "user": "owner", "password": cls.PW})
        assert s[0] == 200, s[1]
        cls.session = cookie_of(s[3])

    def test_a_cookie_flags(self):
        s = req("POST", "/api/login", {"user": "owner", "password": self.PW})
        self.assertEqual(s[0], 200)
        c = next(x for x in s[3] if x.startswith("podburrow="))
        for flag in ("HttpOnly", "SameSite=Strict"):
            self.assertIn(flag, c)

    def test_b_session_opens_the_app(self):
        self.assertEqual(req("GET", "/", cookie=self.session)[0], 200)
        self.assertEqual(req("GET", "/api/state", cookie=self.session)[0], 200)
        self.assertEqual(req("POST", "/api/act", {"action": "nothing"}, self.session)[0], 400)

    def test_c_junk_cookie_refused(self):
        self.assertEqual(req("GET", "/api/state", cookie="podburrow=" + "A" * 43)[0], 401)

    def test_d_setup_again_refused(self):
        self.assertEqual(req("POST", "/api/setup-account", {"code": "x", "user": "b", "password": self.PW})[0], 409)

    def test_e_csrf(self):
        act = {"action": "settings"}
        self.assertEqual(req("POST", "/api/act", act, self.session, {"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(req("POST", "/api/act", act, self.session, {"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(req("POST", "/api/act", act, self.session, {"Content-Type": "text/plain"})[0], 403)
        self.assertEqual(req("POST", "/api/act", act, self.session, {"X-Podburrow": "0"})[0], 403)

    def test_f_wrong_host(self):
        self.assertEqual(req("GET", "/api/state", cookie=self.session, headers={"Host": "evil.example"})[0], 421)
        self.assertEqual(req("POST", "/api/login", {"user": "owner", "password": self.PW}, headers={"Host": "evil.example"})[0], 421)

    def test_g_odd_paths_refused(self):
        for p in ("//api/state", "/\\api/state", "http://x/api/state"):
            self.assertIn(req("GET", p, cookie="")[0], (400, 401, 404), p)
        self.assertEqual(req("GET", "/API/STATE")[0], 401)

    def test_h_forged_proxy_headers_dont_sign_in(self):
        h = {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1", "Remote-User": "owner", "X-Forwarded-Proto": "https"}
        self.assertEqual(req("GET", "/api/state", headers=h)[0], 401)

    def test_i_wrong_password_then_throttled(self):
        last = 0
        for _ in range(8):
            last = req("POST", "/api/login", {"user": "owner", "password": "wrong password here"})[0]
        self.assertIn(last, (401, 429))
        self.assertTrue(any(req("POST", "/api/login", {"user": "owner", "password": "still wrong"})[0] == 429 for _ in range(4)))
        authweb.THROTTLE.__init__()

    def test_i2_ten_wrong_tries_sign_a_session_out(self):
        forgive()
        cook = cookie_of(req("POST", "/api/login", {"user": "owner", "password": self.PW})[3])
        out = []
        for i in range(12):
            authweb.THROTTLE.__init__()
            web._session_tries.update({k: (v[0], 0) for k, v in web._session_tries.items()})   # (skip the waits)
            out.append(req("POST", "/api/account/password", {"password": f"wrong-password-{i:02d}", "new": self.PW + "-2"}, cook)[0])
            if i == 9:
                self.assertEqual(req("GET", "/api/state", cookie=cook)[0], 401, "the 10th wrong try signs it out at once")
        self.assertEqual(out[:9], [403] * 9)
        self.assertEqual(out[9:], [401, 401, 401])
        forgive()

    def test_j_logout_ends_session(self):
        forgive()
        s = req("POST", "/api/login", {"user": "owner", "password": self.PW})
        cook = cookie_of(s[3])
        self.assertEqual(req("POST", "/api/logout", {}, cook)[0], 200)
        self.assertEqual(req("GET", "/api/state", cookie=cook)[0], 401)

    def test_l_two_step_flow(self):
        forgive()
        s = req("POST", "/api/login", {"user": "owner", "password": self.PW})
        cook = cookie_of(s[3])
        start = json.loads(req("POST", "/api/account/totp/start", {"password": self.PW}, cook)[1])
        code = auth.totp_code(start["secret"], int(time.time()) // 30)
        done = req("POST", "/api/account/totp/confirm", {"code": code}, cook)
        self.assertEqual(done[0], 200)
        self.assertEqual(len(json.loads(done[1])["recovery"]), auth.RECOVERY_COUNT)
        self.assertEqual(req("GET", "/api/state", cookie=cook)[0], 401, "old sessions end when two-step turns on")
        forgive()
        first = req("POST", "/api/login", {"user": "owner", "password": self.PW})
        self.assertTrue(json.loads(first[1]).get("code_due"))
        self.assertEqual(cookie_of(first[3]), "", "no session before the code")
        pre = cookie_of(first[3], "podburrow-pre")
        self.assertEqual(req("GET", "/api/state", cookie=pre)[0], 401)
        self.assertEqual(req("POST", "/api/login/code", {"code": "000000"}, pre)[0], 401)
        rec = json.loads(done[1])["recovery"][0]
        ok = req("POST", "/api/login/code", {"code": rec}, pre)
        self.assertEqual(ok[0], 200)
        B_Account.session = cookie_of(ok[3])
        self.assertEqual(req("GET", "/api/state", cookie=B_Account.session)[0], 200)
        forgive()
        again = req("POST", "/api/login", {"user": "owner", "password": self.PW})
        self.assertEqual(req("POST", "/api/login/code", {"code": rec}, cookie_of(again[3], "podburrow-pre"))[0], 401, "a recovery code works once")

    def test_k_no_secret_in_state(self):
        d = req("GET", "/api/auth/state")[1].decode()
        self.assertNotIn("hash", d)
        self.assertNotIn("owner", d)


if __name__ == "__main__":
    unittest.main()
