"""Podburrow's adapter for signin-core's attack runner (signin-core tests/attack_core.py): a real Podburrow in login mode
in the sandbox, behind 127.0.0.1 as its trusted proxy, which sends X-Forwarded-Proto and X-Real-IP as a real proxy does.
The port is one the host firewall doesn't open (the app binds every address)."""
import os, socket, subprocess, sys, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "pod.example", 18496


class Adapter:
    name, cookie = "podburrow", "podburrow"
    setup_code_in_log = True   # (printed at start while there is no account: the docs read it with docker logs)
    pages = ("/",)
    public_get = ("/login", "/js/login.js", "/login.css", "/api/auth/state")
    private_get = ("/api/state", "/api/search?q=x", "/api/episodes?id=1")

    def start(self, base):
        self.lines, self.code = [], None
        data = os.path.join(base, "data")
        os.makedirs(data)
        env = {**os.environ, "DATA": data, "MEDIA": data, "AUTH": "login", "TRUSTED_PROXY": "127.0.0.1",
               "ORIGIN": f"https://{HOST}", "ALLOWED_HOSTS": HOST, "PORT": str(PORT)}
        self.proc = subprocess.Popen([sys.executable, "app/server.py"], env=env, cwd=ROOT,   # (as the container runs it)
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        threading.Thread(target=self._read, daemon=True).start()
        for _ in range(150):
            if self.code and self._up():
                return
            time.sleep(0.1)
        raise RuntimeError("Podburrow did not start: " + "".join(self.lines)[-400:])

    def _read(self):
        for line in self.proc.stdout:
            self.lines.append(line)
            if line.startswith("SETUP CODE:") and not self.code:
                self.code = line.split(":", 1)[1].split()[0]

    def _up(self):
        try:
            socket.create_connection(("127.0.0.1", PORT), 0.5).close()
            return True
        except OSError:
            return False

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()

    def log(self):
        return "".join(self.lines)

    def setup_code(self):
        return self.code

    def send(self, raw):
        s = socket.create_connection(("127.0.0.1", PORT), 30)
        try:
            s.sendall(raw)
            out = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    return out
                out += chunk
        except socket.timeout:
            return b"TIMEOUT"
        except OSError as exc:
            return repr(exc).encode()
        finally:
            s.close()

    def headers(self, ip):
        return [("Host", HOST), ("X-Forwarded-Proto", "https"), ("X-Real-IP", ip)]

    def csrf_ok(self):
        return [("Origin", f"https://{HOST}")]

    def csrf_bad(self):
        return [("no-Origin", []), ("foreign-Origin", [("Origin", "https://evil.example")]),
                ("cross-site", [("Origin", f"https://{HOST}"), ("Sec-Fetch-Site", "cross-site")])]
