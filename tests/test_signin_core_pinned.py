"""The vendored signin-core copy matches its pin; with AUTH=proxy, importing the app opens none of the sign-in's files
(signin-core SPEC.md, Security model 2 and 5)."""
import os, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app")
sys.path.insert(0, APP)
from signin_core import verify  # noqa: E402


class Pinned(unittest.TestCase):
    def test_vendored_copy_matches_its_pin(self):
        ok, problems = verify.check(APP)
        self.assertTrue(ok, problems)

    def test_pin_matches_the_signin_core_release_when_present(self):
        src = os.path.expanduser("~/projects/signin-core/MANIFEST.sha256")
        if not os.path.exists(src):
            self.skipTest("signin-core repo not here")
        with open(src, "rb") as a, open(os.path.join(APP, verify.PIN_NAME), "rb") as b:
            self.assertEqual(a.read(), b.read(), "app/signin_core.pin differs from signin-core's MANIFEST.sha256: run tools/sync.py")


PROBE = r"""
import os, sys
names = ("auth.json", "sessions.json", "setup-code", ".auth.lock")
seen = []
def hook(event, args):
    if event in ("open", "os.remove", "os.rename", "os.stat", "os.listdir") and args and isinstance(args[0], (str, bytes)):
        if os.path.basename(os.fsdecode(args[0])) in names:
            seen.append((event, os.fsdecode(args[0])))
sys.addaudithook(hook)
sys.path.insert(0, sys.argv[1])
import authweb
assert authweb.AUTH == "proxy", authweb.AUTH
print("SEEN", seen)
"""


class ProxyModeTouchesNothing(unittest.TestCase):
    def test_import_in_proxy_mode_opens_no_signin_file(self):
        data = tempfile.mkdtemp(prefix="pb-pin-")
        env = {**os.environ, "DATA": data, "AUTH": "proxy", "TRUSTED_PROXY": "nginx"}
        r = subprocess.run([sys.executable, "-I", "-c", PROBE, APP], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        self.assertIn("SEEN []", r.stdout, r.stdout[-500:])


if __name__ == "__main__":
    unittest.main()
