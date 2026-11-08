"""Podburrow's auth.py: the shared signin-core account layer (app/signin_core/auth.py), configured for Podburrow.
Kept at this path so the documented host commands work:
  docker exec -it <container> python /app/auth.py status | unlock | setup-code | signout | reset [--yes]
Imported as `auth`, it IS signin_core.auth (configured)."""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import authweb                                    # noqa: E402  (checks the pin, builds the Config, configures auth)
from signin_core import auth as _core             # noqa: E402

if __name__ == "__main__":
    sys.exit(_core.cli(authweb.CONFIG, sys.argv[1:]))
sys.modules[__name__] = _core
