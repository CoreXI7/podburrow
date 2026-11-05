# Security review

What was checked before the first release, what was found, and what wasn't checked. This is a record of AI-assisted review, not a
paid audit or a guarantee.

## How it was done

Five independent AI agents each reviewed one area, on throwaway copies, and were asked to prove each finding with a working example:

1. The web API and sign-in
2. Outbound fetches
3. Hostile feeds and media files
4. The web pages
5. Files, disk, the container and the supply chain

Two more agents then re-checked the fixes. Findings were fixed, mostly with a test that failed first. Severity is the reviewer's own rating.

## What was found

All of these are fixed.

| Severity | Finding |
|---|---|
| High | The Docker image didn't contain the app, so it couldn't run |
| High | A hostile feed host could stall a connection during its TLS handshake and hang the only download worker |
| Medium | Slow connections could freeze the app without signing in |
| Medium | With a proxy named, other machines could still connect directly in login mode |
| Medium | A crafted audio file could burn CPU for minutes while its tags were read |
| Medium | A show that kept failing slowly could starve the other shows' downloads |
| Medium | The migration's `--apply` could mark an unmounted folder as the real drive, and `--undo` could give up on an unmounted drive |
| Medium | A DNS failure could forget the home address, so it was briefly reachable |
| Medium | The Account page never showed its warning when someone had the password but the wrong code |
| Low | Oversized headers used too much memory |
| Low | Old sessions came back after switching from proxy mode to the login |
| Low | Sibling sites could probe the API with GET requests |
| Low | Azure's host service address passed the public address check |
| Low | Some refusals had no security headers |
| Low | A crafted feed could be slow to parse, carry a huge image link, or be rejected over one bad episode |
| Low | An unreadable folder could crash startup, or mark episodes as deleted |
| Low | Recovery codes and secrets stayed in the page after closing the dialog |

Earlier tests also found episode dates going into the page unescaped, an empty feed stopping retries, and loose checks on actions.

The fifth reviewer also scanned the code and git history for personal data before publishing.

## Later changes

**Conditional feed checks** (unchanged feeds answer 304 and aren't downloaded again). Five reviews: three AI agents (outbound
fetches, state logic, tests and privacy) and two smaller models. Nothing above Low. Fixed: a wrong clock could stop the daily
full fetch, a 304 after a failed check could hide its error, a host's `ETag: *` would have matched every version, and *Check
now* now always fetches in full. Left as is: the stored ETag is also sent on redirect hops to another host. The redirecting
host already controls where it sends us, and the value is a cache tag, not a secret.

## What wasn't tested

- A security audit by a human
- Reverse proxies other than Nginx Proxy Manager. Its proxy mode was simulated in review, and checked on one live install up to the sign-in redirect
- Running on arm64. The image is built for it but hasn't been run
- Scanning the two-step QR code with a real phone. The codes themselves are tested
- Attacks against the base image, Python or mutagen themselves
- The sign-in code came from another project's audited code. Its functions were compared with the original, but its own review was AI-only too

## Known limits

See [THREAT-MODEL.md](../THREAT-MODEL.md). Without `HOME_NAMES`, a feed can reach your own public address. With `AUTH=proxy`, your proxy's sign-in is your only protection.
