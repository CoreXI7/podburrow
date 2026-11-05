# Threat model

## In short

Podburrow fetches files that strangers control and writes them to your disk, so feeds and media are treated as hostile. The web
page is either protected by its own sign-in or reachable only through your reverse proxy. It was reviewed by AI agents, not a
paid audit, and no software can promise there are no bugs.

## What it protects

- Your server and network, from feeds that try to reach them.
- Your disk, from files that try to fill or escape the media folder.
- The app itself, from people who aren't signed in.

## What it defends against

| Threat | Defence |
|---|---|
| A feed pointing at your LAN, Docker names or a metadata address | Public IPv4 only, ports 80 and 443, checked after DNS and on every redirect; the connection is pinned to the checked address |
| A feed looping back through your router | Addresses behind `HOME_NAMES` are refused. Set it: without it this check is off |
| XML bombs and floods | DOCTYPE and entities refused; parsing runs in a separate process with memory and CPU limits |
| Hostile audio files | Tags are written in a separate process with memory and CPU limits; downloads have size and time limits |
| Slow or stalled hosts | A hard deadline per fetch, enforced on the socket and after connecting |
| Names that escape the media folder | Names are cleaned, capped and checked to stay inside it; symlinks are refused |
| Guessing passwords | scrypt hashes, a common-password blocklist, growing waits, optional authenticator codes and recovery codes |
| Requests from other sites | SameSite cookies, Origin and Sec-Fetch checks, a custom header on actions, a Host allowlist |
| Hostile text reaching the page | Output is escaped, and a CSP refuses inline and outside scripts |
| Slow web clients | Connection caps and read deadlines |

## What it doesn't defend against

- Someone with access to the host, the Docker socket or the data folder.
- A reverse proxy that is misconfigured in `AUTH=proxy` mode: its sign-in is then your only protection.
- Plain HTTP outside your own network: use HTTPS.
- Hostile audio reaching other software: your media player still opens these files.
- Bugs in Python, mutagen or the base image.

## What leaves your server

- Requests to the feeds and hosts you follow.
- Episode search text, sent to Apple's iTunes API.
