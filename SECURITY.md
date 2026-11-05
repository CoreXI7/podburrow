# Security

Podburrow runs on your own server and downloads whatever the feeds you subscribe to tell it to, so it treats feeds,
filenames and media as untrusted. This page says how to report a problem, what counts, and which versions get fixes.

## Reporting a vulnerability

Please **don't open a public issue**. Use GitHub's private report instead: the repository's **Security** tab →
**Report a vulnerability**. Include what you found, how to reproduce it, and which version (release tag or commit) you
ran. This is a small hobby project: expect an answer within about a week, and if it's a real problem, a fix in the next
release. Please give it a chance to ship before you write about it publicly. Thank you for looking.

## Which versions get fixes

Only the **latest release** gets security fixes. There are no backport branches and no fixes for older releases: if
you're on an older version, upgrade first and check whether the problem is still there. Once a fix ships it gets a
GitHub Security Advisory on the repository, so other users can see what to update to.

## What's in scope

In scope — the app as shipped from this repository:

- the web UI and its API, including any sign-in or access control
- feed fetching and parsing (RSS/Atom), and the enclosures/media it points at
- download handling: where files land, what names they get, and what gets written or deleted
- the container image built from this repository

Especially interesting: anything that lets someone who can reach the UI — or a feed you subscribe to — read or write
files outside the download folder, run commands on the host, get at stored credentials, cookies or API tokens, or make
the app fetch something it shouldn't (local addresses, its own files, cloud metadata endpoints).

Out of scope:

- problems that need shell access to the host or admin rights on the container
- misconfiguration: exposing it to the internet without sign-in or TLS, running it as root, mounting the whole
  filesystem, or leaving the download folder world-writable
- bugs in third-party software or dependencies that aren't specific to how Podburrow uses them — report those upstream
- missing hardening headers, rate limits or brute-force protection on a server you already control, self-XSS, and
  "someone who can reach the port can use resources"
- scanner output with no explanation of impact, and reports about the version banner alone

If you're not sure whether something is in scope, report it privately anyway and say so.
