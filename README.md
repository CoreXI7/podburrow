# Podburrow

Podburrow is a self-hosted podcast downloader. Give it a podcast feed and it keeps the show up to date, downloading every
episode into a library that Plex reads as music.

It runs in Docker, has a small web page for adding shows and watching downloads, and keeps its own database and covers
apart from the media library.

## Contents

- [What it is](#what-it-is)
- [What it does](#what-it-does)
- [Install](#install)
- [Using it](#using-it)
- [Updating](#updating)
- [Security](#security)
- [License](#license)

## What it is

Podburrow is a single small server with a worker thread that checks feeds and downloads episodes one at a time. It uses
Python's standard library plus mutagen for tags, and a SQLite database for shows and episodes. There is no external
service to run and it never asks Plex for permission: Plex's own "scan automatically when files change" picks up each
finished file.

## What it does

It follows the feeds you add and checks them on a schedule. Every episode it has not seen before is queued and
downloaded, oldest first, with a number that becomes its Plex track number. A show can be added with its whole back
catalogue or from the newest episode only.

Files are laid out the way Plex's music library wants them: one folder per show, one folder per year, and inside that
`NNN - YYYY-MM-DD - Title.ext`. Year folders exist because one album with hundreds of tracks makes Plex slow. Tags say
artist and album artist are the show, album is the show and year, track is the episode number, genre is Podcast, and
the date, title and cover are filled in. Album compilation flags and sort tags are removed because they split a show
into "Various Artists". A `cover.jpg` goes in each year folder and an `artist.jpg` in the show folder.

Downloads are resumable in the sense that a failed or interrupted episode is tried again with a growing delay, up to
once a day, and it never gives up for good. Podburrow retries network trouble sooner, waits a while between shows when a
host is in trouble, and pauses when the podcast drive is missing or has less than 20 GB free. When a feed host changes
an episode's download link, Podburrow picks up the new link instead of retrying a dead one. An episode whose file you
deleted is marked missing and left alone; it is not downloaded again by itself.

Coming from Podgrab, a migration tool imports the shows you follow and the episodes already on disk, so the library is
not downloaded a second time. Stop Podburrow before running it: the server holds a lock on the data folder and the tool
refuses to start while that lock is held. Details are in
[docs/MIGRATING-FROM-PODGRAB.md](docs/MIGRATING-FROM-PODGRAB.md).

## Install

You need Docker with Compose, a data folder, and a media folder on the podcast drive. Podburrow expects the drive to be
mounted: put an empty file named `.podcasts-media` in the root of the media folder. If the file is gone, Podburrow assumes
the drive is not mounted and pauses rather than filling a folder on the system disk.

1. Copy `docker-compose.yml` from the repository and set the data and media volume paths. Set `TZ` so dates and year
   folders follow your local time.
2. Set `ALLOWED_HOSTS` to the address you will open Podburrow at (it answers only requests for hosts it knows), and set
   set `HOME_NAMES` to a hostname that resolves to your home's public address. Podburrow then refuses to download from
   that address, so a feed can't loop back through your router, and downloads wait until the name resolves. Without it
   that check is off, and the log says so.
3. Start it with `docker compose up -d`. The web page listens on port 8000 inside the container.
4. Keep Podburrow on its own Docker network that only your reverse proxy joins, and give it an HTTPS address at the proxy.
5. Open the address and create the first login.

The settings and reverse proxy notes are in `docker-compose.yml` and `.env.example`.

## Using it

Add a show with its feed address, or search by name. Episode search sends the text you type to Apple's iTunes API and
shows the matching podcasts; Podburrow only adds the feed you choose. Nothing else about your library is sent.

The show page lists episodes and what happened to each: queued, downloading, downloaded, failed, or missing. A show
can be paused, failed episodes retried, and a show unfollowed; unfollowing leaves the downloaded files in place.
Checks run every four hours by default and can be set from every 30 minutes to every 24 hours.

Podburrow has its own sign-in by default. If you already run an SSO proxy, set `AUTH=proxy` and point `TRUSTED_PROXY` at
that proxy instead; Podburrow then relies on the user the proxy has already signed in. Do not set proxy mode without a
proxy you control in front of it.

## Updating

Pull the new version and recreate the container:

```sh
docker compose pull
docker compose up -d
```

Your database, covers and downloaded episodes are kept, and the database is upgraded on start. Back up the data folder
before a large update.

## Security

Podburrow is the part of your network that talks to podcast hosts, so its fetching is deliberately narrow. It only fetches
http and https links on ports 80 and 443, and only to public IPv4 addresses. The address is checked after DNS and again
on every redirect, the connection is made to the address that was checked, TLS certificates are verified, and links
back to your own public address are refused.

Feeds must use a small set of common encodings, and DOCTYPE and ENTITY declarations are refused. They are parsed in a
separate process with a hard memory cap, and tags are written by another capped process, so a hostile feed or file
cannot take the server down with it. Downloads are capped in size and time, written as a `.part` file and renamed into
place only when complete and tagged. File and folder names are cleaned and length-limited, and every path is kept
inside the media folder.

The web side requires a known Host header and a token header on every change. The app is built to sit on a Docker
network only your reverse proxy can reach, and the container itself does not need extra permissions. With
`AUTH=proxy`, only the proxy named in `TRUSTED_PROXY` is believed about who is signed in.

Security review is still in progress. It will be reviewed by AI agents, not a paid audit.

## License

MIT
