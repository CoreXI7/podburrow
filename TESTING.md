# Testing Podburrow

How Podburrow is tested, what the tests cover, and what they don't. Six test files, standard library plus optional mutagen,
no network.

## Run the tests yourself

```sh
cd tests
sh run.sh
```

The tests import the app from `../app` (and the tools from `../tools`), and point `DATA` and `MEDIA` at throwaway temp
folders, so they never touch a real library. `mutagen` is optional: the tagger tests, and the migrate undo tests, skip
themselves when it isn't installed.

## What's tested, and how

| File | What |
|---|---|
| `test_feeds.py` | Feed safety and parsing: UTF-16/32 and unknown encodings refused, `DOCTYPE`/entity-expansion and external-DTD attacks refused, malformed and empty input refused; channel and item fields, defaults, size caps, relative enclosure URLs, guid fallback, element floods; the standalone `feedparse.py` worker (exit codes, JSON on stdout) |
| `test_fetch.py` | The outbound-request policy: `public_addr` refuses loopback, private, link-local/metadata, multicast and other non-global addresses, never resolves IPv6, only allows ports 80/443, and blocks a name if any answer is private; DNS failure handling and home-IP blocking; `fetch` with mocked sockets/connections (bad schemes, URLs with credentials, redirects, HTTP error classes, DNS pinning); `Guard` deadlines and stall messages; `read_capped` body limits |
| `test_names.py` | Naming and path helpers: `safe_name` (separators, traversal, control characters, reserved DOS names, byte caps), `clean_text` (tags, entities, control characters), date parsing and local time, `episode_path` layout with traversal-proof titles, `under_media` containment including symlinks, `sniff_ext` audio detection, `id3_size` header decoding |
| `test_state.py` | The SQLite state: schema creation, idempotent init, migration of an older database, settings defaults and bounds, `store_episodes` numbering/dedup/limits, `refresh_links`, retry backoff, `mark_missing`, the `state()` summary, `episodes()` ordering, and every `act()` action (pause, remove, retry, get-all, settings) |
| `test_migrate.py` | Reading a Podgrab database (live shows only, deleted rows dropped, items sorted by date), mapping old download paths into the media folder including escape attempts, and the journal/undo logic (torn lines skipped, last state wins, aside/start/done entries restored or cleared) |
| `test_tagger.py` | `tagger.py` tag writing: ID3 fields for the show, album, title, track, date, genre and comment, the summary cap, replacing old tags, embedded PNG/JPEG covers, rejection of corrupt m4a/ogg and wrong-extension files, AAC left untouched; plus the server-side helpers (`id3_size`, `cover_file`, symlink-safe `create_new`, `place_covers`, and `write_tags` job building and subprocess failures) |

Nothing real is contacted. No test binds or dials anything beyond `127.0.0.1`; the fetch tests replace DNS and the
connection classes with mocks, and the only addresses they use are loopback/private fixtures that must be refused. Every
feed body, cover, tag job and subprocess result is a local fixture. Test data lives in temp folders removed afterwards.

## What isn't covered

- **The HTTP layer**: routing, the API endpoints as actually served, static files, request parsing and response
  headers are not driven through a real server; the functions behind them are tested directly.
- **The running app**: the scheduler and worker threads, the full check-feed-download-tag pipeline, and what happens
  when they are interrupted.
- **Real downloads and real feeds**: no live feed is fetched, no audio is downloaded, no cover is fetched from a site,
  and no real DNS or TLS is exercised.
- **Real audio**: tag tests run on empty or hand-made files, not on real encodes; playback and stream layout are out of
  scope.
- **A real migration**: the Podgrab reader and undo journal are tested against synthetic databases and files, not a
  large real library.
- **The web page**: the UI, its escaping in a browser, and layout/accessibility are not tested here.
- **Platforms**: symlink behaviour and reserved-name handling are only checked for the machine the suite runs on;
  other operating systems and Python versions are untested by these files.
