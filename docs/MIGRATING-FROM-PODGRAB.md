# Migrating from Podgrab

`migrate.py` copies Podgrab's shows and already-downloaded episodes into Podburrow. It runs inside the Podburrow image and only reads Podgrab's database.

For each episode it copies the file next to its new place, writes the Plex tags on the copy, checks that the audio length is unchanged, renames it into place, keeps the old modification time and then deletes the original. The original tags are saved first, so `--undo` can put everything back.

Duplicates (the same episode stored twice, e.g. after a feed moved hosts) keep one file: the biggest, i.e. the best quality, filed under the ID the feed uses now. The other copies, and broken files (empty or HTML pages), are moved to the hidden `.podgrab-leftovers/` folder inside the media folder, so Plex ignores them. A file that cannot be moved is reported and left as it was; the run continues.

Every step is safe to kill and re-run.

## Before you start

1. **Stop the Podburrow server and Podgrab.** The migration refuses to run while the Podburrow server is up (it takes the same lock).
2. **Create the marker file** in the media folder: an empty file named `.podcasts-media`. The migration will not touch the media until it sees that file, so it can never act on an unmounted drive.

## Dry run

Do this first; it changes nothing:

```
docker compose run --rm --no-deps -v /path/to/podgrab:/podgrab:ro podburrow python3 /tools/migrate.py
```

Mount Podgrab's config folder read-only at `/podgrab` (it contains `podgrab.db`). The output lists, per show, how many episodes will be moved and how many will be downloaded again, plus any duplicates, broken files and unreadable files.

## Apply

Once the dry run looks right:

```
docker compose run --rm --no-deps -v /path/to/podgrab:/podgrab:ro podburrow python3 /tools/migrate.py --apply
```

The shows and episodes are added to Podburrow's database and the files are moved. New episodes stay `pending` until the run finishes, so the server will not start downloading them mid-migration. If an episode could not be moved, its file stays where it was and the episode stays `pending`; fix the file (usually permissions) and run `--apply` again.

If a cover cannot be downloaded, the run stops before moving anything; try again later.

## Undo

```
docker compose run --rm --no-deps podburrow python3 /tools/migrate.py --undo
```

This restores every moved file to its old name and folder, with its original tags and modification time, and puts the set-aside duplicates and broken files back. It reads the journal, so it does not need the Podgrab mount. The Podburrow database still lists the migrated shows after an undo; delete `data/podcasts.db` to forget them.

After a successful migration you can start the Podburrow server again and stop Podgrab.
