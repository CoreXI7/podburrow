#!/usr/bin/env python3
"""Parses one podcast feed in its own process with a hard memory cap (Claude, 2026-10-28; round-4 review).

server.parse_feed_safe() runs `python3 -I feedparse.py <base_url>` with the raw feed bytes on stdin. Whatever shape a
hostile feed takes (element or attribute floods, giant text nodes, ...), at worst this helper dies with MemoryError and
the feed is refused: the podcasts server itself never parses untrusted XML. Prints {"show": ..., "eps": [...]} as JSON.
Exit 0 = ok, 2 = refused (message on stderr), 3 = too much memory.
"""
import json, os, resource, sys

MEM = 220 << 20
OUT_MAX = 24 << 20                                # biggest answer the server will accept

if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_AS, (MEM, MEM))
    resource.setrlimit(resource.RLIMIT_CPU, (90, 95))
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import server as S                            # only its pure parsing functions are used here
        data = sys.stdin.buffer.read(S.FEED_MAX + 1)
        if len(data) > S.FEED_MAX:
            raise S.Blocked("feed is bigger than 16 MB")
        show, eps = S.parse_feed(data, sys.argv[1] if len(sys.argv) > 1 else "")
        out = json.dumps({"show": show, "eps": eps}, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "replace")
        if len(out) > OUT_MAX:                    # the server reads all of this: keep it far below its memory
            raise S.Blocked("the feed's episode list is too large")
        sys.stdout.buffer.write(out)
    except MemoryError:
        print("the feed needed too much memory to read (hostile or broken)", file=sys.stderr)
        sys.exit(3)
    except Exception as e:
        print(f"{e}"[:300] or type(e).__name__, file=sys.stderr)
        sys.exit(2)
