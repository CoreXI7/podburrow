#!/bin/sh
# Each file runs in its own process: the app reads its settings when it is imported.
cd "$(dirname "$0")" || exit 2
rc=0
for t in test_*.py; do python3 -m unittest "${t%.py}" >/tmp/podburrow-test.$$ 2>&1 || { echo "FAILED: $t"; cat /tmp/podburrow-test.$$; rc=1; }; done
rm -f /tmp/podburrow-test.$$
[ $rc = 0 ] && echo "All test files passed."
exit $rc
