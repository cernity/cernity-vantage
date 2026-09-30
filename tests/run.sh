#!/bin/sh
# Cernity Vantage test runner — plain-python asserts, no framework (plan 010 Track A).
# Runs every tests/test_*.py; any failure aborts with a nonzero exit.
set -e
cd "$(dirname "$0")/.."
PY="${PY:-python3}"
for t in tests/test_*.py; do
  echo "== $t =="
  "$PY" "$t"
done
echo "ALL TESTS PASSED"
