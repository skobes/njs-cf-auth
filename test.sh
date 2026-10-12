#!/bin/sh

cd "$(dirname "$0")" || exit 1
for engine in njs QuickJS; do
  echo "=== $engine ==="
  njs -n "$engine" -p "$PWD" -m njs_cf_auth_test.js
done
