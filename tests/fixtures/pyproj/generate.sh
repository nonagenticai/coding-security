#!/bin/sh
# Regenerates pyproj/uv.lock with the real uv (the only generated file here).
set -eu
cd "$(dirname "$0")"
rm -f uv.lock
uv lock
