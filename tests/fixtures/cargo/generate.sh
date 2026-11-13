#!/bin/sh
# Regenerates vulnproj/Cargo.lock with the real cargo (the only generated file here).
# vulnproj: smallvec 1.6.0 (RUSTSEC-2021-0003) direct, smallvec 0.6.x transitive via
# unicode-normalization 0.1.8, a path crate named like a published crate (`time`).
set -eu
cd "$(dirname "$0")/vulnproj"
rm -f Cargo.lock
cargo generate-lockfile
