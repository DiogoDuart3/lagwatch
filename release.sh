#!/bin/sh
# Builds the app and packs it into a zip ready to attach to a GitHub release.
set -eu
cd "$(dirname "$0")"

# Keep the builder's home directory out of the paths baked into the binary.
export RUSTFLAGS="--remap-path-prefix=$HOME=~ --remap-path-prefix=$PWD=lagwatch"

cargo test --release
./bundle.sh --no-install

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
arch=$(uname -m)
zip="target/Lagwatch-$version-macos-$arch.zip"
rm -f "$zip"
# ditto keeps the bundle's signature and metadata intact, unlike zip.
ditto -c -k --keepParent target/Lagwatch.app "$zip"
# Record only the file name so `shasum -c` works next to the download.
(cd target && shasum -a 256 "$(basename "$zip")" | tee "$(basename "$zip").sha256")
