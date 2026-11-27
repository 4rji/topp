#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
work=$(mktemp -d "${TMPDIR:-/tmp}/topp-app.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
app="$work/topp.app"
mkdir -p "$app/Contents/MacOS" build
cp packaging/Info.plist "$app/Contents/Info.plist"
for target in arm64-apple-macos12 x86_64-apple-macos14; do
    xcrun swiftc -O -module-cache-path "$work/cache" -target "$target" \
        static/topp.swift -o "$work/$target"
done
xcrun lipo -create "$work/arm64-apple-macos12" "$work/x86_64-apple-macos14" \
    -output "$app/Contents/MacOS/topp"
/usr/bin/codesign --force --sign - "$app"
/usr/bin/ditto "$app" build/topp.app
/usr/bin/codesign --verify --strict build/topp.app
