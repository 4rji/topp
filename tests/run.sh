#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
workdir=$(mktemp -d "${TMPDIR:-/tmp}/topp-tests.XXXXXXXX")
trap 'rm -rf "$workdir"' EXIT
# Use the real parser, monitor, and findings engine, without starting the app.
awk '/^let args = Array\(CommandLine.arguments.dropFirst\(\)\)/ { found = 1; exit }
     { print } END { if (!found) exit 1 }' static/topp.swift > "$workdir/main.swift"
cat tests/network.swift tests/log.swift tests/process-actions.swift tests/collector.swift >> "$workdir/main.swift"
xcrun swiftc -module-cache-path "$workdir/cache" "$workdir/main.swift" -o "$workdir/check"
"$workdir/check"
