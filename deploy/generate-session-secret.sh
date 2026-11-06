#!/bin/sh
# Create a persistent env file with a fresh 256-bit HMAC signing key.
set -eu

output=${1:-htxpro.env}
dir=$(dirname "$output")
base=$(basename "$output")

if [ -e "$output" ] || [ -L "$output" ]; then
    echo "refusing to overwrite existing secret file: $output" >&2
    exit 1
fi

command -v openssl >/dev/null 2>&1 || {
    echo "openssl is required to generate a session secret" >&2
    exit 1
}

umask 077
mkdir -p "$dir"
tmp=$(mktemp "$dir/.${base}.tmp.XXXXXX")
cleanup() {
    rm -f "$tmp"
}
trap cleanup EXIT HUP INT TERM

secret=$(openssl rand -hex 32)
printf 'HTXPRO_SESSION_SECRET=%s\n' "$secret" > "$tmp"
chmod 600 "$tmp"
# A hard link creates the destination atomically and fails if another process
# created it after the initial existence check.
if ! ln "$tmp" "$output"; then
    echo "refusing to overwrite existing secret file: $output" >&2
    exit 1
fi
rm -f "$tmp"
trap - EXIT HUP INT TERM
printf 'Wrote %s (mode 0600). Keep this file private and persistent.\n' "$output"
