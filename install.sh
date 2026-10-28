#!/bin/sh
# Minimal launcher; the reviewed installer is pinned by commit and digest.
# Define the complete function before invoking it so a partial download stops.
sigvid_install() (
    set -eu
    umask 077
    directory=$(mktemp -d /tmp/sigvid-installer.XXXXXXXX)
    trap 'rm -rf "$directory"' EXIT
    trap 'exit 1' HUP INT TERM
    curl -fsS --proto '=https' --tlsv1.2 --max-time 90 --max-filesize 131072 \
        'https://raw.githubusercontent.com/norvidinc/sigvid-agentic-defense-v6-beta-install/b96de83b3405e63316142968cfb6b62d83d8a70e/install.py' \
        -o "$directory/install.py"
    printf '%s  %s\n' 'f926dab29d5b69074a985d9e2c060b4ca3cde792fc2623b97f4c3043c07f36d2' "$directory/install.py" | sha256sum --check --status || {
        printf '%s\n' 'Installer checksum verification failed. Nothing was installed.' >&2
        exit 1
    }
    /usr/bin/python3 "$directory/install.py" "$@"
)
sigvid_install "$@"
