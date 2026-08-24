#!/bin/sh
# AtilKurt Docker entrypoint: run with env vars or pass full args

set -e

if [ -n "$ATILKURT_DOMAIN" ] && [ -n "$ATILKURT_USER" ]; then
    if [ "$#" -eq 1 ] && [ "$1" = "--help" ]; then
        set --
    fi
    OUTPUT="${ATILKURT_OUTPUT:-/output/report.html}"
    # Password is passed via ATILKURT_PASS env var (read by AtilKurt.py directly).
    # The --password CLI flag is deprecated; the app will pick up ATILKURT_PASS
    # automatically from the environment.
    set -- --domain "$ATILKURT_DOMAIN" --username "$ATILKURT_USER" --output "$OUTPUT" "$@"
    if [ -n "$ATILKURT_DC_IP" ]; then
        set -- --dc-ip "$ATILKURT_DC_IP" "$@"
    fi
    exec python3 AtilKurt.py "$@"
fi

# No env vars: run exactly what was passed (e.g. --help or full CLI)
exec python3 AtilKurt.py "$@"
