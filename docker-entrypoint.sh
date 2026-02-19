#!/bin/sh
# AtilKurt Docker entrypoint: run with env vars or pass full args

set -e

if [ -n "$ATILKURT_DOMAIN" ] && [ -n "$ATILKURT_USER" ] && [ -n "$ATILKURT_DC_IP" ]; then
    OUTPUT="${ATILKURT_OUTPUT:-/output/report.html}"
    # Password is passed via ATILKURT_PASS env var (read by AtilKurt.py directly).
    # The --password CLI flag is deprecated; the app will pick up ATILKURT_PASS
    # automatically from the environment.
    exec python3 AtilKurt.py --domain "$ATILKURT_DOMAIN" --username "$ATILKURT_USER" \
        --dc-ip "$ATILKURT_DC_IP" --output "$OUTPUT" "$@"
fi

# No env vars: run exactly what was passed (e.g. --help or full CLI)
exec python3 AtilKurt.py "$@"
