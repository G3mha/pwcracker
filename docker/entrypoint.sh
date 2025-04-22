#!/bin/bash
set -e

# Check if we need to build first
if [ ! -f /app/build/pwcracker ]; then
    echo "Building project..."
    mkdir -p /app/build
    cd /app/build
    cmake ..
    make
fi

# If no arguments provided, show help
if [ $# -eq 0 ]; then
    exec /app/build/pwcracker --help
else
    exec /app/build/pwcracker "$@"
fi
