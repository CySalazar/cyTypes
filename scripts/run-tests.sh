#!/bin/bash
set -euo pipefail

# Clean resource forks (macOS shared volume artifact)
find . -name '._*' -delete 2>/dev/null || true

# Build and test with single-thread to avoid file locking on shared volumes
dotnet build cyTypes.sln --no-restore -m:1 --verbosity quiet
dotnet test cyTypes.sln --no-build --verbosity normal
