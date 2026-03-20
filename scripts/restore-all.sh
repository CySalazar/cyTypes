#!/bin/bash
set -euo pipefail
# Workaround for .NET 9 SDK solution-level restore issue on shared volumes.
# Restores each project individually then builds with --no-restore.
echo "Restoring all projects..."
for proj in src/*/*.csproj tests/*/*.csproj; do
    echo "  Restoring $proj"
    dotnet restore "$proj" --verbosity quiet
done
echo "All projects restored."
