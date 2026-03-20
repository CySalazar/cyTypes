#!/bin/bash
set -euo pipefail
dotnet run --project tests/CyTypes.Benchmarks/CyTypes.Benchmarks.csproj -c Release -- "$@"
