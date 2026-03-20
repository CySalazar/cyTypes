#!/bin/bash
set -euo pipefail
dotnet build src/CyTypes.Analyzer/CyTypes.Analyzer.csproj --verbosity normal
dotnet test tests/CyTypes.Analyzer.Tests/CyTypes.Analyzer.Tests.csproj --verbosity normal
