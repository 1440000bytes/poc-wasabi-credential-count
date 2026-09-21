#!/usr/bin/env bash
# Fetches the exact WabiSabi 1.3.0 source + native binary the PoC runs against.
#   - NWabiSabi source pinned to the commit the 1.3.0 nupkg was built from
#   - libwabisabi.so extracted from the published nupkg on nuget.org
#   - an InternalsVisibleTo("Poc") shim so the PoC can build request records
set -euo pipefail
PIN=6ef358a962bb219c506479ffa6c828979cfb3903   # WabiSabi 1.3.0 (repository commit in the nuspec)

if [ ! -d NWabiSabi ]; then
  git clone https://github.com/zkSNACKs/NWabiSabi NWabiSabi
fi
( cd NWabiSabi && git checkout -q "$PIN" )

# Allow the PoC assembly to use the internal request constructors.
cat > NWabiSabi/csharp/WabiSabi/AssemblyInfo.Poc.cs <<'CS'
using System.Runtime.CompilerServices;
[assembly: InternalsVisibleTo("Poc")]
CS

# The source tree builds the native lib in CI; grab the published binary instead.
NUPKG=wabisabi.1.3.0.nupkg
if [ ! -f "$NUPKG" ]; then
  curl -sL -o "$NUPKG" https://api.nuget.org/v3-flatcontainer/wabisabi/1.3.0/wabisabi.1.3.0.nupkg
fi
mkdir -p NWabiSabi/csharp/WabiSabi/runtimes/linux-x64/native
unzip -o -q "$NUPKG" 'runtimes/linux-x64/native/libwabisabi.so' -d /tmp/wabisabi-nupkg
cp /tmp/wabisabi-nupkg/runtimes/linux-x64/native/libwabisabi.so \
   NWabiSabi/csharp/WabiSabi/runtimes/linux-x64/native/libwabisabi.so
cp /tmp/wabisabi-nupkg/runtimes/linux-x64/native/libwabisabi.so NWabiSabi/csharp/WabiSabi/libwabisabi.so

echo "setup done. Now: dotnet run --project Poc -c Release"
