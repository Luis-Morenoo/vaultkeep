#!/usr/bin/env bash
# Regenerate the hashed lockfiles from requirements.in and requirements-dev.in.
# Runs pip-compile in Docker (Linux, Python 3.12 - the same as CI and the image),
# so nothing is installed on the host. --generate-hashes records the sha256 of
# every published file for each pinned version, so the lockfiles also install
# on Windows and macOS.
set -euo pipefail
export MSYS_NO_PATHCONV=1   # stop Git Bash rewriting /container/paths

host_path() { (cd "$1" && (pwd -W 2>/dev/null || pwd)); }
cd "$(dirname "$0")/.."

docker run --rm -v "$(host_path .):/src" -w /src python:3.12-slim sh -c '
  set -e
  pip install -q --disable-pip-version-check pip-tools==7.6.0
  opts="--quiet --generate-hashes --allow-unsafe --strip-extras --no-emit-index-url"
  pip-compile $opts --output-file requirements.txt requirements.in
  pip-compile $opts --output-file requirements-dev.txt requirements-dev.in
'
echo "Locked: requirements.txt and requirements-dev.txt"
echo "Check:  pip install --require-hashes --only-binary :all: -r requirements-dev.txt"
