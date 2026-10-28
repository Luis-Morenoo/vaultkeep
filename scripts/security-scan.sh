#!/usr/bin/env bash
# Pre-release security scan for VaultKeep.
# Runs every scanner in a Docker container, so nothing is installed on the host.
# Usage (from the repo root, Docker Desktop running):
#   bash scripts/security-scan.sh            # scan this working copy + its history
#   bash scripts/security-scan.sh --fresh    # also clone from GitHub and rescan the clone
set -u
export MSYS_NO_PATHCONV=1                   # stop Git Bash rewriting /container/paths

# Docker on Windows needs a Windows-style path (E:/...); elsewhere $PWD is fine
host_path() { (cd "$1" && (pwd -W 2>/dev/null || pwd)); }
REPO=$(host_path .)
OUT=security-reports
# Start empty: some tools (pip-audit) write no file when clean, so a stale
# report from an earlier run must never be mistaken for the current one
rm -rf "$OUT" 2>/dev/null; mkdir -p "$OUT"
status=0

scan_history() {   # $1 = host path of a git repo, $2 = report prefix
  echo "== gitleaks ($2): full history, all refs"
  docker run --rm -v "$1:/repo" ghcr.io/gitleaks/gitleaks:latest \
    git /repo --log-opts="--all" --redact --verbose \
    --report-format json --report-path "/repo/$OUT/$2-gitleaks.json" || status=1

  echo "== trufflehog ($2): full history, all branches"
  docker run --rm -v "$1:/repo" trufflesecurity/trufflehog:latest \
    git file:///repo --no-update --fail --json > "$OUT/$2-trufflehog.json" || status=1
  grep -c '"DetectorName"' "$OUT/$2-trufflehog.json" | sed 's/^/   trufflehog findings: /'
}

scan_history "$REPO" local

echo "== commit author / committer emails (every commit)"
git log --all --format='%an <%ae> | %cn <%ce>' | sort | uniq -c | tee "$OUT/authors.txt"

echo "== bandit + pip-audit"
# Each tool's exit code is captured before printing its report, so a finding
# fails the scan (piping into cat/tee would hide the tool's own exit code)
docker run --rm -v "$REPO:/src" -w /src python:3.12-slim sh -c '
  pip install -q --disable-pip-version-check bandit pip-audit || exit 2
  echo "-- bandit"
  bandit -r vaultkeep run.py -f txt -o security-reports/bandit.txt; b=$?
  cat security-reports/bandit.txt
  echo "-- pip-audit"
  pip-audit -r requirements.txt --desc on -o security-reports/pip-audit.txt; a=$?
  cat security-reports/pip-audit.txt
  [ "$b" -eq 0 ] && [ "$a" -eq 0 ]' || status=1

echo "== semgrep (python + secrets rulesets)"
docker run --rm -v "$REPO:/src" semgrep/semgrep semgrep scan \
  --config p/python --config p/secrets --config p/flask \
  --metrics=off --error --text --exclude venv --exclude security-reports \
  --output /src/$OUT/semgrep.txt /src || status=1
cat "$OUT/semgrep.txt"

if [[ "${1:-}" == "--fresh" ]]; then
  TMP=$(mktemp -d)
  echo "== fresh clone from origin into $TMP"
  git clone --quiet --no-single-branch "$(git remote get-url origin)" "$TMP/vaultkeep"
  (cd "$TMP/vaultkeep" && git fetch --quiet --tags origin '+refs/heads/*:refs/remotes/origin/*')
  mkdir -p "$TMP/vaultkeep/$OUT"
  scan_history "$(host_path "$TMP/vaultkeep")" fresh
  cp "$TMP/vaultkeep/$OUT"/fresh-* "$OUT"/ 2>/dev/null
fi

echo
[[ $status -eq 0 ]] && echo "RESULT: all scanners exited clean" \
                  || echo "RESULT: at least one scanner reported findings - see $OUT/"
exit $status
