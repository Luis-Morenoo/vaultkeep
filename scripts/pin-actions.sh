#!/usr/bin/env bash
# Pin every GitHub Action in .github/workflows to a full commit SHA, keeping the
# tag as a comment (e.g. actions/checkout@<sha> # v4). Tags can be moved by the
# action's owner; a SHA can't. Dependabot keeps pinned SHAs up to date.
# Run once from the repo root:  bash scripts/pin-actions.sh
set -euo pipefail
for wf in .github/workflows/*.yml; do
  grep -oE 'uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@v[0-9][A-Za-z0-9_.-]*' "$wf" | sort -u | while read -r _ ref; do
    repo=${ref%@*}; tag=${ref#*@}
    # ^{} dereferences annotated tags to the commit they point at
    sha=$(git ls-remote "https://github.com/$repo" "refs/tags/$tag^{}" | cut -f1)
    [[ -z "$sha" ]] && sha=$(git ls-remote "https://github.com/$repo" "refs/tags/$tag" | cut -f1)
    if [[ -z "$sha" ]]; then echo "!! could not resolve $ref" >&2; exit 1; fi
    sed -i "s#uses: $repo@$tag\$#uses: $repo@$sha \# $tag#" "$wf"
    echo "pinned $repo@$tag -> $sha"
  done
done
