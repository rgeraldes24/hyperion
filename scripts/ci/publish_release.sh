#!/usr/bin/env bash
# Create a release or complete its assets without replacing published files.
set -euo pipefail

: "${GH_REPO:?Missing GitHub repository}"
: "${RELEASE_TAG:?Missing release tag}"
[[ $RELEASE_TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]] || {
    echo "Invalid release tag: $RELEASE_TAG" >&2
    exit 1
}

asset_dir=${1:-release}
assets=()
for name in hypc-static-linux hypc-macos hypc-windows.exe hypjson.js SHA256SUMS; do
    asset="$asset_dir/$name"
    [[ -s $asset ]] || { echo "Missing or empty release asset: $asset" >&2; exit 1; }
    assets+=("$asset")
done

# A successful list distinguishes an absent release from authentication/network errors.
# Paginate so rerunning an older release works as well.
release_id=$(gh api --paginate "repos/$GH_REPO/releases?per_page=100" \
    --jq ".[] | select(.tag_name == \"$RELEASE_TAG\") | .id")

if [[ -z $release_id ]]; then
    options=(--verify-tag --generate-notes --title "$RELEASE_TAG")
    [[ $RELEASE_TAG != *-* ]] || options+=(--prerelease)
    gh release create "$RELEASE_TAG" "${assets[@]}" "${options[@]}"
    exit 0
fi

existing_assets=$(gh release view "$RELEASE_TAG" --json assets --jq '.assets[].name')
download_dir=$(mktemp -d)
trap 'rm -rf "$download_dir"' EXIT
pending_assets=()

# Check every existing file before uploading anything, including the checksums.
for asset in "${assets[@]}"; do
    name=${asset##*/}
    if grep -Fxq -- "$name" <<< "$existing_assets"; then
        gh release download "$RELEASE_TAG" --pattern "$name" --dir "$download_dir"
        if ! cmp -s "$asset" "$download_dir/$name"; then
            echo "Existing release asset $name differs from this build; refusing to overwrite it." >&2
            exit 1
        fi
        echo "Keeping identical release asset: $name"
    else
        pending_assets+=("$asset")
    fi
done

if (( ${#pending_assets[@]} > 0 )); then
    gh release upload "$RELEASE_TAG" "${pending_assets[@]}"
else
    echo "Release $RELEASE_TAG already contains all matching assets."
fi
