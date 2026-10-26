#!/usr/bin/env bash
set -euo pipefail

# Run from any directory: bash scripts/build-release.sh v1.2.3 /tmp/release
# Release tags are published only after the Go and installer CI checks pass.
release_version=${1:?usage: build-release.sh VERSION OUTPUT_DIRECTORY}
output_dir=${2:?usage: build-release.sh VERSION OUTPUT_DIRECTORY}
if [[ ! $release_version =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo 'Version must have the form v1.2.3 or v1.2.3-rc.1' >&2
  exit 2
fi
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p -- "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd)
cd -- "$repo_dir"
release_commit=$(git rev-parse --verify HEAD)
release_epoch=$(git show -s --format=%ct HEAD)
staging_dir=$(mktemp -d)
trap 'rm -rf -- "$staging_dir"' EXIT

for target_arch in amd64 arm64; do
  target_dir="$staging_dir/$target_arch"
  mkdir -p -- "$target_dir"
  CGO_ENABLED=0 GOOS=linux GOARCH="$target_arch" go build -mod=readonly -trimpath \
    -ldflags="-s -w -buildid= -X main.version=$release_version -X main.commit=$release_commit" \
    -o "$target_dir/acbridge" .
  cp LICENSE "$target_dir/LICENSE"
  tar --sort=name --mtime="@$release_epoch" --owner=0 --group=0 --numeric-owner \
    -C "$target_dir" -cf - acbridge LICENSE | gzip -n > "$output_dir/acbridge_linux_$target_arch.tar.gz"
done
(
  cd -- "$output_dir"
  sha256sum acbridge_linux_amd64.tar.gz acbridge_linux_arm64.tar.gz > SHA256SUMS
)
echo "Built Linux amd64 and arm64 release archives in $output_dir"
