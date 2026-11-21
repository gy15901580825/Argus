#!/usr/bin/env bash
set -euo pipefail

image=$1
platform=$2
version=$3
expected_probes=$4
if [[ ! "$expected_probes" =~ ^[1-9][0-9]*$ ]]; then
    echo "expected_probes must be a positive integer; got '$expected_probes'" >&2
    exit 1
fi
version_output=$(docker run --rm --platform "$platform" "$image" --version)
printf '%s\n' "$version_output"
[[ "$version_output" == "argus-probe, version $version" ]]
probe_output=$(docker run --rm --platform "$platform" "$image" list-probes)
printf '%s\n' "$probe_output"
[[ "$(printf '%s\n' "$probe_output" | tail -n 1)" == "$expected_probes probes" ]]
uid=$(docker run --rm --platform "$platform" --entrypoint id "$image" -u)
[[ "$uid" != 0 ]]
printf 'UID: %s\n' "$uid"
size=$(docker image inspect "$image" --format '{{.Size}}')
printf '%s uncompressed image size: %s bytes\n' "$platform" "$size"
