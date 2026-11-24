#!/bin/sh
set -eu

output="${1:?Pass the output directory}"
mkdir -p "$output"
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0
go build -mod=readonly -trimpath -buildvcs=false -o "$output/deploycore-agent.exe" .
(
    version="$(cat VERSION)"
    commit="${GITHUB_SHA:-unknown}"
    case "$commit" in
        unknown) ;;
        *[!a-fA-F0-9]*) exit 1 ;;
    esac
    toolchain="$(go env GOVERSION)"
    cp agent.wxs "$output/agent.wxs"
    cp upgrade-agent.ps1 "$output/upgrade-agent.ps1"
    cd "$output"
    wixl -a x64 -D "Version=$version" -D "Source=deploycore-agent.exe" \
        -o deploycore-agent.msi agent.wxs
    rm agent.wxs
    sha256sum deploycore-agent.exe deploycore-agent.msi upgrade-agent.ps1 > SHA256SUMS
    printf '{"version":"%s","commit":"%s","go":"%s","os":"windows","architecture":"amd64"}\n' \
        "$version" "$commit" "$toolchain" > build.json
)
