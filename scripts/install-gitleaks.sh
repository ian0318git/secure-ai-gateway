#!/usr/bin/env bash
# Install the pinned gitleaks binary into .venv/bin.
#
# gitleaks is a Go program, not a Python package, so it cannot come in
# through `pip install -e ".[dev]"` the way ruff/mypy/bandit do. This
# script is what the pre-commit gate tells you to run when the binary
# is missing.
#
# The version is PINNED and the SHA-256 is verified against the
# published checksums file before anything is moved into place. A
# secret scanner that can be silently swapped out is worse than no
# secret scanner: it reports "clean" and you believe it.
#
# Usage:  scripts/install-gitleaks.sh [DEST_DIR]
#         Defaults to .venv/bin (where the pre-commit gate looks for it).
#         CI passes a temp dir, since there is no venv there.
#         GITLEAKS_VERSION overrides the pinned version.

set -euo pipefail

VERSION="${GITLEAKS_VERSION:-8.30.1}"
DEST="${1:-$(git rev-parse --show-toplevel)/.venv/bin}"

case "$(uname -m)" in
    x86_64)          ARCH="x64" ;;
    aarch64|arm64)   ARCH="arm64" ;;
    *) echo "install-gitleaks: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

case "$(uname -s)" in
    Linux)  OS="linux" ;;
    Darwin) OS="darwin" ;;
    *) echo "install-gitleaks: unsupported OS $(uname -s)" >&2; exit 1 ;;
esac

if [ ! -d "$DEST" ]; then
    echo "install-gitleaks: $DEST does not exist — create it first" >&2
    exit 1
fi

ASSET="gitleaks_${VERSION}_${OS}_${ARCH}.tar.gz"
BASE="https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}"

TMP="$(mktemp -d)"
# shellcheck disable=SC2064  # expand TMP now, not at trap time
trap "rm -rf '$TMP'" EXIT

echo "install-gitleaks: downloading $ASSET"
curl -fsSL -o "$TMP/$ASSET" "$BASE/$ASSET"
curl -fsSL -o "$TMP/checksums.txt" "$BASE/gitleaks_${VERSION}_checksums.txt"

echo "install-gitleaks: verifying SHA-256"
( cd "$TMP" && grep "  $ASSET\$" checksums.txt > want.txt )
if [ ! -s "$TMP/want.txt" ]; then
    echo "install-gitleaks: $ASSET not listed in the checksums file" >&2
    exit 1
fi
( cd "$TMP" && sha256sum -c want.txt )

tar -xzf "$TMP/$ASSET" -C "$TMP" gitleaks
install -m 0755 "$TMP/gitleaks" "$DEST/gitleaks"

echo "install-gitleaks: installed $("$DEST/gitleaks" version) -> $DEST/gitleaks"
