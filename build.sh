#!/bin/sh
# Builds Apex Activity Manager Server Edition for Linux (x86_64 and aarch64,
# static: runs on any distribution) into one download:
#   dist/apex-server-<version>-linux.tar.gz  (install.sh + both programs + README)
set -eu
cd "$(dirname "$0")"
GO=${GO:-$(command -v go || echo /opt/homebrew/bin/go)}
VERSION=$(sed -n 's/^var version = "\(.*\)"/\1/p' main.go)
OUT=${BUILD_DIR:-${TMPDIR:-/tmp}/apex/server-edition}
STAGE="$OUT/apex-server-$VERSION"
rm -rf "$STAGE"; mkdir -p "$STAGE" dist
"$GO" vet ./...
"$GO" test ./...
for a in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$a "$GO" build -trimpath -ldflags "-s -w" -o "$STAGE/apex-server-linux-$a" .
done
cp install.sh README.md LICENSE "$STAGE/"
chmod +x "$STAGE/install.sh"
# No macOS extended attributes in the archive (Linux tar warns about them).
COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -C "$OUT" -czf "dist/apex-server-$VERSION-linux.tar.gz" "apex-server-$VERSION"
TGZ="dist/apex-server-$VERSION-linux.tar.gz"
(cd dist && shasum -a 256 "apex-server-$VERSION-linux.tar.gz" > "apex-server-$VERSION-linux.tar.gz.sha256")
# Signed for automatic updates (servers install only releases signed with this key).
KEY=${APEX_RELEASE_KEY:-$HOME/.config/apex-release/server-edition-ed25519.key}
if [ -f "$KEY" ]; then "$GO" run ./tools/sign "$KEY" "$TGZ"; echo "Signed $TGZ.sig"
else echo "Not signed (no release key at $KEY): servers won't install this automatically."; fi
echo "Built dist/apex-server-$VERSION-linux.tar.gz ($(du -h "dist/apex-server-$VERSION-linux.tar.gz" | cut -f1))"
