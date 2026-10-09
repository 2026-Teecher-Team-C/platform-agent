#!/bin/bash
# packaging/macos/build-pkg.sh — dist/teecher-agent(PyInstaller onedir) → dist/teecher-agent.pkg
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION="${AGENT_VERSION:-0.1.0}"
STAGE=build/pkgroot
APP="$STAGE/Applications/Teecher Agent"

rm -rf "$STAGE"
mkdir -p "$APP"
cp -R dist/teecher-agent/. "$APP/"
cp packaging/agent.conf packaging/macos/uninstall.sh "$APP/"
chmod 755 "$APP/uninstall.sh" packaging/macos/scripts/postinstall
pkgbuild --root "$STAGE" --scripts packaging/macos/scripts \
  --identifier kr.teecher.agent --version "$VERSION" --install-location / \
  dist/teecher-agent.pkg
