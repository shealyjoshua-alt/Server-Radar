#!/bin/bash
# Builds dist/Server Radar.app from the local Electron runtime (no download step).
set -euo pipefail
cd "$(dirname "$0")/.."
STAGE=$(mktemp -d)
cp -R src config assets package.json package-lock.json "$STAGE/"
(cd "$STAGE" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund >/dev/null && rm -f package-lock.json)
APP="dist/Server Radar.app"
rm -rf "$APP" && mkdir -p dist
cp -R node_modules/electron/dist/Electron.app "$APP"
node node_modules/@electron/asar/bin/asar.mjs pack "$STAGE" "$APP/Contents/Resources/app.asar"
rm -f "$APP/Contents/Resources/default_app.asar"
PLIST="$APP/Contents/Info.plist"
plutil -replace CFBundleName -string "Server Radar" "$PLIST"
plutil -replace CFBundleDisplayName -string "Server Radar" "$PLIST"
plutil -replace CFBundleIdentifier -string "com.serverradar.app" "$PLIST"
rm -rf "$STAGE"
echo "built $APP"
