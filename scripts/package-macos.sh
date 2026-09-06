#!/bin/bash
set -euo pipefail

# Packages AgentScan into a signed, notarized macOS .dmg.
#
# Local dev builds are ad-hoc signed (no env vars needed).
# A public release requires:
#   AGENTSCAN_SIGNING_IDENTITY  e.g. "Developer ID Application: Harish Gupta (V7SF7XDP3N)"
#   AGENTSCAN_NOTARY_PROFILE    a notarytool keychain profile name
# With both set, the script enables the hardened runtime, notarizes, and staples the ticket.

project_root="$(cd "$(dirname "$0")/.." && pwd)"
app_path="$project_root/src-tauri/target/release/bundle/macos/AgentScan.app"
dmg_dir="$project_root/src-tauri/target/release/bundle/dmg"
architecture="$(uname -m)"
app_version="$(awk -F'"' '/"version"/ { print $4; exit }' "$project_root/src-tauri/tauri.conf.json")"
dmg_path="$dmg_dir/AgentScan_${app_version}_${architecture}.dmg"
signing_identity="${AGENTSCAN_SIGNING_IDENTITY:--}"
notary_profile="${AGENTSCAN_NOTARY_PROFILE:-}"

if [[ "$signing_identity" != "-" && -z "$notary_profile" ]]; then
  echo "AGENTSCAN_NOTARY_PROFILE is required for a signed release" >&2
  exit 1
fi

cd "$project_root"
npx tauri build --bundles app --no-sign

if [[ "$signing_identity" == "-" ]]; then
  codesign --force --deep --timestamp=none --sign - "$app_path"
else
  codesign --force --deep --options runtime --timestamp --sign "$signing_identity" "$app_path"
fi
codesign --verify --deep --strict --verbose=2 "$app_path"

mkdir -p "$dmg_dir"
staging_dir="$(mktemp -d "${TMPDIR:-/tmp}/agentscan-dmg.XXXXXX")"
trap 'rm -rf "$staging_dir"' EXIT
ditto "$app_path" "$staging_dir/AgentScan.app"
ln -s /Applications "$staging_dir/Applications"
rm -f "$dmg_path"
hdiutil create -volname AgentScan -srcfolder "$staging_dir" -ov -format UDZO "$dmg_path"
hdiutil verify "$dmg_path"

if [[ "$signing_identity" != "-" ]]; then
  codesign --force --timestamp --sign "$signing_identity" "$dmg_path"
  xcrun notarytool submit "$dmg_path" --keychain-profile "$notary_profile" --wait
  xcrun stapler staple "$dmg_path"
  xcrun stapler validate "$dmg_path"
fi

echo "$app_path"
echo "$dmg_path"
