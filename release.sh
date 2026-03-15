#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Murari MacControl — Release packager
#
# Usage:
#   bash release.sh           # prompts for version
#   bash release.sh v1.2.0    # non-interactive
#
# Output:
#   releases/murari-maccontrol-v1.2.0.zip
#
# The zip contains ONLY files safe to distribute publicly:
#   server.py, index.html, setup.sh, README.md, LICENSE, CONTRIBUTING.md
#
# Sensitive / generated files (cert.pem, key.pem, config.json, ssl.cnf)
# are intentionally excluded.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# ── Version ───────────────────────────────────────────────────────────────────
VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo ""
  echo "  ┌──────────────────────────────────────┐"
  echo "  │  Murari MacControl — Release Builder  │"
  echo "  └──────────────────────────────────────┘"
  echo ""
  read -rp "  Version (e.g. v1.0.0): " VERSION
fi

# Strip leading 'v' for display, keep it for folder/zip naming
VERSION_NUM="${VERSION#v}"
VERSION_TAG="v${VERSION_NUM}"

echo ""
echo "  Building release ${VERSION_TAG}…"

# ── Output directory ─────────────────────────────────────────────────────────
RELEASES_DIR="$DIR/releases"
BUNDLE_NAME="murari-maccontrol-${VERSION_TAG}"
BUNDLE_DIR="$RELEASES_DIR/$BUNDLE_NAME"
ZIP_PATH="$RELEASES_DIR/${BUNDLE_NAME}.zip"

rm -rf "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR"

# ── Files to include ─────────────────────────────────────────────────────────
INCLUDE=(
  "server.py"
  "index.html"
  "setup.sh"
  "README.md"
  "LICENSE"
  "CONTRIBUTING.md"
  ".gitignore"
)

MISSING=()
for f in "${INCLUDE[@]}"; do
  if [[ -f "$DIR/$f" ]]; then
    cp "$DIR/$f" "$BUNDLE_DIR/$f"
    echo "  ✓ $f"
  else
    MISSING+=("$f")
    echo "  ✗ MISSING: $f"
  fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo ""
  echo "  ✗ Aborting — missing files: ${MISSING[*]}"
  exit 1
fi

# ── Make setup.sh executable inside zip ─────────────────────────────────────
chmod +x "$BUNDLE_DIR/setup.sh"

# ── Safety check — sensitive files must NOT be in the bundle ─────────────────
FORBIDDEN=("config.json" "cert.pem" "key.pem" "ssl.cnf")
for f in "${FORBIDDEN[@]}"; do
  if [[ -f "$BUNDLE_DIR/$f" ]]; then
    echo ""
    echo "  ✗ SECURITY: $f ended up in the bundle — aborting!"
    rm -rf "$BUNDLE_DIR"
    exit 1
  fi
done
echo "  ✓ Sensitive files excluded (config.json, cert.pem, key.pem, ssl.cnf)"

# ── Create zip ───────────────────────────────────────────────────────────────
cd "$RELEASES_DIR"
zip -r "${BUNDLE_NAME}.zip" "$BUNDLE_NAME" -x "*.DS_Store" -x "__pycache__/*" > /dev/null
cd "$DIR"

# ── Checksums ────────────────────────────────────────────────────────────────
SHA256=$(shasum -a 256 "$ZIP_PATH" | awk '{print $1}')
echo ""
echo "  ┌──────────────────────────────────────────────────────────────────┐"
echo "  │  ✓ Release built successfully!                                   │"
echo "  └──────────────────────────────────────────────────────────────────┘"
echo ""
echo "  📦  File   : $ZIP_PATH"
echo "  📏  Size   : $(du -sh "$ZIP_PATH" | cut -f1)"
echo "  🔒  SHA256 : $SHA256"
echo ""

# ── GitHub release instructions ──────────────────────────────────────────────
echo "  Next steps to publish on GitHub:"
echo ""
echo "  1. Commit and push your changes:"
echo "     git add -A && git commit -m \"Release ${VERSION_TAG}\""
echo "     git tag ${VERSION_TAG}"
echo "     git push origin main --tags"
echo ""
echo "  2. Create the GitHub Release:"
echo "     gh release create ${VERSION_TAG} \\"
echo "       \"${ZIP_PATH}\" \\"
echo "       --title \"Murari MacControl ${VERSION_TAG}\" \\"
echo "       --notes-file RELEASE_NOTES.md"
echo ""
echo "     Or go to: https://github.com/YOUR_USERNAME/murari-maccontrol/releases/new"
echo "     and upload: ${BUNDLE_NAME}.zip"
echo ""
echo "  3. Add to release description:"
echo "     SHA-256: ${SHA256}"
echo ""

# ── Cleanup bundle folder (keep only the zip) ────────────────────────────────
rm -rf "$BUNDLE_DIR"
echo "  ✓ Done. Bundle folder cleaned up — zip is the only output."
echo ""
