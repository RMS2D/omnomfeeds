#!/usr/bin/env sh
# oM noM Security Feeds installer - detects OS + arch, pulls the latest release binary.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/RMS2D/omnomfeeds/main/install.sh | sh
#
# Env vars:
#   SECFEED_VERSION   pin a specific version (default: latest)
#   SECFEED_INSTALL   override install dir (default: /usr/local/bin or ~/.local/bin)
set -eu

REPO="RMS2D/omnomfeeds"
VERSION="${SECFEED_VERSION:-latest}"

# --- OS / arch detection ---
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)

case "$os" in
  linux)  GOOS=linux ;;
  darwin) GOOS=macos ;;
  *) echo "unsupported OS: $os" >&2; exit 1 ;;
esac

case "$arch" in
  x86_64|amd64) GOARCH=x86_64 ;;
  arm64|aarch64) GOARCH=arm64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

# --- Resolve version ---
if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' \
    | head -n1)
  if [ -z "$VERSION" ]; then
    echo "could not resolve latest version" >&2
    exit 1
  fi
fi
# Strip leading 'v' for the archive filename
SHORT="${VERSION#v}"

ARCHIVE="omnomfeeds_${SHORT}_${GOOS}_${GOARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"

# --- Install dir ---
if [ -n "${SECFEED_INSTALL:-}" ]; then
  DEST="$SECFEED_INSTALL"
elif [ -w "/usr/local/bin" ] 2>/dev/null || [ "$(id -u)" -eq 0 ]; then
  DEST="/usr/local/bin"
else
  DEST="${HOME}/.local/bin"
  mkdir -p "$DEST"
  case ":${PATH}:" in
    *":${DEST}:"*) ;;
    *) echo "note: ${DEST} is not on your PATH" >&2 ;;
  esac
fi

# --- Download + extract ---
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "> downloading ${ARCHIVE}..."
if ! curl -fsSL "$URL" -o "${TMP}/${ARCHIVE}"; then
  echo "download failed: ${URL}" >&2
  exit 1
fi

echo "> extracting..."
tar -xzf "${TMP}/${ARCHIVE}" -C "$TMP"

if [ ! -f "${TMP}/secfeed" ]; then
  echo "extracted archive does not contain 'secfeed' binary" >&2
  exit 1
fi

chmod +x "${TMP}/secfeed"

# --- Install (use sudo only when DEST not writable) ---
if [ -w "$DEST" ]; then
  mv "${TMP}/secfeed" "${DEST}/secfeed"
elif command -v sudo >/dev/null 2>&1; then
  echo "> elevating to write to ${DEST}"
  sudo mv "${TMP}/secfeed" "${DEST}/secfeed"
else
  echo "no write permission for ${DEST} and sudo not available" >&2
  echo "rerun with SECFEED_INSTALL=\$HOME/bin or similar" >&2
  exit 1
fi

echo ""
echo "  oM noM Security Feeds ${VERSION} installed at ${DEST}/secfeed"
echo ""
echo "  start it:    secfeed"
echo "  config:      press 'c' in the UI, or edit \$HOME/.config/secfeed/config.json"
echo "  open at:     http://localhost:8080"
echo ""
