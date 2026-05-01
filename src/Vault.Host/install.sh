#!/usr/bin/env bash
# Install the VaultCore native messaging host for Chrome/Chromium/Firefox.
# Pass the extension ID as the first argument (the "long string" Chrome shows
# on chrome://extensions when developer mode is on).
#
# Usage:
#   ./install.sh <chrome-extension-id> [path-to-vault-mh]
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <extension-id> [path-to-vault-mh-binary]"
  exit 1
fi

EXT_ID="$1"
HOST_PATH="${2:-$(pwd)/vault-mh}"

if [[ ! -x "$HOST_PATH" ]]; then
  echo "Error: $HOST_PATH does not exist or is not executable."
  echo "Build it first with: dotnet publish src/Vault.Host -c Release -r linux-x64"
  exit 1
fi

NAME="io.vaultcore.host"

write_manifest() {
  local target_dir="$1"
  mkdir -p "$target_dir"
  cat > "$target_dir/${NAME}.json" <<EOF
{
  "name": "${NAME}",
  "description": "VaultCore native messaging host",
  "path": "${HOST_PATH}",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://${EXT_ID}/"
  ]
}
EOF
  echo "Installed to ${target_dir}/${NAME}.json"
}

OS="$(uname -s)"
case "$OS" in
  Linux*)
    write_manifest "$HOME/.config/google-chrome/NativeMessagingHosts"
    write_manifest "$HOME/.config/chromium/NativeMessagingHosts"
    write_manifest "$HOME/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts"
    # Firefox uses allowed_extensions instead of allowed_origins; emit both.
    FIREFOX_DIR="$HOME/.mozilla/native-messaging-hosts"
    mkdir -p "$FIREFOX_DIR"
    cat > "$FIREFOX_DIR/${NAME}.json" <<EOF
{
  "name": "${NAME}",
  "description": "VaultCore native messaging host",
  "path": "${HOST_PATH}",
  "type": "stdio",
  "allowed_extensions": ["${EXT_ID}"]
}
EOF
    echo "Installed Firefox manifest to ${FIREFOX_DIR}/${NAME}.json"
    ;;
  Darwin*)
    write_manifest "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
    write_manifest "$HOME/Library/Application Support/Chromium/NativeMessagingHosts"
    write_manifest "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"
    write_manifest "$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"
    ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac

echo
echo "Done. Restart your browser to pick up the new host."
