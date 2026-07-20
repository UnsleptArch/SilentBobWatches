#!/usr/bin/env bash
#
# silentbobwatches installer
#
# Builds a release binary with cargo and installs it somewhere on PATH.
# Does not require root. Safe to re-run to upgrade an existing install.

set -euo pipefail

BOLD="$(tput bold 2>/dev/null || true)"
RESET="$(tput sgr0 2>/dev/null || true)"
GREEN="$(tput setaf 2 2>/dev/null || true)"
YELLOW="$(tput setaf 3 2>/dev/null || true)"
RED="$(tput setaf 1 2>/dev/null || true)"

info()  { printf "%s[+]%s %s\n" "$GREEN" "$RESET" "$1"; }
warn()  { printf "%s[!]%s %s\n" "$YELLOW" "$RESET" "$1"; }
die()   { printf "%s[x]%s %s\n" "$RED" "$RESET" "$1"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

printf "%ssilentbobwatches installer%s\n\n" "$BOLD" "$RESET"

# --------------------------------------------------------
# 1. Verify a Rust toolchain is available
# --------------------------------------------------------

if ! command -v cargo >/dev/null 2>&1; then
    warn "cargo was not found on PATH."
    echo
    echo "Install a Rust toolchain first, for example:"
    echo "  Arch Linux   : sudo pacman -S rust"
    echo "  Debian/Ubuntu: sudo apt install cargo rustc"
    echo "  Any distro   : https://rustup.rs"
    echo
    die "aborting -- no cargo available"
fi

RUSTC_VERSION="$(rustc --version 2>/dev/null || echo unknown)"
info "Found Rust toolchain: $RUSTC_VERSION"

# --------------------------------------------------------
# 2. Build
# --------------------------------------------------------

info "Building release binary (this can take a minute or two)..."
if ! cargo build --release; then
    die "build failed -- see the error output above"
fi

BIN_PATH="$SCRIPT_DIR/target/release/silentbobwatches"
if [ ! -f "$BIN_PATH" ]; then
    die "build succeeded but binary not found at $BIN_PATH"
fi

info "Build succeeded: $BIN_PATH"

# --------------------------------------------------------
# 3. Choose an install location
# --------------------------------------------------------

INSTALL_DIR=""
if [ -w "/usr/local/bin" ] 2>/dev/null; then
    install -m 755 "$BIN_PATH" "/usr/local/bin/silentbobwatches"
    INSTALL_DIR="/usr/local/bin"
elif command -v sudo >/dev/null 2>&1 && [ "${SBW_NO_SUDO:-0}" != "1" ]; then
    printf "%s[?]%s /usr/local/bin is not writable. Install there with sudo? [y/N] " "$YELLOW" "$RESET"
    read -r ANSWER || ANSWER="n"
    case "$ANSWER" in
        y|Y|yes|YES)
            if sudo install -m 755 "$BIN_PATH" /usr/local/bin/silentbobwatches; then
                INSTALL_DIR="/usr/local/bin"
            fi
            ;;
    esac
fi

if [ -z "$INSTALL_DIR" ]; then
    mkdir -p "$HOME/.local/bin"
    cp "$BIN_PATH" "$HOME/.local/bin/silentbobwatches"
    chmod 755 "$HOME/.local/bin/silentbobwatches"
    INSTALL_DIR="$HOME/.local/bin"
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *)
            warn "$HOME/.local/bin is not on your PATH."
            echo "    Add this to your shell rc file (e.g. ~/.bashrc or ~/.zshrc):"
            echo "      export PATH=\"\$HOME/.local/bin:\$PATH\""
            ;;
    esac
fi

echo
info "Installed to: $INSTALL_DIR/silentbobwatches"
echo
"$INSTALL_DIR/silentbobwatches" --version 2>/dev/null || true
echo
echo "Try it out:"
echo "  silentbobwatches 10.0.0.0/24 -vv"
echo
info "Done."
