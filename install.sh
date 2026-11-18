#!/usr/bin/env bash
# install.sh — interactive menu for the SATAN-CYBR-HCK Rust tooling.
# Authorized testing only: run the tools against systems you own or may test.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE="$ROOT/biochimera"

have() { command -v "$1" >/dev/null 2>&1; }

check_rust() {
  if ! have cargo; then
    echo "[!] cargo (Rust) not found."
    echo "    Install from https://rustup.rs then re-run this script."
    return 1
  fi
  echo "[*] cargo: $(cargo --version)"
}

build_all() {
  check_rust || return 1
  echo "[*] Building release binaries..."
  ( cd "$CRATE" && cargo build --release )
  echo "[+] Built: $CRATE/target/release/{biochimera,reconstruction}"
}

run_biochimera() {
  check_rust || return 1
  read -r -p "Target URL (returns 403): " url
  [ -z "${url:-}" ] && { echo "[!] No URL."; return 1; }
  ( cd "$CRATE" && cargo run --release --bin biochimera -- "$url" )
}

run_reconstruction() {
  check_rust || return 1
  read -r -p "Target host or URL: " tgt
  [ -z "${tgt:-}" ] && { echo "[!] No target."; return 1; }
  ( cd "$CRATE" && cargo run --release --bin reconstruction -- "$tgt" )
}

install_bins() {
  build_all || return 1
  local dest="${1:-$HOME/.local/bin}"
  mkdir -p "$dest"
  cp "$CRATE/target/release/biochimera" "$dest/"
  cp "$CRATE/target/release/reconstruction" "$dest/"
  echo "[+] Installed to $dest (make sure it is on your PATH)."
}

menu() {
  cat <<MENU

=============================================
  SATAN-CYBR-HCK — tooling installer
=============================================
  1) Check prerequisites (Rust/cargo)
  2) Build all tools (release)
  3) Run biochimera (403-bypass tester)
  4) Run reconstruction (DNS/proxy/firewall)
  5) Install binaries to ~/.local/bin
  q) Quit
=============================================
MENU
}

while true; do
  menu
  read -r -p "Select: " choice
  case "${choice:-}" in
    1) check_rust || true ;;
    2) build_all || true ;;
    3) run_biochimera || true ;;
    4) run_reconstruction || true ;;
    5) install_bins || true ;;
    q|Q) echo "Bye."; exit 0 ;;
    *) echo "[!] Unknown option: ${choice:-}" ;;
  esac
done
