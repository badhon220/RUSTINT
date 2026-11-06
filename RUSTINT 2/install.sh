#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${HOME}/.local/share/rustint"
BIN_DIR="${HOME}/.local/bin"

for tool in cargo rustc python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "[!] Missing: $tool"
    echo "Install base packages: sudo apt update && sudo apt install -y build-essential python3 curl"
    echo "Install Rust/Cargo using rustup: https://rustup.rs"
    exit 1
  fi
done

mkdir -p "$APP_DIR" "$BIN_DIR"
cp "$ROOT/Cargo.toml" "$APP_DIR/"
rm -rf "$APP_DIR/src" "$APP_DIR/python"
cp -R "$ROOT/src" "$ROOT/python" "$APP_DIR/"

echo "[*] Building RUSTINT in release mode..."
(cd "$APP_DIR" && cargo build --release)

cat > "$BIN_DIR/rustint" <<EOF
#!/usr/bin/env bash
export PYTHONPATH="$APP_DIR/python\${PYTHONPATH:+:\$PYTHONPATH}"
exec "$APP_DIR/target/release/rustint" "\$@"
EOF
chmod +x "$BIN_DIR/rustint"

echo "[+] Installed to $BIN_DIR/rustint"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "[!] Add to PATH: echo 'export PATH=\"\\$HOME/.local/bin:\\$PATH\"' >> ~/.bashrc && source ~/.bashrc" ;;
esac
echo "[*] Test with: rustint --help"
