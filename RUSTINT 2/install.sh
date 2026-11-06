#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${HOME}/.local/share/rustint"
BIN_DIR="${HOME}/.local/bin"

for tool in cargo rustc python3; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "[!] Missing $tool. Install Rust/Cargo and Python 3 first."
    exit 1
  }
done

mkdir -p "$APP_DIR" "$BIN_DIR"
cp "$ROOT/Cargo.toml" "$APP_DIR/"
rm -rf "$APP_DIR/src" "$APP_DIR/python"
cp -R "$ROOT/src" "$ROOT/python" "$APP_DIR/"

echo "[*] Building RUSTINT v0.2 in release mode..."
(cd "$APP_DIR" && cargo build --release)

cat > "$BIN_DIR/rustint" <<EOF
#!/usr/bin/env bash
export PYTHONPATH="$APP_DIR/python\${PYTHONPATH:+:\$PYTHONPATH}"
exec "$APP_DIR/target/release/rustint" "\$@"
EOF
chmod +x "$BIN_DIR/rustint"

echo "[+] RUSTINT v0.2 installed at $BIN_DIR/rustint"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "[!] Add ~/.local/bin to PATH: echo 'export PATH=\"\\$HOME/.local/bin:\\$PATH\"' >> ~/.bashrc" ;;
esac
echo "[*] Try: rustint --help"
