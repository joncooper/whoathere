#!/bin/sh
set -eu

RUNTIME_ROOT=${WHOATHERE_RUNTIME_INPUT_ROOT:-"$HOME/whoathere-runtime-inputs"}
UV_BIN=${WHOATHERE_UV_BINARY:-"$HOME/.local/bin/uv"}
PYTHON_MINOR=${WHOATHERE_PYTHON_MINOR:-3.12}
NODE_MAJOR=${WHOATHERE_NODE_MAJOR:-22}
SETUPTOOLS_VERSION=${WHOATHERE_SETUPTOOLS_VERSION:-68.2.2}

mkdir -p "$RUNTIME_ROOT/downloads" "$RUNTIME_ROOT/wheels" "$HOME/.local/bin"

if [ ! -x "$UV_BIN" ]; then
  curl -fsSL https://astral.sh/uv/install.sh -o "$RUNTIME_ROOT/downloads/uv-install.sh"
  UV_INSTALL_DIR="$HOME/.local/bin" UV_NO_MODIFY_PATH=1 sh "$RUNTIME_ROOT/downloads/uv-install.sh"
fi

"$UV_BIN" --version
"$UV_BIN" python install "$PYTHON_MINOR"

PY_RUNTIME=$(find "$HOME/.local/share/uv/python" -maxdepth 1 -type d -name "cpython-$PYTHON_MINOR.*-macos-aarch64-none" 2>/dev/null | sort | tail -n 1)
if [ -z "$PY_RUNTIME" ] || [ ! -x "$PY_RUNTIME/bin/python3" ]; then
  echo "python_runtime_not_found=true" >&2
  exit 1
fi

rm -f "$RUNTIME_ROOT"/wheels/pip-*.whl "$RUNTIME_ROOT"/wheels/setuptools-*.whl "$RUNTIME_ROOT"/wheels/wheel-*.whl "$RUNTIME_ROOT"/wheels/packaging-*.whl

WHOATHERE_RUNTIME_INPUT_ROOT="$RUNTIME_ROOT" WHOATHERE_SETUPTOOLS_VERSION="$SETUPTOOLS_VERSION" python3 - <<'PY'
import hashlib
import json
import os
import pathlib
import urllib.request

out_dir = pathlib.Path(os.environ["WHOATHERE_RUNTIME_INPUT_ROOT"]) / "wheels"
out_dir.mkdir(parents=True, exist_ok=True)

def download_project(project, version_override=None):
    with urllib.request.urlopen(f"https://pypi.org/pypi/{project}/json", timeout=60) as response:
        data = json.load(response)
    version = version_override or data["info"]["version"]
    selected = None
    for item in data["releases"][version]:
        filename = item.get("filename", "")
        if item.get("packagetype") == "bdist_wheel" and filename.endswith("-py3-none-any.whl"):
            selected = item
            break
    if not selected:
        raise SystemExit(f"{project}_py3_none_any_not_found")
    target = out_dir / selected["filename"]
    with urllib.request.urlopen(selected["url"], timeout=120) as response:
        payload = response.read()
    actual = hashlib.sha256(payload).hexdigest()
    expected = selected["digests"]["sha256"]
    if actual != expected:
        raise SystemExit(f"{project}_sha256_mismatch expected={expected} actual={actual}")
    target.write_bytes(payload)
    print(f"{project}_version={version}")
    print(f"{project}_file={target}")
    print(f"{project}_sha256={actual}")
    return target

download_project("pip")
download_project("setuptools", os.environ["WHOATHERE_SETUPTOOLS_VERSION"])
download_project("packaging")
download_project("wheel")
PY

PY_WHEEL_DIR="$RUNTIME_ROOT/wheels"
WHEEL_FILE=$(find "$RUNTIME_ROOT/wheels" -maxdepth 1 -name 'wheel-*.whl' -type f 2>/dev/null | sort | tail -n 1)
if [ -z "$WHEEL_FILE" ]; then
  echo "wheel_package_file_not_found=true" >&2
  exit 1
fi

NODE_INDEX="$RUNTIME_ROOT/downloads/node-index.tab"
curl -fsSL https://nodejs.org/dist/index.tab -o "$NODE_INDEX"
NODE_VERSION=$(awk -v major="$NODE_MAJOR" 'NR>1 && $1 ~ "^v" major "\\." && $3 ~ /(darwin-arm64|osx-arm64)/ {print $1; exit}' "$NODE_INDEX")
if [ -z "$NODE_VERSION" ]; then
  echo "node_darwin_arm64_not_found=true" >&2
  exit 1
fi

NODE_TAR="node-$NODE_VERSION-darwin-arm64.tar.xz"
NODE_URL="https://nodejs.org/dist/$NODE_VERSION/$NODE_TAR"
SHASUM_URL="https://nodejs.org/dist/$NODE_VERSION/SHASUMS256.txt"
(
  cd "$RUNTIME_ROOT/downloads"
  curl -fsSLO "$NODE_URL"
  curl -fsSLO "$SHASUM_URL"
  grep " $NODE_TAR\$" SHASUMS256.txt | shasum -a 256 -c -
)

NODE_DIR="$RUNTIME_ROOT/node-runtime"
rm -rf "$NODE_DIR"
mkdir -p "$NODE_DIR"
tar -xJf "$RUNTIME_ROOT/downloads/$NODE_TAR" -C "$NODE_DIR" --strip-components=1
"$NODE_DIR/bin/node" --version
PATH="$NODE_DIR/bin:$PATH" "$NODE_DIR/bin/npm" --version

ENV_FILE="$RUNTIME_ROOT/runtime-env.sh"
cat > "$ENV_FILE" <<EOF
export WHOATHERE_PYTHON_RUNTIME_DIR='$PY_RUNTIME'
export WHOATHERE_PYTHON_WHEEL_DIR='$PY_WHEEL_DIR'
export WHOATHERE_WHEEL_PACKAGE_FILE='$WHEEL_FILE'
export WHOATHERE_NODE_RUNTIME_DIR='$NODE_DIR'
export WHOATHERE_UV_BINARY='$UV_BIN'
EOF
chmod 0600 "$ENV_FILE"

printf 'runtime_inputs_ready=true\n'
printf 'runtime_env=%s\n' "$ENV_FILE"
printf 'WHOATHERE_PYTHON_RUNTIME_DIR=%s\n' "$PY_RUNTIME"
printf 'WHOATHERE_PYTHON_WHEEL_DIR=%s\n' "$PY_WHEEL_DIR"
printf 'WHOATHERE_WHEEL_PACKAGE_FILE=%s\n' "$WHEEL_FILE"
printf 'WHOATHERE_NODE_RUNTIME_DIR=%s\n' "$NODE_DIR"
printf 'WHOATHERE_UV_BINARY=%s\n' "$UV_BIN"
