#!/bin/sh
set -eu
umask 077

inputs=/inputs
work=/work
rootfs=/tmp/whoathere-execution-runtime-rootfs
artifacts="$work/artifacts"
runner=/runner/whoathere-linux-vz-package-root-runtime
epoch=1783900800
timestamp=202607130000.00
rootfs_uuid=57484f41-5448-4552-5254-554e54494d45

mkdir -p "$rootfs" "$artifacts"
tar -xzf "$inputs/minirootfs/alpine-minirootfs-3.24.1-aarch64.tar.gz" -C "$rootfs"
apk --no-cache --repositories-file /dev/null add --no-network --allow-untrusted \
    "$inputs"/build-apks/*.apk >/dev/null
apk --no-cache --repositories-file /dev/null add --root "$rootfs" --no-network \
    --allow-untrusted --no-scripts \
    "$inputs"/runtime-apks/*.apk >/dev/null

mkdir -p "$rootfs/whoathere" "$rootfs/workspace" "$rootfs/tmp" "$rootfs/lost+found"
install -m 0500 "$runner" "$rootfs/whoathere/package-root-runtime"
chown 65534:65534 "$rootfs/workspace" "$rootfs/tmp"
chmod 0711 "$rootfs/whoathere"
chmod 0700 "$rootfs/workspace" "$rootfs/tmp"
rm -f "$rootfs/etc/resolv.conf"
: > "$rootfs/etc/resolv.conf"
: > "$rootfs/etc/apk/repositories"
rm -rf "$rootfs/var/cache/apk"/* "$rootfs/tmp"/*

run_as_package() {
    test "$#" = 1
    chroot "$rootfs" /bin/su -s /bin/sh nobody -c "$1"
}
test "$(run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /usr/bin/id -u')" = 65534
test "$(run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /usr/bin/id -g')" = 65534
test "$(run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /usr/bin/id -G')" = 65534
node_version=$(run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /usr/bin/node --version')
npm_version=$(run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /usr/bin/npm --version')
python_version=$(run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /usr/bin/python3 --version')
pip_version=$(run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /usr/bin/python3 -m pip --version')
test "$node_version" = v24.17.0
test "$npm_version" = 11.12.1
test "$python_version" = 'Python 3.14.5'
case "$pip_version" in
    'pip 26.1.2 from '*'/pip (python 3.14)') ;;
    *) echo "unexpected pip runtime identity" >&2; exit 65 ;;
esac
if run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /whoathere/package-root-runtime --qualification-probe' >/dev/null 2>&1; then
    echo "execution runtime accepted a qualification invocation from the package identity" >&2
    exit 65
else
    code=$?
    if [ "$code" -ne 126 ]; then
        echo "package identity qualification denial returned unexpected status: $code" >&2
        exit 65
    fi
fi
if run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /whoathere/package-root-runtime --execute' >/dev/null 2>&1; then
    echo "execution runtime accepted an incomplete execution invocation from package identity" >&2
    exit 65
else
    code=$?
    if [ "$code" -ne 126 ]; then
        echo "package identity execution denial returned unexpected status: $code" >&2
        exit 65
    fi
fi

rm -rf "$rootfs/tmp"/*
rm -f "$rootfs/var/log/apk.log"
find "$rootfs" -exec touch -h -t "$timestamp" {} +
tar --sort=name --format=gnu --mtime="@$epoch" --numeric-owner \
    -cf "$artifacts/rootfs.tar" -C "$rootfs" .

genext2fs -f -z -B 4096 -b 262144 -N 131072 -L WHOATHERE_RT -m 0 \
    -a "$artifacts/rootfs.tar" "$artifacts/rootfs.ext2"
debugfs -w -R 'set_inode_field /var/tmp mode 041777' "$artifacts/rootfs.ext2" >/dev/null 2>&1
E2FSPROGS_FAKE_TIME=$epoch tune2fs -U "$rootfs_uuid" "$artifacts/rootfs.ext2" >/dev/null
E2FSPROGS_FAKE_TIME=$epoch e2fsck -fn "$artifacts/rootfs.ext2" >/dev/null
cp "$runner" "$artifacts/package-root-runtime"
chmod 0444 "$artifacts/rootfs.tar" "$artifacts/rootfs.ext2"
chmod 0500 "$artifacts/package-root-runtime"

printf '%s\n' "$node_version" > "$artifacts/node-version.txt"
printf '%s\n' "$npm_version" > "$artifacts/npm-version.txt"
printf '%s\n' "$python_version" > "$artifacts/python-version.txt"
printf '%s\n' "$pip_version" > "$artifacts/pip-version.txt"
sha256sum "$rootfs/usr/bin/node" | awk '{print $1}' > "$artifacts/node-sha256.txt"
sha256sum "$rootfs/usr/lib/node_modules/npm/bin/npm-cli.js" | awk '{print $1}' \
    > "$artifacts/npm-cli-sha256.txt"
sha256sum "$rootfs/usr/bin/python3.14" | awk '{print $1}' \
    > "$artifacts/python-sha256.txt"
sha256sum "$rootfs/usr/bin/pip3" | awk '{print $1}' > "$artifacts/pip-entrypoint-sha256.txt"
