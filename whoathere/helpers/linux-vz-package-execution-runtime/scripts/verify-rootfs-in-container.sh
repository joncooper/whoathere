#!/bin/sh
set -eu
umask 077

inputs=/inputs
image=/image
work=/tmp/whoathere-execution-runtime-verify
epoch=1783900800

apk --no-cache --repositories-file /dev/null add --no-network --allow-untrusted \
    "$inputs"/build-apks/*.apk >/dev/null
mkdir -p "$work/tar-root" "$work/ext4-root"
tar -xf "$image/rootfs.tar" -C "$work/tar-root"
var_tmp_stat=$(debugfs -R 'stat /var/tmp' "$image/rootfs.ext2" 2>/dev/null)
case "$var_tmp_stat" in
    *'Type: directory    Mode:  01777'*) ;;
    *) echo "ext2 /var/tmp sticky mode is missing" >&2; exit 65 ;;
esac
debugfs -R "rdump / $work/ext4-root" "$image/rootfs.ext2" >/dev/null 2>&1
chmod 1777 "$work/ext4-root/var/tmp"
tar --sort=name --format=gnu --mtime="@$epoch" --numeric-owner \
    -cf "$work/ext4-root.tar" -C "$work/ext4-root" .
cmp "$image/rootfs.tar" "$work/ext4-root.tar"
E2FSPROGS_FAKE_TIME=$epoch e2fsck -fn "$image/rootfs.ext2" >/dev/null

run_as_package() {
    test "$#" = 1
    chroot "$work/tar-root" /bin/su -s /bin/sh nobody -c "$1"
}
test "$(run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /usr/bin/id -u')" = 65534
test "$(run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /usr/bin/id -g')" = 65534
test "$(run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /usr/bin/id -G')" = 65534
test "$(run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /usr/bin/node --version')" = v24.17.0
test "$(run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /usr/bin/npm --version')" = 11.12.1
test "$(run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /usr/bin/python3 --version')" = 'Python 3.14.5'
case "$(run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /usr/bin/python3 -m pip --version')" in
    'pip 26.1.2 from '*'/pip (python 3.14)') ;;
    *) echo "verified rootfs has the wrong pip identity" >&2; exit 65 ;;
esac
if run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /whoathere/package-root-runtime --qualification-probe' >/dev/null 2>&1; then
    echo "execution runtime accepted qualification from package identity" >&2
    exit 65
else
    code=$?
    if [ "$code" -ne 126 ]; then
        echo "verified package identity qualification denial returned unexpected status: $code" >&2
        exit 65
    fi
fi
if run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /whoathere/package-root-runtime --execute' >/dev/null 2>&1; then
    echo "execution runtime accepted incomplete execution from package identity" >&2
    exit 65
else
    code=$?
    if [ "$code" -ne 126 ]; then
        echo "verified package identity execution denial returned unexpected status: $code" >&2
        exit 65
    fi
fi
test ! -s "$work/tar-root/etc/resolv.conf"
test ! -s "$work/tar-root/etc/apk/repositories"
test "$(stat -c '%u:%g:%a' "$work/tar-root/workspace")" = 65534:65534:700
test "$(stat -c '%u:%g:%a' "$work/tar-root/tmp")" = 65534:65534:700
test "$(stat -c '%u:%g:%a' "$work/ext4-root/workspace")" = 65534:65534:700
test "$(stat -c '%u:%g:%a' "$work/ext4-root/tmp")" = 65534:65534:700
test "$(stat -c '%u:%g:%a' "$work/tar-root/whoathere")" = 0:0:711
test "$(stat -c '%u:%g:%a' "$work/tar-root/whoathere/package-root-runtime")" = 0:0:500
test "$(stat -c '%u:%g:%a' "$work/ext4-root/whoathere")" = 0:0:711
test "$(stat -c '%u:%g:%a' "$work/ext4-root/whoathere/package-root-runtime")" = 0:0:500
cmp "$image/package-root-runtime" "$work/tar-root/whoathere/package-root-runtime"
cmp "$image/package-root-runtime" "$work/ext4-root/whoathere/package-root-runtime"
