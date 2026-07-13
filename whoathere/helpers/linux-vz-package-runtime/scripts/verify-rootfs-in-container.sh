#!/bin/sh
set -eu
umask 077

inputs=/inputs
image=/image
work=/tmp/whoathere-runtime-verify
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
# debugfs rdump materializes this directory without its sticky bit. The inode assertion above
# checks the image itself; restore that one proven bit only for the canonical archive comparison.
chmod 1777 "$work/ext4-root/var/tmp"
tar --sort=name --format=gnu --mtime="@$epoch" --numeric-owner \
    -cf "$work/ext4-root.tar" -C "$work/ext4-root" .
if ! cmp -s "$image/rootfs.tar" "$work/ext4-root.tar"; then
    tar -tvf "$image/rootfs.tar" > "$work/source.list"
    tar -tvf "$work/ext4-root.tar" > "$work/ext2.list"
    diff -u "$work/source.list" "$work/ext2.list" | sed -n '1,80p' >&2 || true
    echo "ext2 contents do not match canonical rootfs archive" >&2
    exit 65
fi
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
test "$(run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /whoathere/package-runtime-probe --runtime-probe')" = \
    '{"execution_authority":false,"package_execution":false,"schema_version":"whoathere.linux_vz_package_runtime_probe.v1","status":"candidate_runtime_nonexecuting","sync_back":false}'
test "$(run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /whoathere/package-runtime-probe fork_exec_exit')" = \
    '{"execution_authority":false,"package_execution":false,"schema_version":"whoathere.linux_vz_package_runtime_probe.v1","status":"candidate_runtime_nonexecuting","sync_back":false}'
if run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /whoathere/package-runtime-probe' >/dev/null 2>&1; then
    echo "verified runtime probe accepted an unauthorized invocation" >&2
    exit 65
else
    test "$?" = 64
fi
if run_as_package 'exec /usr/bin/env -i HOME=/workspace TMPDIR=/tmp PATH=/usr/bin:/bin /whoathere/package-runtime-probe package_install' >/dev/null 2>&1; then
    echo "verified runtime probe accepted an open-ended invocation" >&2
    exit 65
else
    test "$?" = 64
fi
test ! -s "$work/tar-root/etc/resolv.conf"
test ! -s "$work/tar-root/etc/apk/repositories"
test "$(stat -c '%u:%g:%a' "$work/tar-root/workspace")" = 65534:65534:700
test "$(stat -c '%u:%g:%a' "$work/tar-root/tmp")" = 65534:65534:700
test "$(stat -c '%u:%g:%a' "$work/ext4-root/workspace")" = 65534:65534:700
test "$(stat -c '%u:%g:%a' "$work/ext4-root/tmp")" = 65534:65534:700
test "$(stat -c '%u:%g:%a' "$work/tar-root/whoathere")" = 0:0:711
test "$(stat -c '%u:%g:%a' "$work/tar-root/whoathere/package-runtime-probe")" = 0:0:555
test "$(stat -c '%u:%g:%a' "$work/ext4-root/whoathere")" = 0:0:711
test "$(stat -c '%u:%g:%a' "$work/ext4-root/whoathere/package-runtime-probe")" = 0:0:555
