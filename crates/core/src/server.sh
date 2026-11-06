#!/bin/sh
# Ancient Protector's server inventory, run over ssh as `sh -s -- <marker> <folder>...`.
#
# It only reads: it never uses sudo, writes no file and opens no connection. Each part of the
# answer is printed as a "<marker> begin <part>" line, the part's output, an empty line and a
# "<marker> end <exit status>" line. The marker is random per run, so no file's content can end a
# part early. Standard error is dropped: the exit status says whether a part was read.

marker=$1
shift

part() {
    name=$1
    shift
    printf '%s begin %s\n' "$marker" "$name"
    "$@" 2>/dev/null
    status=$?
    printf '\n%s end %s\n' "$marker" "$status"
}

# shellcheck disable=SC2329 # called through part
os_release() {
    cat /etc/os-release || cat /usr/lib/os-release
}

# shellcheck disable=SC2329 # called through part
listening() {
    ss -tulpn || netstat -tulpn
}

# The lockfile names and skipped folders match the Mac's project folder walk (lockfiles.rs).
# At most 200 files of under 16 MiB each, so one large folder cannot flood the answer.
lockfiles() {
    { [ -d "$1" ] && [ -r "$1" ]; } || return 1
    find "$1" -mindepth 1 -xdev \
        -type d \( -name '.*' -o -name node_modules -o -name target -o -name vendor \
        -o -name dist -o -name build \) -prune \
        -o -type f \( -name Cargo.lock -o -name package-lock.json -o -name npm-shrinkwrap.json \
        -o -name uv.lock -o -name poetry.lock \) -size -16384k -print | head -n 200
}

part os-release os_release
part kernel uname -srm
part dpkg cat /var/lib/dpkg/status
part apk cat /lib/apk/db/installed
part rpm rpm -qa --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n'
part listening listening
part docker-containers docker ps --no-trunc --format '{{json .}}'
part docker-images docker images --digests --no-trunc --format '{{json .}}'

for dir in "$@"; do
    files=$(lockfiles "$dir")
    status=$?
    printf '%s begin dir %s\n%s\n%s end %s\n' "$marker" "$dir" "$files" "$marker" "$status"
    printf '%s\n' "$files" | while IFS= read -r file; do
        if [ -n "$file" ]; then
            part "file $file" cat "$file"
        fi
    done
done
exit 0
