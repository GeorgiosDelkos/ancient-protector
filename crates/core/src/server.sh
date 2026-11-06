#!/bin/sh
# Ancient Protector's server inventory, sent on ssh's stdin and run by `sh -s`. The app puts two
# lines before it: `marker=<random hex>` and `set -- '<folder>' ...` with the folders whose
# lockfiles are read. Neither is on the remote command line, so other users of the server cannot
# see the marker in `ps`.
#
# It only reads: it never uses sudo, writes no file and opens no connection. Each part of the
# answer is printed as a "<marker> begin <part>" line, the part's output, an empty line and a
# "<marker> end <exit status>" line. The marker is random per run, so no file's content can end a
# part early. Standard error is dropped for the whole script: the exit status says whether a part
# was read, and error text from the server would only reach the user's terminal.

# shellcheck disable=SC2154 # marker is set by the app's first line
exec 2>/dev/null
nl='
'

part() {
    name=$1
    shift
    printf '%s begin %s\n' "$marker" "$name"
    "$@" </dev/null
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
# Names with a newline are skipped, since the list is one path per line. At most 201 paths are
# listed, so the app can tell that the list was cut at 200; files are under 16 MiB.
lockfiles() {
    { [ -d "$1" ] && [ -r "$1" ]; } || return 1
    find "$1" -mindepth 1 -xdev \
        \( -name "*$nl*" -o -type d \( -name '.*' -o -name node_modules -o -name target \
        -o -name vendor -o -name dist -o -name build \) \) -prune \
        -o -type f \( -name Cargo.lock -o -name package-lock.json -o -name npm-shrinkwrap.json \
        -o -name uv.lock -o -name poetry.lock \) -size -16384k -print | head -n 201
}

# Checked again just before reading: a file replaced by a symlink or a FIFO since the listing is
# not read (a FIFO would block until the app's time limit).
# shellcheck disable=SC2329 # called through part
lockfile() {
    [ -f "$1" ] && [ ! -L "$1" ] && cat -- "$1"
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
    printf '%s\n' "$files" | head -n 200 | while IFS= read -r file; do
        if [ -n "$file" ]; then
            part "file $file" lockfile "$file"
        fi
    done
done
exit 0
