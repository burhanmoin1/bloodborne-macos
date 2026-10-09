#!/bin/zsh
set -eu
bb_app_root="${0:A:h}"
bb_python="${BB_PYTHON:-}"

if [[ -z "$bb_python" ]]; then
    for bb_candidate in \
        /Library/Frameworks/Python.framework/Versions/3.13/bin/python3 \
        /Library/Frameworks/Python.framework/Versions/3.12/bin/python3 \
        /opt/homebrew/bin/python3 \
        /usr/bin/python3; do
        if [[ -x "$bb_candidate" ]] && "$bb_candidate" -c 'import tkinter' >/dev/null 2>&1; then
            bb_python="$bb_candidate"
            break
        fi
    done
fi

if [[ -z "$bb_python" ]]; then
    print -u2 'A Python 3 installation with Tk support is required for the source launcher.'
    exit 1
fi

export BB_WORKSPACE="$bb_app_root"
if [[ -f "$bb_app_root/bbport-windows/Bloodborne.exe" ]]; then
    export BB_PORT_DIR="$bb_app_root/bbport-windows"
fi
exec "$bb_python" "$bb_app_root/app/launcher.py"
