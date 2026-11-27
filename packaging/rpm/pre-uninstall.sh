#!/bin/sh

if [ "${1:-0}" -eq 0 ]; then
    systemctl disable --now project-charlotte.service || :
fi

exit 0