#!/bin/sh

systemctl daemon-reload || :
if [ "${1:-0}" -gt 0 ]; then
    systemctl try-restart project-charlotte.service || :
fi

exit 0