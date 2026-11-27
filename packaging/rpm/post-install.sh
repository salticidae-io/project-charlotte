#!/bin/sh
set -e

if ! getent passwd www-data >/dev/null; then
    useradd --system --home-dir /var/www --shell /sbin/nologin www-data
fi

systemctl daemon-reload || :
systemctl enable project-charlotte.service || :
systemctl start project-charlotte.service || :