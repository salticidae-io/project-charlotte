#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
printf 'Charlotte CGI executed this script.\n'
printf 'Request method: %s\n' "${REQUEST_METHOD:-unknown}"
printf 'Script name: %s\n' "${SCRIPT_NAME:-unknown}"
printf 'Query string: %s\n' "${QUERY_STRING:-}"
printf 'Server protocol: %s\n' "${SERVER_PROTOCOL:-unknown}"
printf 'Remote address: %s\n' "${REMOTE_ADDR:-unknown}"
printf 'Worker uid: %s\n' "$(id -u)"
printf 'CGI process id: %s\n' "$$"