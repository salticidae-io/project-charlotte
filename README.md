# project-charlotte

`project-charlotte` is an asynchronous Rust web server for static sites and
virtual-hosted applications. It serves files and directory listings, and can
optionally connect to or supervise FastCGI applications, inspect traffic with
ModSecurity, serve TLS and HTTP/3, and provision certificates with ACME.

For a deeper description of the runtime and request flow, see
[ARCHITECTURE.md](ARCHITECTURE.md). Configuration examples are in
[examples/](examples/), and fuzzing instructions are in [FUZZING.md](FUZZING.md).

## Features

- Static file serving with MIME types, index files, optional directory
  listings, `try_files`, byte ranges, and conditional requests.
- YAML virtual hosts with exact and wildcard names, per-host document roots,
  isolated worker processes that can drop to configured user/group IDs, or
  transparent reverse proxies.
- FastCGI over TCP or Unix sockets, with optional server-managed FastCGI
  application processes.
- Classic CGI scripts, run directly or through a configured interpreter.
- Optional ModSecurity request and response inspection.
- Optional TLS with SNI-based certificate selection, ACME HTTP-01 certificate
  provisioning and renewal, and HTTP/3 over QUIC.
- Hot reload of virtual-host files from a configured directory.

## Requirements

- Rust and Cargo with Rust 2024 edition support (Rust 1.85 or newer).
- The `modsecurity-rs` dependency checked out as a sibling directory at
  `../modsecurity-rs`, as specified by the path dependency in `Cargo.toml`.

Build and run the test suite from the project directory:

```sh
cargo build --release
cargo test
```

## Build features

The major parts of the server are Cargo features. All four are enabled by
default; leave some out to build a smaller server.

| Feature | Provides | Without it |
| --- | --- | --- |
| `hosting` | The fallback site (`--root`), virtual hosts with a document root and their worker processes, static files, FastCGI, and CGI. | Hosting options and virtual hosts with a `root` are refused. Requests that match no virtual host get `404`. |
| `proxy` | Virtual hosts with `proxy_pass`. | Virtual hosts with `proxy_pass` are refused. |
| `acme` | ACME certificate provisioning (`--acme-*`). | The ACME options and `acme: true` are refused. |
| `http3` | The HTTP/3 listener (`--http3-bind`). | TLS is served over TCP only. |

TLS termination, SNI certificate selection, ModSecurity, `--user`/`--group`,
and virtual-host reloading are part of every build. A build refuses the
options and virtual-host settings of a feature it lacks at startup and names
the feature, rather than ignoring them. `project-charlotte --help` lists the
options the binary accepts and the features it was built with.

For example, to build a reverse proxy that terminates TLS, provisions its
certificates with ACME, and serves HTTP/3, but hosts nothing itself:

```sh
cargo build --release --no-default-features --features proxy,acme,http3
```

`scripts/check-features.sh` checks that every combination of features
compiles without warnings.

### Debian packages

[`cargo-deb`](https://github.com/kornelski/cargo-deb) builds two packages,
which both install `/usr/bin/project-charlotte` and so conflict with each
other:

| Package | Command | Features |
| --- | --- | --- |
| `project-charlotte` | `cargo deb` | all |
| `project-charlotte-proxy` | `cargo deb --variant proxy` | `proxy`, `acme`, `http3` |

The `Debian packages` GitHub workflow builds both for each supported Ubuntu
release.

## Quick start

Create a small document root and start the server using its default local
address (`127.0.0.1:8080`):

```sh
mkdir -p public
printf '%s\n' '<h1>Hello from Charlotte</h1>' > public/index.html
cargo run -- --root public
```

In another terminal, request the page:

```sh
curl http://127.0.0.1:8080/
```

The default document root is the current directory and directory listings are
enabled by default. For safety, choose a directory containing only files you
intend to serve.

## Configuration

Run `project-charlotte --help` (or `cargo run -- --help` in the source tree) to
see all command-line options. Common options include:

| Option | Purpose |
| --- | --- |
| `--bind ADDRESS` | Plain HTTP listener; defaults to `127.0.0.1:8080`. |
| `--no-plain-http` | Disable the plain HTTP listener; incompatible with ACME HTTP-01. |
| `--root DIRECTORY` | Fallback document root when no virtual host handles a request; defaults to `.`. |
| `--user USER [--group GROUP]` | Drop the master process to this account before starting; requires root. |
| `--index NAME` | Fallback index file name; defaults to `index.html`. |
| `--no-listing` | Disable directory listings, which are enabled by default. |
| `--try-files ENTRY` | Add a candidate or fallback rule; may be specified more than once. |
| `--config FILE` | Load virtual-host declarations from a YAML file. |
| `--vhost-dir DIRECTORY` | Load and watch additional `.yaml` and `.yml` virtual-host files in a directory. |
| `--control-socket PATH` | Serve the local HTTP configuration API on a Unix socket. |
| `--tls-bind ADDRESS` | Listen for HTTPS; configure a certificate with `--tls-cert` and `--tls-key`, or use eligible ACME virtual hosts. |
| `--http3-bind ADDRESS` | Enable the HTTP/3 listener; TLS configuration is required. |
| `--rate-limit RATE` | Apply a per-client request limit such as `20/s`, `600/m`, or `36000/h`; disabled by default. |
| `--rate-limit-burst N` | Set the allowed burst; requires `--rate-limit` and defaults to the rate rounded up per second. |
| `--trusted-proxy CIDR` | Trust a proxy address or network when resolving `X-Forwarded-For`; repeatable and empty by default. |
| `--access-log` | Write one access-log record per request to stdout. |
| `--access-log-file FILE` | Append access-log records to `FILE` (takes precedence over `--access-log`). |
| `--access-log-format FORMAT` | Apache `LogFormat` string or nickname (`common`, `combined`, `vhost_common`, `vhost_combined`, `referer`, `agent`). |
| `--error-log-file FILE` | Append error-log records (including CGI/FastCGI stderr) to `FILE` instead of stderr. |
| `--error-log-format FORMAT` | Apache `ErrorLogFormat` string; defaults to `[%t] [%l] [pid %P] [module %m] %M`. |
| `--bot-detection` | Enable the built-in bot policy in enforcing mode. |
| `--bot-config FILE` | Load bot-detection settings from YAML; enables detection and overrides the defaults. |
| `--fastcgi EXT=ADDR` | Route a file extension to a FastCGI TCP or Unix-socket backend. |
| `--cgi EXT[=INTERPRETER]` | Execute matching scripts directly or with an interpreter; repeatable. |
| `--fastcgi-app EXT=PROGRAM` | Start and supervise a FastCGI application for an extension. |
| `--fastcgi-app-max-workers EXT=N` | Set the on-demand FastCGI app pool limit (1–256); defaults to one. |
| `--fastcgi-app-idle-timeout EXT=SECS` | Reap surplus idle app workers after 1–86,400 seconds; defaults to 60 seconds. |
| `--modsecurity-rules FILE` | Load ModSecurity rules; can be repeated to load multiple files. |
| `--modsecurity-block-status CODE` | Override the status for ModSecurity blocking interventions (400–599; defaults to the rule status or 403). |
| `--acme-directory URL --acme-cache DIR` | Configure ACME certificate provisioning and its cache. |

Rate limits return `429 Too Many Requests` with a `Retry-After` header. The
client key is the socket peer IP unless that peer matches a configured
`--trusted-proxy` address or CIDR; in that case Charlotte resolves the client
from the rightmost untrusted `X-Forwarded-For` hop. IPv4 addresses are tracked
individually and IPv6 addresses are grouped by `/64`.

Charlotte strips `X-Forwarded-For` from requests received from untrusted peers.
For a trusted proxy, it keeps a normalized IP-only chain and appends the direct
peer IP when proxying upstream. Configure only proxies that overwrite or safely
append `X-Forwarded-For`; trusting arbitrary clients lets them spoof their
address for rate limiting and access logs. `--access-log` writes the resolved
client address and direct peer address, request line, status, host, and user
agent to stdout; quotes, backslashes, and control characters are escaped.

### Logging

Access and error logs can be written directly to files for the whole server
(`--access-log-file`, `--error-log-file`) and overridden per virtual host with
the `access_log`, `access_log_format`, `error_log`, and `error_log_format` YAML
keys. A vhost without its own setting inherits the server's file and format.
Files are opened in append mode with mode `0640`; vhost log paths are relative
to the YAML file and are reopened when virtual hosts are reloaded. Vhost log
files are opened after the server drops privileges, so they must be writable
by the server user.

Access formats follow Apache `mod_log_config`: `%%`, `%a`, `%{c}a`, `%A`, `%b`,
`%B`, `%D`, `%h`, `%H`, `%{Name}i`, `%{Name}o`, `%{Name}C`, `%l`, `%m`,
`%{ja4}n`, `%p`, `%{local|remote|canonical}p`, `%P`, `%q`, `%r`, `%s`, `%>s`,
`%t`, `%{strftime}t` (with `begin:`/`end:` and `sec`, `msec`, `usec`,
`msec_frac`, `usec_frac`), `%T`, `%{s|ms|us}T`, `%u`, `%U`, `%v`, and `%V`, plus
status conditions such as `%400,501{User-Agent}i` and `%!200{Referer}i`.
Unsupported directives are rejected at startup. The default format keeps the
previous stdout layout. Records are written when the response body finishes,
so `%b`, `%D`, and `%T` reflect what was sent.

Error formats follow Apache `ErrorLogFormat`: `%%`, `%a`, `%A`, `%t`, `%{u}t`,
`%{c}t`, `%{cu}t`, `%l`, `%m`, `%M`, `%P`, `%T`, and `%v`. As in Apache, a
field introduced with `% ` (for example `% ,\ host\ %v`) is omitted with its
prefix when empty, `\ ` is a literal space, and `%-x` omits an empty value.
CGI stderr lines and FastCGI `FCGI_STDERR` records are logged at `error` level
to the error log of the virtual host that ran the script, together with the
client address. Processes spawned with `fastcgi_app` inherit the worker's
stderr, so their raw output is appended to the same file unformatted.

### Configuration socket

`--control-socket /run/charlotte/control.sock` enables a local HTTP/1.1 JSON
API for the vhost directory. The socket is created with mode `0600`; its parent
directory must already exist, be writable by the server's effective account
(after any privilege drop), and not be writable by untrusted users. `GET /vhosts`
lists directory-backed vhosts and read-only vhosts from the main config, while
`GET /vhosts/{name}` returns the YAML entries as JSON.
Names are limited to 64 ASCII letters, digits, dots, underscores, and hyphens,
and must begin with a letter, digit, underscore, or hyphen.

`POST /vhosts/{name}` creates a file, `PUT` creates or replaces it, and
`DELETE` removes it. Mutations require `--vhost-dir`; main-config vhosts are
read-only. A request body is one vhost mapping in JSON or YAML. Charlotte
validates the change against the complete vhost configuration, including
duplicate names and worker setup, before atomically writing a mode-`0640` YAML
file and switching the running router. Invalid changes leave both the file and
the active configuration unchanged. `GET /status` reports uptime, vhost count,
and version; it is the read-only starting point for future server statistics.

```sh
curl --unix-socket /run/charlotte/control.sock http://localhost/vhosts
curl --unix-socket /run/charlotte/control.sock \
  -X PUT -H 'Content-Type: application/json' \
  --data '{"server_names":["www.example.com"],"root":"/srv/www/example","user":"www-example"}' \
  http://localhost/vhosts/example
curl --unix-socket /run/charlotte/control.sock \
  -X DELETE http://localhost/vhosts/example
```

The API uses `201` for a successful create, `200` for a successful get or
replace, and `204` for delete. Invalid requests return `400`, missing vhosts
`404`, create conflicts `409`, oversized bodies `413`, and unavailable mutation
storage `503`.

### Bot detection

Bot detection is disabled unless `--bot-detection` or `--bot-config` is used.
The built-in policy scores user-agent, browser-header, and (for TCP TLS)
ClientHello/JA4 signals; scanner signatures are blocked, and intermediate
scores receive a proof-of-work challenge. Claimed search-engine crawlers are
verified with reverse and forward DNS by default. HTTP/3 and plaintext
connections do not have a JA4 fingerprint.

Use `mode: log` in a policy file to observe scores without enforcing them, or
configure exceptions for health checks and API clients. A bot policy accepts
`challenge_threshold` (40), `block_threshold` (80), `challenge_difficulty`
(16 bits), `challenge_ttl` (seconds), `allow_ips`, `deny_ips`,
`allow_user_agents`, `deny_user_agents`, `builtin_rules`, `honeypot_paths`,
`honeypot_ban`, `exempt_paths`, `verify_crawlers`, `ja4_allow`, and `ja4_deny`.
The challenge cookie is HMAC-signed and bound to the client IPv4 `/24` or IPv6
`/64`; HTTPS responses mark it `Secure`.

```yaml
mode: log
challenge_threshold: 40
block_threshold: 80
allow_ips: [192.0.2.0/24]
exempt_paths: [/health, /api/]
verify_crawlers: true
```

Per-vhost YAML can inherit the global policy, disable it with `bot: off`, or
provide its own policy map. Since automation clients such as `curl` can be
legitimate health checks, begin with log mode and explicitly allow trusted
clients before enforcing.

### OWASP Core Rule Set

`examples/modsecurity-crs.conf` is a main rules file for Debian/Ubuntu
installations of the OWASP Core Rule Set. It enables the engine and request and
response body inspection, then includes the packaged CRS setup, exclusions, and
rules. The packaged `owasp-crs.load` uses Apache's `IncludeOptional`, which
libmodsecurity does not support, so use the example directly:

```sh
project-charlotte --modsecurity-rules examples/modsecurity-crs.conf
```

The example expects `crs-setup.conf`, the CRS rules directory, and the exclusion
files at their standard Debian/Ubuntu paths under `/etc/modsecurity/crs` and
`/usr/share/modsecurity-crs`.

Use `--modsecurity-block-status 403` to choose the status returned for
ModSecurity deny/drop interventions. The value must be between 400 and 599;
without it, the rule's `status` is used when valid, otherwise Charlotte returns
403. A redirect intervention keeps its configured redirect status. A virtual
host can override the global setting with `modsecurity_block_status: CODE` in
its YAML declaration; this requires global ModSecurity rules.

Server-managed FastCGI apps start with no workers. The first request starts one,
and additional workers are started only when concurrent requests need them, up
to `--fastcgi-app-max-workers`. Every idle worker is reaped after
`--fastcgi-app-idle-timeout`, so the pool can scale back to zero; a request after
that starts a fresh worker. The idle timeout defaults to 60 seconds. The old
`--fastcgi-app-workers` option remains as a deprecated alias for
`--fastcgi-app-max-workers`. Workers restart immediately after a clean exit if
they ran for at least 50 ms; failed or very short-lived processes are delayed
to avoid a rapid restart loop.

Classic CGI entries can be configured from the command line or in each virtual
host's YAML `cgi` list. Without an interpreter, the script must be executable;
with one, the interpreter receives the script path as its argument:

```sh
project-charlotte --root public --cgi cgi --cgi py=/usr/bin/python3
```

The equivalent vhost setting is `cgi: [cgi, "py=/usr/bin/python3"]`. CGI
scripts are resolved under the document root, run as the server or vhost
worker's user, and receive CGI request variables plus the request body on
standard input. Their response headers are parsed as CGI headers and stdout is
streamed to the client. CGI and FastCGI applications can set the response
status with a `Status: CODE` header or a leading NPH `HTTP/1.0`, `HTTP/1.1`,
`HTTP/2`, or `HTTP/3` status line; final statuses must be in the 200–599 range.

The master normally keeps the identity of the account that starts it. To start
as root and run the master as an unprivileged account, use `--user` and
optionally override its primary group with `--group`. The master clears
supplementary groups and retains only the capabilities needed to launch
virtual-host workers as their configured users and groups (plus
`CAP_NET_BIND_SERVICE` if it had that capability before dropping privileges).

Alternatively, an unprivileged account can run the binary with file
capabilities:

```sh
sudo setcap cap_setuid,cap_setgid=ep /path/to/project-charlotte
```

Add `cap_net_bind_service` to that command if the master must bind privileged
ports. `CAP_SETUID` is powerful: a compromised master with this capability can
switch to UID 0. Protect the binary and its configuration accordingly.

Virtual-host configuration is provided as YAML. For example, a basic host
declaration looks like this:

```yaml
vhost:
  - server_names: [www.example.com, example.com]
    root: /srv/www/example.com/public
    user: www-example
    group: www-data
    index: index.html
    listing: false
    rate_limit: "20/s"
    rate_limit_burst: 40
```

Virtual hosts without `rate_limit` inherit the global CLI limit. Set
`rate_limit: off` to exempt a host, or give it a rate such as `20/s` to create
an independent per-host bucket; `rate_limit_burst` is optional and defaults to
the rate rounded up per second.

Worker-backed hosts require a document root and worker user. A host configured
with `proxy_pass` is served directly by the master and does not need `root` or
`user`. A proxy vhost can forward requests arriving over
HTTP/1.1, HTTP/2, or HTTP/3 to an HTTP or HTTPS upstream:

```yaml
vhost:
  - server_names: [api.example.com]
    proxy_pass: https://backend.internal:8443/api
    proxy_preserve_host: true
    proxy_timeout: 60
    proxy_ca_root: trust/backend-ca.pem
    access_log: logs/api-access.log
    access_log_format: combined
    error_log: logs/api-error.log
    error_log_format: "[%t] [%l] [client %a] %M"
```

`proxy_pass` may include a path prefix but not a query. The original request
path and query are appended to that prefix. `proxy_preserve_host` defaults to
`true`; set it to `false` to send the upstream authority as `Host` instead.
`proxy_timeout` is the response-header timeout in seconds and defaults to 60.
HTTPS upstreams use the system trust roots unless `proxy_ca_root` points to a
PEM CA bundle; that path is relative to the YAML file. Request bodies and
upstream response bodies are streamed. Charlotte removes hop-by-hop headers and
sets `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host`. Connection
upgrades, WebSockets, and CONNECT tunnelling are not supported; upstream
connection failures return 502 and response-header timeouts return 504.

### HTTP/3-only reverse proxy

To run only a QUIC listener in front of an upstream, disable plain HTTP, omit
`--tls-bind`, and provide a TLS certificate plus an HTTP/3 address:

```sh
project-charlotte \
  --no-plain-http \
  --http3-bind 0.0.0.0:443 \
  --tls-cert /etc/charlotte/fullchain.pem \
  --tls-key /etc/charlotte/privkey.pem \
  --config /etc/charlotte/proxy.yaml
```

The YAML file should define proxy vhosts as shown above. Charlotte does not bind
the default plain HTTP address in this mode, and it also does not open a TLS
TCP listener unless `--tls-bind` is supplied. ACME HTTP-01 provisioning is
incompatible with `--no-plain-http`; use a certificate obtained by another
means.

See
[`examples/charlotte.yaml`](examples/charlotte.yaml) for FastCGI, TLS,
catch-all, ACME, and additional settings, and
[`examples/vhosts.d/example.yaml`](examples/vhosts.d/example.yaml) for a
per-host file. Paths in virtual-host files are resolved relative to their
configuration file.

For ACME HTTP-01 provisioning, configure eligible virtual hosts and ensure the
ACME service can reach the server over plaintext HTTP. Keep the ACME cache
outside all served document roots. See
[`examples/reverse-proxy-acme.yaml`](examples/reverse-proxy-acme.yaml) for an
SSL-terminating reverse proxy configuration with automated certificate
provisioning, or [`examples/charlotte.yaml`](examples/charlotte.yaml) for the
general server configuration.

## Development

Run tests with `cargo test`. Tests that need a feature are compiled only when
it is enabled, so a reduced build is tested with the same feature flags it is
built with, for example
`cargo test --no-default-features --features proxy,acme,http3`. Fuzz target
setup, seed tests, and target commands are documented in
[FUZZING.md](FUZZING.md); the fuzz targets need the default features.

Run coverage with `cargo tarpaulin` (install it with
`cargo install cargo-tarpaulin --locked`); reports are written to
`target/coverage`.

Run the Gungraun callgrind benchmarks with `cargo bench`. They require Valgrind
and the matching runner version:

```sh
cargo install gungraun-runner --version 0.20.0 --locked
cargo bench
```