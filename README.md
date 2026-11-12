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
| `--root DIRECTORY` | Fallback document root when no virtual host handles a request; defaults to `.`. |
| `--user USER [--group GROUP]` | Drop the master process to this account before starting; requires root. |
| `--index NAME` | Fallback index file name; defaults to `index.html`. |
| `--no-listing` | Disable directory listings, which are enabled by default. |
| `--try-files ENTRY` | Add a candidate or fallback rule; may be specified more than once. |
| `--config FILE` | Load virtual-host declarations from a YAML file. |
| `--vhost-dir DIRECTORY` | Load and watch additional `.yaml` and `.yml` virtual-host files in a directory. |
| `--tls-bind ADDRESS` | Listen for HTTPS; configure a certificate with `--tls-cert` and `--tls-key`, or use eligible ACME virtual hosts. |
| `--http3-bind ADDRESS` | Enable the HTTP/3 listener; TLS configuration is required. |
| `--fastcgi EXT=ADDR` | Route a file extension to a FastCGI TCP or Unix-socket backend. |
| `--cgi EXT[=INTERPRETER]` | Execute matching scripts directly or with an interpreter; repeatable. |
| `--fastcgi-app EXT=PROGRAM` | Start and supervise a FastCGI application for an extension. |
| `--fastcgi-app-max-workers EXT=N` | Set the on-demand FastCGI app pool limit (1–256); defaults to one. |
| `--fastcgi-app-idle-timeout EXT=SECS` | Reap surplus idle app workers after 1–86,400 seconds; defaults to 60 seconds. |
| `--modsecurity-rules FILE` | Load ModSecurity rules; can be repeated to load multiple files. |
| `--modsecurity-block-status CODE` | Override the status for ModSecurity blocking interventions (400–599; defaults to the rule status or 403). |
| `--acme-directory URL --acme-cache DIR` | Configure ACME certificate provisioning and its cache. |

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

Server-managed FastCGI apps start with one worker and spawn additional workers
only when concurrent requests need them, up to `--fastcgi-app-max-workers`.
Surplus idle workers are reaped after `--fastcgi-app-idle-timeout`, while one
worker stays ready. The old `--fastcgi-app-workers` option remains as a
deprecated alias for `--fastcgi-app-max-workers`. Workers restart immediately
after a clean exit if they ran for at least 50 ms; failed or very short-lived
processes are delayed to avoid a rapid restart loop.

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
streamed to the client.

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
```

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

Run tests with `cargo test`. Fuzz target setup, seed tests, and target commands
are documented in [FUZZING.md](FUZZING.md).