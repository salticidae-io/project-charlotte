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
- TOML virtual hosts with exact and wildcard names, per-host document roots,
  and isolated worker processes that can drop to configured user/group IDs.
- FastCGI over TCP or Unix sockets, with optional server-managed FastCGI
  application processes.
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
| `--config FILE` | Load virtual-host declarations from a TOML file. |
| `--vhost-dir DIRECTORY` | Load and watch additional virtual-host TOML files in a directory. |
| `--tls-bind ADDRESS` | Listen for HTTPS; configure a certificate with `--tls-cert` and `--tls-key`, or use eligible ACME virtual hosts. |
| `--http3-bind ADDRESS` | Enable the HTTP/3 listener; TLS configuration is required. |
| `--fastcgi EXT=ADDR` | Route a file extension to a FastCGI TCP or Unix-socket backend. |
| `--fastcgi-app EXT=PROGRAM` | Start and supervise a FastCGI application for an extension. |
| `--modsecurity-rules FILE` | Load ModSecurity rules; can be repeated to load multiple files. |
| `--acme-directory URL --acme-cache DIR` | Configure ACME certificate provisioning and its cache. |

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

Virtual-host configuration is provided as TOML. For example, a basic host
declaration looks like this:

```toml
[[vhost]]
server_names = ["www.example.com", "example.com"]
root = "/srv/www/example.com/public"
user = "www-example"
group = "www-data"
index = "index.html"
listing = false
```

The root and worker user are required for each host. Each configured host is
served by a worker process. See
[`examples/charlotte.toml`](examples/charlotte.toml) for FastCGI, TLS,
catch-all, ACME, and additional settings, and
[`examples/vhosts.d/example.toml`](examples/vhosts.d/example.toml) for a
per-host file. Paths in virtual-host files are resolved relative to their
configuration file.

For ACME HTTP-01 provisioning, configure eligible virtual hosts and ensure the
ACME service can reach the server over plaintext HTTP. Keep the ACME cache
outside all served document roots. See the example configuration for details.

## Development

Run tests with `cargo test`. Fuzz target setup, seed tests, and target commands
are documented in [FUZZING.md](FUZZING.md).