# Architecture

`project-charlotte` is an asynchronous Rust web server. It serves static files
and directory listings, can route configured virtual hosts to separate worker
processes, and optionally integrates FastCGI, ModSecurity, TLS, ACME certificate
provisioning, and HTTP/3. `src/main.rs` is the composition root: it parses
configuration, initializes shared services, starts listeners, and coordinates
shutdown.

## Configuration and startup

`config::Config::parse` reads command-line options for listener addresses,
document roots, static-file behavior, FastCGI, TLS, ACME, ModSecurity, thread
counts, and worker privileges. An optional TOML configuration file declares
virtual hosts and can name a directory of additional virtual-host files.
Paths in those declarations are resolved relative to their configuration
source. The [examples](examples/) directory contains project examples.

In master mode, startup canonicalizes the fallback document root, starts any
configured FastCGI applications, loads the WAF and virtual-host table, and
initializes ACME and TLS certificate resolution. It then binds the plaintext
listener and any configured TLS or HTTP/3 listeners. TLS and HTTP/3 require
TLS configuration or eligible ACME virtual hosts as appropriate.

## Processes and request flow

The master owns public listeners, protocol negotiation, virtual-host routing,
and shared certificate and policy state. Its Tokio runtime accepts connections
concurrently. TCP connections use Hyper's automatic HTTP/1 and HTTP/2 server;
HTTP/3 uses a separate QUIC endpoint and `h3`. All transports pass requests to
the same router.

The request path is:

1. The master accepts a TCP connection, or the HTTP/3 endpoint accepts a QUIC
   connection. For TLS connections, the handshake obtains the SNI name and
   selects a certificate.
2. `Router::dispatch` checks for a matching ACME HTTP-01 challenge first. On
   plaintext requests with a host, it may also start certificate provisioning
   in the background.
3. The router selects a virtual host from the request authority, falling back
   to the default host when configured. It applies that host's WAF, or the
   global WAF, before normal routing.
4. Routing checks that a TLS request's SNI and HTTP authority select the same
   virtual host. A mismatch is rejected with `421 Misdirected Request`.
   Requests for a configured virtual host are forwarded to its worker; if no
   virtual host matches and no default is configured, the master uses the
   fallback `Config` directly.
5. `handler::handle_request` applies `try_files` rules, resolves FastCGI
   scripts, or serves a static file or directory listing. Static responses
   include MIME types, validators, conditional-request handling, and byte
   ranges. `HEAD` responses omit the body.
6. The response returns through the router to the client. Where HTTP/3 is
   enabled for TCP traffic, the master also advertises its endpoint with an
   `Alt-Svc` header.

## Virtual-host workers

Each configured virtual host has a worker that runs the same executable in
`--worker` mode. The process is started on the first request and reused while
its connection remains healthy. The router connects to it through a Unix
socket pair; the private connection uses HTTP/2 and is not a public listener.
Before forwarding, the master records the original peer and local socket
addresses and HTTP version in internal `x-charlotte-*` headers, and converts
the request URI to an absolute form for the internal request. The worker
validates and removes that metadata, restores the original URI and version,
then calls the same request handler used by the fallback path.

Workers can run under configured UID/GID credentials. The master asks workers
to terminate cleanly and uses a bounded wait before forcibly stopping one, so
worker-managed FastCGI applications can clean up as well.

## FastCGI application pools

Each server-managed FastCGI app starts with one supervised process. Requests
lease an idle process; if all existing processes are busy, the pool starts
another up to `max_workers` (1–256, default 1). Each process has its own Unix
listening socket in a private per-app directory. When the pool is idle, extra
processes are reaped after `idle_timeout` seconds (1–86,400, default 60), while
one process remains available. The CLI options are
`--fastcgi-app-max-workers EXT=N` and
`--fastcgi-app-idle-timeout EXT=SECS`; virtual-host TOML uses `max_workers` and
`idle_timeout` (the older `workers` TOML field and
`--fastcgi-app-workers` option remain aliases for `max_workers`). Each process
is supervised and restarted independently.

## TLS, SNI, and ACME

`tls` builds Rustls server configurations and resolves certificates by SNI.
An available ACME certificate is preferred; otherwise the resolver selects a
matching virtual-host certificate or the configured fallback certificate. The
same resolver supports TCP TLS and HTTP/3 TLS. After the handshake, the router
compares the normalized SNI host with the request authority's selected host to
prevent cross-host routing on a TLS connection.

`acme` manages the ACME account, HTTP-01 challenge responses, certificate
cache, and renewal/provisioning work. Challenge responses are served by the
router before WAF inspection. Startup ensures the ACME cache is outside every
served document root. Certificate state is shared with the TLS resolver so a
newly provisioned certificate can be used without restarting the server.

## Reload and shutdown

When a virtual-host directory is configured, `reload` watches it for changes
and coalesces bursts of filesystem events before reloading. `vhost` parses and
validates the combined declarations, then publishes the updated routing
configuration. The reload path also refreshes static SNI certificates and the
set of ACME-eligible names.

On Ctrl-C, the master broadcasts shutdown to connection tasks. TCP connections
are asked to shut down gracefully; the HTTP/3 task and virtual-host watcher
are joined, and active connection tasks are allowed to finish. Worker process
cleanup is handled when their router-owned handles are dropped.

## Module map

| Module | Responsibility |
| --- | --- |
| `main` | Startup, listeners, connection tasks, protocol dispatch, and shutdown. |
| `config` | CLI parsing and shared server, virtual-host, and backend settings. |
| `vhost` | Virtual-host loading and matching, routing, worker management, and request dispatch. |
| `worker` | Private HTTP/2 worker service, metadata validation, and privilege dropping. |
| `handler` | Request handling, static files, listings, ranges, validators, and response helpers. |
| `fastcgi` | FastCGI script resolution, request parameters, and backend exchange. |
| `fastcgi_app` | Lifecycle management for FastCGI applications started by the server. |
| `waf` | ModSecurity rule loading and request/response inspection. |
| `tls` | Rustls configuration, static certificates, and SNI certificate selection. |
| `acme` | ACME account, HTTP-01 challenges, certificate cache, and renewal. |
| `http3` | QUIC and HTTP/3 connection handling, forwarding requests to the router. |
| `reload` | Virtual-host directory watcher and coordinated routing/TLS/ACME refresh. |
| `httpdate` | HTTP-date formatting and parsing for protocol headers and validators. |
| `mime` | File-extension to content-type mapping. |
| `fuzz_support` | Shared request fixtures and helpers used by fuzz-oriented unit tests. |

## Security and testing boundaries

Request paths are decoded and checked before filesystem access, and resolved
files are constrained to the configured document root. Virtual-host workers
provide a process boundary and can use a separate UID/GID; this is not a
substitute for deployment-level sandboxing. WAF request and response body
limits are configurable. The ACME cache is kept outside served roots so
private key material is not exposed as static content.

The master refuses a configuration file, virtual-host directory, or
virtual-host file that is world-writable or owned by anyone other than root
or the server's own user, and refuses a virtual host whose user is root: those
files choose the account a worker runs as and the programs it starts. A
worker receives only a short allowlist of the master's environment, and the
environment of its FastCGI apps reaches it through its own environment rather
than its command line.

Files whose name begins with a dot are neither served nor listed, except
under `.well-known`. A served file is opened first and then confirmed, by
descriptor, to lie under the document root, so swapping a path component for
a symbolic link cannot redirect the read. When the WAF is active, `Range`
and `If-Range` are removed from requests after inspection so that response
rules always see a whole response; the cost is that inspected responses
cannot be resumed or seeked. Responses larger than the response-body limit
are inspected only up to that limit.

The master accepts at most 4096 concurrent TCP connections, closes a
connection that has not produced a complete request head within 30 seconds,
and bounds the time a client may take to deliver a request body. A failed
`accept` is logged rather than fatal. The master itself keeps the privileges
it was started with; it terminates TLS, parses requests, serves the fallback
site, and runs ModSecurity in that one process.

Unit and integration tests cover routing, handlers, TLS, ACME, FastCGI, and
ModSecurity. Fuzz targets exercise parsed inputs and request-handling paths;
see [FUZZING.md](FUZZING.md) for target names, setup, and commands. HTTP wire
parsing itself is delegated to Hyper and `h3` and is outside those fuzz
targets.