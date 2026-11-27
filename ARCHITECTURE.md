# Architecture

`project-charlotte` is an asynchronous Rust web server. It serves static files
and directory listings, can route configured virtual hosts to separate worker
processes or HTTP/HTTPS upstreams, and optionally integrates FastCGI, CGI,
ModSecurity, TLS, ACME certificate provisioning, HTTP/3, and Redis-backed
swarm access checks. `src/lib.rs` is the composition root: it parses
configuration, initializes shared services, starts listeners, and coordinates
shutdown. `src/main.rs` is a thin executable wrapper that calls the library's
`run` function. The companion binaries are `charlotte-ctl`,
`apache2charlotte`, `nginx2charlotte`, and `charlotte-configure`.

## Build features

Five Cargo features, all enabled by default, select the major parts of the
server:

| Feature | Modules and dependencies it compiles |
| --- | --- |
| `hosting` | `handler`, `fastcgi`, `fastcgi_app`, `worker`, `mime`, `vhost::hosted`; `fastcgi-client`. |
| `proxy` | `proxy`; `hyper-rustls` and the Hyper client. |
| `acme` | `acme`; `instant-acme`, `x509-parser`. |
| `http3` | `http3`; `quinn`, `h3`, `h3-quinn`. |
| `swarm` | `swarm`; Redis-backed access checks and request recording, with optional nftables sets. |

`main`, `config`, `control`, `bot`, `cgroup`, `forwarded`, `ja4`, `logging`,
`logopener`, `pathctx`, `privileges`, `ratelimit`, `reload`, `response`, `tls`,
`vhost`, and `waf` are present in every build. `swarm` is feature-gated;
`mime` is used by hosting. `Config` and virtual-host declarations keep the same
shape whichever features are enabled: `Config::parse` and virtual-host
validation refuse settings that belong to a feature that was left out and name
that feature. Without `hosting` there are no worker processes and no fallback
site, so a request that matches no virtual host is answered `404`.

## Configuration and startup

`config::Config::parse` reads command-line options for listener addresses,
document roots, static-file behavior, FastCGI and CGI, TLS, ACME, ModSecurity,
thread counts, worker privileges, and other server settings. The main YAML
configuration can also set global CLI defaults in an `options` mapping;
explicit command-line values take precedence. `--check-config` validates the
main configuration and vhost-directory files, reports source locations, and
exits before opening logs, dropping privileges, or starting listeners. The
configuration can declare virtual hosts and name a directory of additional
virtual-host files. Paths in those declarations are resolved relative to their
configuration source. The [examples](examples/) directory contains project
examples.

When running as root with `--user`, the master reads the trusted main
configuration while still privileged and passes its contents on after the
privilege drop; the configured account may not be able to traverse the
configuration directory. Startup canonicalizes the fallback document root,
creates configured FastCGI application pools (which prewarm their configured
minimum workers), loads the WAF and virtual-host table, and initializes ACME
and TLS certificate resolution. Hosted vhost roots and worker identities are
validated at startup, but hosted workers are started only when traffic first
reaches them. The master then binds the plaintext listener, any configured TLS
or HTTP/3 listeners, and the optional Unix configuration socket. The socket is
mode `0600`, and its parent directory is prepared for the configured master
account before the privilege drop. TLS and HTTP/3 require TLS configuration or
eligible ACME virtual hosts as appropriate.

## Processes and request flow

The master owns public listeners, protocol negotiation, virtual-host routing,
and shared certificate and policy state. Its Tokio runtime accepts connections
concurrently. TCP connections use Hyper's automatic HTTP/1 and HTTP/2 server;
HTTP/3 uses a separate QUIC endpoint and `h3`. All transports pass requests to
the same router.

The request path is:

1. The master accepts a TCP connection, or the HTTP/3 endpoint accepts a QUIC
   connection. For TCP TLS connections, a bounded recorder captures the
   ClientHello for JA4 while the handshake obtains SNI and selects a
   certificate. HTTP/3 and plaintext requests have no JA4 fingerprint.
2. `Router::dispatch` resolves the client address from `X-Forwarded-For` only
   when the socket peer matches a configured trusted-proxy CIDR; otherwise it
   removes the header. The router selects a virtual host from the request
   authority, falling back to the default host when configured. Every request
   is recorded in the server-wide traffic meter used by bot busy gating. On
   plaintext requests with a host, ACME certificate provisioning may also
   start in the background.
3. Before ordinary routing, the master answers ACME HTTP-01 challenges. It
   then applies an enabled HTTP-to-HTTPS redirect for a selected vhost that has
   a certificate and an active TLS listener, the vhost or global rate limit,
   optional swarm Redis checks, the effective bot policy, and request-phase
   inspection by the vhost or global WAF, in that order. These pre-routing
   responses do not reach a worker or upstream. Response-phase WAF inspection
   happens after the handler or upstream has produced a response.
4. Routing checks that a TLS request's SNI and HTTP authority select the same
   virtual host. A mismatch is rejected with `421 Misdirected Request`.
   Proxy virtual hosts forward directly from the master. Worker-backed hosts
   are forwarded to their worker; if no virtual host matches and no default is
   configured, the master uses the fallback `Config` directly.
5. `handler::handle_request` applies `try_files` rules, resolves FastCGI or CGI
   scripts, or serves a static file or directory listing. Small static files
   may be served from the in-memory cache. Other static responses include MIME
   types, validators, conditional-request handling, and byte ranges. `HEAD`
   responses omit the body.
6. Response-phase WAF inspection runs as the response returns through the
   router. Request-stage timings are attached to the response and, when
   enabled, included in `Server-Timing`; access-log and debug summaries are
   completed when the response body finishes or is dropped. Where HTTP/3 is
   enabled for TCP traffic, the master also advertises its endpoint with an
   `Alt-Svc` header.

Rate limiting is optional and runs for TCP and QUIC requests across HTTP/1,
HTTP/2, and HTTP/3, after ACME challenges and HTTPS redirects. A vhost can
inherit the global limiter, replace it with an independent limiter, or disable
rate limiting. Buckets use the resolved client IP (IPv6 grouped by `/64`) and
bounded, sharded in-memory state; rejection returns `429` with `Retry-After`.
When swarm support is enabled and configured, Redis access checks run after
rate limiting and before bot policy; a vhost can opt out. When an access log
is configured (globally or for the selected vhost), `Router::dispatch` wraps
the response body so that one record is written in the configured Apache
`LogFormat` once the body finishes or is dropped. File log targets use
background writers; stdout and stderr targets are synchronous. Dispatch also
scopes a task-local request context (client, local address, server name, and
the vhost's error log) so that errors raised while handling the request,
including CGI and FastCGI stderr, reach the right error log. Hosted workers
write their errors to stderr, which the master or root helper directs to the
vhost (or global) error-log target.

Bot detection is opt-in through `--bot-detection` or `--bot-config`. Global
policy is inherited by vhosts unless they specify `bot: off` or a policy map.
The master scores request and JA4/header signals, verifies claimed crawler IPs
with background reverse/forward DNS checks, and applies log, challenge, or
block actions. Challenge and crawler caches are bounded; DNS concurrency is
limited, and proof-of-work cookies are signed and scoped to the client's `/24`
or `/64` prefix. A configured busy threshold gates policy evaluation using
server-wide request volume. JA4 is available for captured TCP ClientHello
messages, not plaintext or HTTP/3.

## Configuration socket

`control` serves an HTTP/1.1 JSON API over a Unix socket when
`--control-socket` is configured. Its state holds the shared `Router`, startup
configuration, TLS SNI handle, and process start time; this is also the
extension point for future statistics. Vhost CRUD is restricted to the watched
vhost directory; entries in the main configuration are visible but read-only.

For a mutation, `Router` applies a proposed file override to the complete set of
source files while holding the source-state lock, validates the declarations,
and builds the candidate vhost table. Only after all checks succeed does it
write a mode-`0640` temporary file, fsync and rename it (or remove the file for
delete), then atomically replace the active table. The directory watcher sees
the resulting filesystem event but skips it because the committed contents are
already current. Both watcher and socket changes share the TLS SNI and ACME
post-reload update path. Request bodies are capped at 1 MiB and accepted as
JSON or YAML.

## Virtual-host workers

Each worker-backed virtual host has a worker that runs the same executable in
`--worker` mode. Its configuration and document-root type are validated at
startup, but the process is started on the first request and reused while its
connection remains healthy. An idle worker is stopped after the configured
`worker_idle_timeout` (300 seconds by default); `0` disables reaping, and the
next request starts a stopped worker again. Active requests, including
streaming response bodies, prevent idle reaping. The router connects to the
worker through a Unix socket pair; the private connection uses HTTP/2 and is
not a public listener. Before forwarding, the master records the resolved
client and local socket addresses and HTTP version in internal
`x-charlotte-*` headers, and converts the request URI to an absolute form for
the internal request. The worker validates and removes that metadata, restores
the original URI and version, then calls the same request handler used by the
fallback path.

Workers can run under configured UID/GID credentials and receive the target
user's supplementary groups from the group database. Optional cgroup v2 paths
and memory, CPU, and PID limits are applied before the worker starts; child
CGI/FastCGI processes inherit its cgroup. The root helper owns workers when
the master drops privileges, and worker shutdown uses bounded waits so a
failed worker cannot hang startup or teardown.

## Reverse proxies

A vhost with `proxy_pass` is handled directly in the master and does not need
a document root or worker process. Its upstream URL may use HTTP or HTTPS and
include a path prefix; the incoming path and query are appended. A pooled
Hyper client negotiates HTTP/1.1 or HTTP/2 with HTTPS upstreams using ALPN;
`proxy_http2: true` instead forces HTTP/2, including prior-knowledge h2c for
cleartext HTTP upstreams. The pool keeps up to 64 idle connections per host
for 90 seconds. TCP upstreams use `TCP_NODELAY`, and on Linux the client
requests quick acknowledgements after reads. TCP HTTP/1.1, HTTP/2, and QUIC
HTTP/3 clients all use this same routing path. Request and response bodies are
streamed, hop-by-hop headers (including headers named by `Connection`) are
removed, and the proxy sets `X-Forwarded-For`, `X-Forwarded-Proto`, and
`X-Forwarded-Host`. An incoming `X-Forwarded-For` chain is retained only when
the direct peer matches a configured `--trusted-proxy` address or CIDR;
otherwise the header is removed. The upstream chain contains normalized IP
addresses and the direct peer IP, without socket ports. HTTPS upstreams use
system roots by default or a configured PEM CA bundle. Header acquisition has
a configurable timeout; WebSocket/Upgrade and CONNECT tunnelling are not
implemented.

## FastCGI application pools

Server-managed CGI-mode FastCGI apps prewarm `min_workers` at startup (default
1), then start more on demand up to `max_workers` (default CPU count, capped
at 8). Each worker process has its own Unix listening socket in a private
per-app directory and is supervised independently. Idle workers are reaped
after `idle_timeout` (default 60 seconds), but the pool never shrinks below its
minimum; setting the minimum to 0 permits it to shrink to zero. `mode: fpm`
instead supervises one PHP-FPM process with a generated private pool
configuration, and Charlotte limits concurrent leases to `max_workers`.
PHP-named managed apps receive OPcache and realpath-cache defaults and a
private OPcache file-cache directory unless disabled or overridden. CGI-mode
apps use `PHP_FCGI_MAX_REQUESTS=10000` by default; FPM mode configures its
corresponding `pm.max_requests` limit. Explicit app arguments and environment
settings take precedence. CLI settings include
`--fastcgi-app-min-workers EXT=N`, `--fastcgi-app-max-workers EXT=N`,
`--fastcgi-app-idle-timeout EXT=SECS`, `--fastcgi-app-mode EXT=cgi|fpm`, and
`--fastcgi-app-php-defaults EXT=on|off` (the older `workers` YAML field and
`--fastcgi-app-workers` option remain aliases for `max_workers`).

External FastCGI TCP and Unix-socket backends use a separate keep-alive pool:
up to 8 idle connections per backend by default, with a 30-second idle expiry.
Only fully read responses return a connection to the pool; a request using a
stale pooled connection is retried once on a fresh connection if the failure
occurs before response content arrives. `--fastcgi-keepalive 0` disables this
reuse. Server-managed application sockets are not part of this pool.

For hosted static files, files up to 64 KiB can be cached in memory. The default
TTL is 1 second, with caps of 1,024 entries and 32 MiB; `--static-cache-ttl-ms
0` disables it. Changes can remain unseen until an entry expires.

## Classic CGI

Configured CGI extensions use the same root-confined script resolver and CGI
request variables as FastCGI. Each request starts a process directly or via an
optional interpreter; the request body is written to stdin, CGI headers are
parsed before returning the response, and stdout is streamed while the child
is supervised. The process receives a cleared environment populated with CGI
parameters and `PATH`. Virtual-host scripts run with the worker's credentials.

## TLS, SNI, and ACME

`tls` builds Rustls server configurations and resolves certificates by SNI.
An available ACME certificate is preferred; otherwise the resolver selects a
matching virtual-host certificate or the configured fallback certificate. The
same resolver supports TCP TLS and HTTP/3 TLS. After the handshake, the router
compares the normalized SNI host with the request authority's selected host to
prevent cross-host routing on a TLS connection. When the master drops to
`--user`, the root helper reads static certificate and key PEM files from the
TLS directories it was started with and returns only parsed certificate and
private-key DER sections to the master. TLS listeners keep a 16,384-entry
session cache and issue session tickets to support session resumption.

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

On Ctrl-C or SIGTERM, the master broadcasts shutdown to connection tasks. TCP
connections are asked to shut down gracefully; the HTTP/3 task and virtual-host
watcher are joined, and active connection tasks are allowed to finish. Worker
process cleanup is handled when their router-owned handles are dropped. File
logs are flushed during shutdown; files use background writer threads with
batched writes, while stdout and stderr logging remains synchronous.

## Module map

| Module | Responsibility |
| --- | --- |
| `lib` | Composition root, server startup, listeners, protocol dispatch, and shutdown. |
| `main` | Thin executable wrapper around the library's `run` function. |
| `config` | CLI parsing and shared server, virtual-host, and backend settings. |
| `configure_support` | Hidden library validation API used by `charlotte-configure`. |
| `control` | Local Unix-socket configuration API and vhost mutations. |
| `vhost` | Virtual-host loading and matching, routing, proxy dispatch, and request dispatch. |
| `vhost::hosted` | Master-side worker processes for hosted virtual hosts: spawning, request forwarding, and restart. |
| `worker` | Private HTTP/2 worker service, metadata validation, and privilege dropping. |
| `handler` | Request handling, static files, listings, ranges, and validators. |
| `response` | Response construction shared by every build: status and error responses, the `Date` header, and body coalescing. |
| `fastcgi` | FastCGI and CGI script resolution, request parameters, and backend exchange. |
| `fastcgi_app` | Lifecycle management for FastCGI applications started by the server. |
| `proxy` | Pooled HTTP/HTTPS upstream clients and reverse-proxy header/body handling. |
| `waf` | ModSecurity rule loading and request/response inspection. |
| `bot` | Bot policy parsing, request scoring, crawler checks, challenges, and cookies. |
| `ja4` | Bounded TLS ClientHello capture, parsing, and JA4 fingerprinting. |
| `cgroup` | Validation and setup for worker cgroup v2 paths and resource limits. |
| `swarm` | Feature-gated Redis access checks and batched request writes, plus optional nftables set refresh and matching. |
| `ratelimit` | Bounded per-client GCRA request buckets and `429` responses. |
| `forwarded` | Trusted-proxy CIDR matching and XFF resolution/sanitization. |
| `logging` | Apache-compatible formats, request timing/context, synchronous console targets, and queued file writers. |
| `logopener` | Root helper for a master that drops to `--user`: opens log files and reads TLS PEM sections inside directories fixed at startup, and starts and stops virtual-host workers. |
| `tls` | Rustls configuration, static certificates, and SNI certificate selection. |
| `acme` | ACME account, HTTP-01 challenges, certificate cache, and renewal. |
| `http3` | QUIC and HTTP/3 connection handling, forwarding requests to the router. |
| `reload` | Virtual-host directory watcher and coordinated routing/TLS/ACME refresh. |
| `httpdate` | HTTP-date formatting and parsing for protocol headers and validators. |
| `mime` | File-extension to content-type mapping. |
| `privileges` | Dropping the master to `--user`/`--group` and narrowing its capabilities; website operations remain under the selected account. |
| `pathctx` | Filesystem error context and trusted path/configuration checks. |
| `fuzz_support` | Shared request fixtures and helpers used by fuzz-oriented unit tests. |

## Security and testing boundaries

Request paths are decoded and checked before filesystem access, and resolved
files are constrained to the configured document root. Virtual-host workers
provide a process boundary and can use a separate UID/GID; this is not a
substitute for deployment-level sandboxing. WAF request and response body
limits are configurable. The ACME cache is kept outside served roots so
private key material is not exposed as static content.

The master refuses a configuration file, virtual-host directory, or
virtual-host file that is world-writable, writable by a group other than
root's, or owned by anyone other than root or the server's own user, and
refuses a virtual host whose user is root: those files choose the account a
worker runs as and the programs it starts. Each file is checked and read
through one descriptor. Only a server with no privilege at all also accepts
write access for its owner's private group. A
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

By default, the master accepts at most 4096 concurrent TCP connections
(`--max-connections`), closes a connection if no request starts within 30
seconds, and limits completion of each request head to the configured
`--header-read-timeout` (also 30 seconds by default). TLS handshakes are
limited to 10 seconds by default (`--tls-handshake-timeout`). A failed
`accept` is logged rather than fatal. Unless `--user` is supplied, the master
keeps the identity it was started with; with `--user`/`--group`, it drops to
that account before serving requests. It terminates TLS, parses requests,
serves the fallback site, runs ModSecurity, and forwards reverse-proxy traffic
in that process; the separate root helper opens log files and returns only
parsed TLS certificate/key sections, never raw PEM file contents.

With `--user`, the master drops its identity-changing capabilities and retains
`CAP_NET_BIND_SERVICE` only when it was permitted at startup. The helper
receives its log and TLS directories once, before the master drops privileges,
holds a descriptor for each, and resolves every later request beneath one of
them with `openat2(RESOLVE_BENEATH)`. It also owns the worker processes: the
master sends the worker's identity, arguments, environment and its end of the
socket pair, and the helper refuses UID 0, anything but a worker command line
for that identity, and environment names outside the worker allowlist. It
reaps exited workers and stops the rest when the master goes away. A non-root
server without `--user` can start workers itself when it has `CAP_SETUID` and
`CAP_SETGID`; it also retains `CAP_KILL` and `CAP_NET_BIND_SERVICE` when those
capabilities are permitted.

Unit and integration tests cover routing, handlers, TLS, ACME, FastCGI, CGI,
reverse proxying, ModSecurity, swarm checks, bot policy, limits, and shutdown.
Tests run under cargo-nextest, configured in `.config/nextest.toml`. Root-only
tests are marked ignored and run in the privileged CI job with
`cargo nextest run --run-ignored only`. Feature-combination checks compile all five optional
features in every combination. Fuzz targets exercise parsed inputs and
request-handling paths; see [FUZZING.md](FUZZING.md) for target names, setup,
and commands. HTTP wire parsing itself is delegated to Hyper and `h3` and is
outside those fuzz targets.