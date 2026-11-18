# project-charlotte

`project-charlotte` is an asynchronous Rust web server for static sites and
virtual-hosted applications. It serves files and directory listings, and can
optionally connect to or supervise FastCGI applications, inspect traffic with
ModSecurity, serve TLS and HTTP/3, and provision certificates with ACME.

For a deeper description of the runtime and request flow, see
[ARCHITECTURE.md](ARCHITECTURE.md). Configuration examples are in
[examples/](examples/), and fuzzing instructions are in [FUZZING.md](FUZZING.md).

Run the browser-driven live feature demo with `demo/run.sh`; see
[demo/README.md](demo/README.md) for prerequisites, controls, and the optional
headless validation mode.

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
release. Both packages install and enable the `project-charlotte.service`
systemd unit. Before starting it, create `/etc/charlotte/charlotte.yaml` from
the packaged example at
`/usr/share/doc/project-charlotte/examples/charlotte.yaml` (or the matching
`project-charlotte-proxy` documentation directory). The unit has a
`ConditionPathExists` check for that file, so systemd skips the service until
the configuration is present. After creating it, start the service with
`sudo systemctl start project-charlotte`. Edit
`/etc/default/project-charlotte` to change the command-line options passed to
the server; this file is preserved as a conffile during package upgrades.

### Apache configuration conversion

`apache2charlotte` converts an Apache configuration file to Charlotte's
virtual-host YAML. Relative `Include` paths use `ServerRoot` (or the input
configuration's directory); included directories are traversed recursively,
and `IncludeOptional` and file globs are supported. Directly supported
directives are converted, while the rest are retained as comments with their
source locations so they can be reviewed and migrated manually:

```sh
apache2charlotte /etc/apache2/apache2.conf --output charlotte-vhosts.yaml
```

Use `--server-root DIRECTORY` to override `ServerRoot`, and repeat `-D NAME`
or `-D NAME=VALUE` to define Apache variables used by `Include` and
`<IfDefine>`. Add `--no-comments` to omit the generated review and explanation
comments from the YAML output.

Add `--user-from-root` to set each vhost's `user` and `group` to the owner of
its document root, overriding configured values. Relative document roots are
resolved from the converter's current working directory; if ownership cannot
be determined, configured values are kept and a review comment is emitted.
FastCGI apps are emitted only when their executable is an absolute path;
commands such as `php-cgi` or relative paths are skipped with a review comment.
Apache `DirectoryIndex` and nginx `index` entries are converted to an ordered
`index` list; entries that are not bare file names are skipped with a review
comment.

### nginx configuration conversion

`nginx2charlotte` converts nginx `http`/`server` configuration to Charlotte's
virtual-host YAML. Relative `include` paths use the input file's directory by
default; included directories are traversed recursively and file globs are
supported. Recognized directives are converted, while unsupported directives
are retained as source-located comments for manual review:

```sh
nginx2charlotte /etc/nginx/nginx.conf --output charlotte-vhosts.yaml
```

Use `--prefix DIRECTORY` to change the base directory for relative includes.
Only `location /` and PHP regex locations have direct route mappings; other
locations and nginx listener settings are retained as comments. Add
`--no-comments` to omit the generated review and explanation comments from the
YAML output.

Add `--user-from-root` to set each vhost's `user` and `group` to the owner of
its root, overriding configured values. Relative roots are resolved from the
converter's current working directory; if ownership cannot be determined,
configured values are kept and a review comment is emitted.

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
| `--debug` | Log verbose startup details, including listener binding, workers, and TLS initialization. |
| `--no-plain-http` | Disable the plain HTTP listener; incompatible with ACME HTTP-01. |
| `--root DIRECTORY` | Fallback document root when no virtual host handles a request; defaults to `.`. |
| `--user USER [--group GROUP]` | Drop the master process to this account before starting; requires root. |
| `--index NAME` | Fallback index file name; repeat or comma-separate values to try them in order (default `index.html`). |
| `--no-listing` | Disable directory listings, which are enabled by default. |
| `--try-files ENTRY` | Add a candidate or fallback rule; may be specified more than once. |
| `--config FILE` | Load virtual-host declarations from a YAML file. |
| `--vhost-dir DIRECTORY` | Load and watch additional `.yaml` and `.yml` virtual-host files in a directory. |
| `--check-config` | Validate the virtual-host YAML files and exit, reporting errors with source locations. |
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
| `--log-dir DIRECTORY` | With `--user`: additional directory in which the root helper may open log files (repeatable). |
| `--tls-dir DIRECTORY` | With `--user`: additional directory from which the root helper may read TLS PEM files (repeatable). |
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

Any command-line option can also be set as a global default in the main
configuration file's top-level `options` mapping. Use the long option name with
hyphens or underscores; flags take YAML booleans, single-value options take a
scalar, and repeatable options take a scalar or sequence. Command-line values
override file defaults, and an explicitly supplied repeatable option replaces
the corresponding file sequence. Relative path options are resolved against
the directory containing the config file. The `config`, `check-config`, `help`,
and internal worker options cannot be set this way. For example:

```yaml
options:
  bind: 0.0.0.0:8080
  debug: true
  index: [index.html, index.htm]
  access-log-file: logs/access.log
```

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
to the YAML file and are reopened when virtual hosts are reloaded. When the
server starts as root with `--user`, a small root helper opens log files,
including worker stderr logs, and reads TLS certificate and key files so they
need not be accessible to the website account. The master and website workers
still perform website operations under their configured users and groups. The
server sends error output to stderr when no error log is configured, including
output from the root helper and worker processes.

The helper only works inside directories fixed at startup: the directories
holding the log files and TLS certificate/key files named by the options and
virtual hosts read at startup, the ACME cache, and any directory added with
`--log-dir DIRECTORY` or `--tls-dir DIRECTORY` (both repeatable; `log_dir` and
`tls_dir` in the `options` of the config file). Log and TLS directories are
separate lists, the filesystem root cannot be listed, and the list cannot be
changed while the server runs. A reload or control-socket change that names a
log or TLS file in any other directory is refused until the server is
restarted or the directory is listed with one of those options. Within a
listed directory the helper resolves paths with `openat2(RESOLVE_BENEATH)`, so
neither `..` nor a symlink can lead outside it; it only handles regular files,
refuses a final-component symlink, and returns append-only descriptors for
logs and only parsed certificate/key DER sections for TLS. A compromised
master can therefore still append to log files and read PEM sections in the
listed directories, and nowhere else. A listed directory is covered with all
its subdirectories, so keep log files in a directory of their own: a log
configured as `/var/log/site.log` lists all of `/var/log`.

Access formats follow Apache `mod_log_config`: `%%`, `%a`, `%{c}a`, `%A`, `%b`,
`%B`, `%D`, `%h`, `%H`, `%I`, `%{Name}i`, `%{Name}o`, `%{Name}C`, `%l`, `%m`,
`%{ja4}n`, `%O`, `%p`, `%{local|remote|canonical}p`, `%P`, `%q`, `%r`,
`%s`, `%S`, `%>s`, `%t`, `%{strftime}t` (including `begin:`/`end:` and
`sec`, `msec`, `usec`, `msec_frac`, `usec_frac`), `%T`, `%{s|ms|us}T`, `%u`,
`%U`, `%v`, and `%V`, plus
status conditions such as `%400,501{User-Agent}i` and `%!200{Referer}i`.
Unsupported directives are rejected at startup. The default format keeps the
previous stdout layout. Records are written when the response body finishes,
so `%b`, `%D`, and `%T` reflect what was sent.
`%I`, `%O`, and `%S` include request bytes received, response bytes sent, and
their total, respectively. Header sizes are estimates based on HTTP/1.x request
and response lines and header fields; they may differ from actual wire bytes,
especially with HTTP/2 compression or headers added by Hyper after dispatch.

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
API for the vhost directory. The socket is created with mode `0600`. A missing
parent directory is created with mode `0750` (missing ancestors get `0755`);
with `--user`, this happens before privileges are dropped and the directory is
owned by the `--user`/`--group` account. An existing directory owned by that
account is tightened to `0750`. An existing directory owned by someone else is
handed over only if it is empty or contains just the old socket; otherwise it
must already be writable by the server's effective account, and startup fails
with an explanatory error rather than re-owning a shared directory such as
`/run`. Keep the directory unwritable by untrusted users. `GET /vhosts`
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

The `charlotte-ctl` binary exposes the same operations without constructing
HTTP requests manually. `--socket` selects the control socket and defaults to
`CHARLOTTE_CONTROL_SOCKET` or `/run/charlotte/control.sock`; `--timeout` sets
the socket read and write timeout in seconds (10 by default). For example:

```sh
charlotte-ctl list
charlotte-ctl get example
charlotte-ctl put example example.yaml
cat example.yaml | charlotte-ctl create example -
charlotte-ctl delete example
```

For `create` and `put` (also available as `apply`), the file argument is
optional and defaults to standard input; pass `-` to select standard input
explicitly. Request files may contain JSON or YAML. Successful JSON responses
are printed to standard output as pretty-printed JSON; server errors are shown
on standard error and return a nonzero exit status.

The API uses `201` for a successful create, `200` for a successful get or
replace, and `204` for delete. Invalid requests return `400`, missing vhosts
`404`, create conflicts `409`, oversized bodies `413`, and unavailable mutation
storage `503`.

### Bot detection

Bot detection is disabled unless `--bot-detection` (the built-in policy in
enforcing mode) or `--bot-config FILE` (a YAML policy) is used. The master
evaluates every request after the ACME challenge check and the rate limit, and
before ModSecurity and routing, so blocked and challenged requests never reach
the WAF, a worker, a script, or a proxied upstream. The client address is the
same one used for rate limiting, so it honours `--trusted-proxy`.

#### How a request is scored

Each request gets a score from 0 upwards; the reasons are recorded alongside
it. The checks run in this order:

1. **Bypasses.** `mode: off`, a path starting with an `exempt_paths` prefix, or
   a client in `allow_ips` is allowed without further checks.
2. **Honeypots.** A client banned by a honeypot is blocked (score 100). A
   request with any method whose path equals a `honeypot_paths` entry bans the
   client IP for `honeypot_ban` seconds and is blocked.
3. **Explicit rules.** A client in `deny_ips`, a user agent containing a
   `deny_user_agents` substring, or a JA4 fingerprint in `ja4_deny` adds 100.
   Without a deny match, a user agent containing an `allow_user_agents`
   substring is allowed immediately. User-agent patterns are matched
   case-insensitively.
4. **Built-in rules** (`builtin_rules: true`, the default):

   | Signal | Score |
   | --- | --- |
   | Scanner user agent (`sqlmap`, `nikto`, `nmap`, `masscan`, `zgrab`, `nuclei`, `wpscan`, `acunetix`, `nessus`, `openvas`, `dirbuster`, `gobuster`, `ffuf`) | 100 |
   | Automation user agent (`curl`, `wget`, `python-requests`, `python-urllib`, `go-http-client`, `okhttp`, `java/`, `libwww-perl`, `scrapy`, `aiohttp`, `axios`, `node-fetch`, `httpclient`, `headlesschrome`, `phantomjs`) | 50 |
   | Empty or missing user agent | 50 |
   | Browser user agent over HTTP/1.0 | 30 |
   | Browser user agent without `Accept` | 20 |
   | Browser user agent without `Accept-Language` | 20 |
   | Browser user agent over TLS without `Sec-Fetch-Mode` | 15 |

   A "browser user agent" contains `chrome/`, `chromium/`, `firefox/`,
   `safari/`, or `edg/`.
5. **TLS fingerprint.** On TCP TLS connections Charlotte records the
   ClientHello and computes its [JA4](https://github.com/FoxIO-LLC/ja4)
   fingerprint (also available in access logs as `%{ja4}n`). Without a deny
   match, a fingerprint in `ja4_allow` is allowed immediately. For browser
   user agents, a ClientHello that offers neither `h2` nor `http/1.1` ALPN adds
   30, one whose highest version is below TLS 1.3 adds 30, and a Chrome,
   Chromium or Edge user agent without GREASE values adds 40.
6. **Crawler verification** (`verify_crawlers: true`, the default). A user
   agent claiming to be Googlebot, Bingbot, Applebot, YandexBot, Baiduspider or
   DuckDuckBot triggers a reverse DNS lookup of the client IP. The name must end
   in the operator's domain (`.googlebot.com`, `.search.msn.com`,
   `.applebot.apple.com`, `.yandex.ru`, `.crawl.baidu.com`, `.duckduckgo.com`)
   and resolve forward to the same IP. A verified crawler is allowed unless a
   deny rule matched; an impostor adds 100. Lookups time out after 2 seconds,
   at most 16 run at once, and results are cached for an hour (60 seconds after
   a lookup error, which adds nothing to the score).

#### What happens next

A score at or above `block_threshold` (default 80) returns `403 Forbidden`. A
score at or above `challenge_threshold` (default 40) gets a proof-of-work
challenge, unless `challenge: false` or the request carries a valid challenge
cookie. Anything lower is allowed. In `mode: log`, any request with a non-zero
score is allowed and only logged. Each block, challenge and log decision is
written to the error log, for example:

```text
bot detection: client=198.51.100.7:51234 score=50 action=Challenge reasons=["automation user-agent"]
```

The challenge is a small HTML page, returned with status 403. Its JavaScript
searches for a nonce whose SHA-256 hash, combined with a server-issued seed,
starts with `challenge_difficulty` zero bits (default 16, at most 24; each
extra bit doubles the work). The browser then loads
`/.well-known/charlotte-bot-challenge`. Charlotte checks the seed, the
proof-of-work and the return path, sets the `charlotte_bot` cookie and
redirects (`303`) to the original URL. The seed must be used within
`challenge_ttl` seconds (default 3600). The cookie is HMAC-SHA256 signed,
`HttpOnly`, `SameSite=Lax`, `Secure` on HTTPS, and valid for 7 days from the
client's IPv4 `/24` or IPv6 `/64`. Clients without JavaScript or cookies cannot
pass a challenge.

#### Configuration

A policy file, a vhost `bot` map, and the built-in defaults accept these keys:

| Key | Default | Meaning |
| --- | --- | --- |
| `mode` | `enforce` | `enforce`, `log` (score and log only), or `off`. |
| `challenge_threshold` | `40` | Lowest score that is challenged (1–100, at most `block_threshold`). |
| `block_threshold` | `80` | Lowest score that is blocked (at most 100). |
| `challenge` | `true` | Set to `false` to allow, rather than challenge, mid-range scores. |
| `challenge_difficulty` | `16` | Proof-of-work leading zero bits (0–24). |
| `challenge_ttl` | `3600` | Seconds a challenge seed stays valid (at most 7 days). |
| `allow_ips` / `deny_ips` | `[]` | IP addresses or CIDR ranges. |
| `allow_user_agents` / `deny_user_agents` | `[]` | Case-insensitive user-agent substrings. |
| `ja4_allow` / `ja4_deny` | `[]` | Exact JA4 fingerprints. |
| `builtin_rules` | `true` | Enable the built-in user-agent and header rules. |
| `honeypot_paths` | `[]` | Exact paths that ban the client. |
| `honeypot_ban` | `3600` | Ban length in seconds (at most 30 days). |
| `exempt_paths` | `[]` | Path prefixes that skip bot detection. |
| `verify_crawlers` | `true` | Verify claimed search-engine crawlers through DNS. |

Unknown keys are rejected, and paths must be local absolute paths.

```yaml
mode: log
challenge_threshold: 40
block_threshold: 80
allow_ips: [192.0.2.0/24]
allow_user_agents: [internal-monitor/]
exempt_paths: [/health, /api/]
honeypot_paths: [/wp-login.php]
honeypot_ban: 86400
verify_crawlers: true
```

The `--bot-config` file is the global policy. A virtual host inherits it, turns
it off with `bot: off`, or replaces it with its own policy map (a replacement,
not a merge):

```yaml
vhost:
  - server_names: [api.example.com]
    root: /srv/www/api
    user: www-api
    bot: off
  - server_names: [www.example.com]
    root: /srv/www/example
    user: www-example
    bot:
      challenge_difficulty: 18
      honeypot_paths: [/admin.php]
```

Automation clients such as `curl` score 50 and are challenged by default, which
breaks health checks and API clients. Start in log mode, read the logged
reasons, and add exemptions or allow rules for trusted clients before
enforcing.

#### Limitations

- The signing key, bans and crawler cache are held in memory. Restarting the
  server invalidates all challenge cookies and lifts all bans.
- All virtual hosts share one signing key and ban list. A challenge cookie
  issued by one vhost is accepted by the others, and a honeypot ban applies on
  every vhost with bot detection enabled.
- HTTP/3 and plaintext connections have no JA4 fingerprint, and neither does
  a ClientHello larger than the 16 KiB capture buffer. JA4 rules and scores do
  not apply to these requests.
- `exempt_paths` is a plain prefix match: `/health` also exempts
  `/healthcheck`. End the prefix with `/` where that matters.
- Honeypot bans are per exact IP address, so clients sharing a NAT are banned
  together, and an IPv6 client can move to another address in its `/64`.
  Anything that makes a visitor's browser request a honeypot URL, such as an
  embedded image on another site, bans that visitor.
- Allow rules based on user agents or JA4 fingerprints rely on values the
  client controls. Use `allow_ips` for clients that must never be challenged.

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
optionally override its primary group with `--group`. The master initializes
supplementary groups from the account's group database entry, using `--group`
as the primary group when supplied. Hosted workers likewise receive the
configured user's supplementary groups. This grants access available through
those groups to website operations, so configure group membership accordingly.
After the drop the master holds no capability except `CAP_NET_BIND_SERVICE`
(if it had it), so it cannot change its identity again or signal processes of
other accounts. A separate root helper opens log files, reads TLS
certificate/key PEM sections, and starts and stops virtual-host workers on the
master's behalf. The helper only starts this same binary in worker mode, never
as UID 0, with the short worker environment allowlist, and keeps only
`CAP_DAC_OVERRIDE`, `CAP_SETUID`, `CAP_SETGID` and `CAP_KILL`. The master
continues to handle requests and website operations under `--user`/`--group`,
and hosted workers continue under their configured identities. A compromised
master can still ask for a worker under any non-root account, as its
configuration already can.

The Debian package runs the server this way: `/etc/default/project-charlotte`
passes `--user www-data`, and the systemd unit confines the service
(`ProtectSystem=full`, private `/tmp` and devices, a capability bounding set,
and a system-call filter). Virtual hosts created through the control socket
are written by the `--user` account, so that account needs write access to the
`--vhost-dir` directory, which must still be owned by root or by that account.

Alternatively, an unprivileged account can run the binary with file
capabilities:

```sh
sudo setcap cap_setuid,cap_setgid=ep /path/to/project-charlotte
```

Add `cap_net_bind_service` to that command if the master must bind privileged
ports. `CAP_SETUID` is powerful: a compromised master with this capability can
switch to UID 0. Protect the binary and its configuration accordingly, or
prefer starting as root with `--user`, where the master keeps no such
capability.

The main config file, the `--vhost-dir` directory and the files in it choose
the accounts and programs the server runs. The server refuses any of them that
is not owned by root or by the account running the server, that is
world-writable, or that is group-writable by a group other than root's. Each
file is checked and read through the same open descriptor, so it cannot be
swapped between the check and the read. A server running without any
privilege (not root, no `--user`, no `CAP_SETUID`) also accepts a file that is
group-writable by its owner's private group, the group that has no other
member.

Virtual-host configuration is provided as YAML. For example, a basic host
declaration looks like this:

```yaml
vhost:
  - server_names: [www.example.com, example.com]
    root: /srv/www/example.com/public
    user: www-example
    group: www-data
    index: [index.html, index.htm]
    listing: false
    rate_limit: "20/s"
    rate_limit_burst: 40
```

Each vhost `index` may be a single filename or an ordered list. Charlotte serves
the first matching file found in the requested directory, then falls back to a
directory listing (if enabled).

Virtual hosts without `rate_limit` inherit the global CLI limit. Set
`rate_limit: off` to exempt a host, or give it a rate such as `20/s` to create
an independent per-host bucket; `rate_limit_burst` is optional and defaults to
the rate rounded up per second.

Worker-backed hosts require a document root and worker user. A host configured
with `proxy_pass` is served directly by the master and does not need `root` or
`user`. Worker-backed vhost configuration and document-root existence are
validated at startup, but the worker process is started only when that host
receives its first request. Workers are stopped after 300 seconds without
active requests by default; set `--worker-idle-timeout SECS` to change the
default, or use `worker_idle_timeout: SECS` on a vhost. Set either value to `0`
to keep workers alive indefinitely. If the master cannot inspect a root because
of filesystem permissions, it defers that access check to the worker user.

A proxy vhost can forward requests arriving over HTTP/1.1, HTTP/2, or HTTP/3 to
an HTTP or HTTPS upstream:

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
outside all served document roots. When started with `--user`, the server
creates the cache directory if needed and assigns it and its existing regular
files to that account before dropping privileges. See
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