# Fuzzing

This project uses `test-fuzz` with AFL to fuzz parsed application inputs and
request-handling paths. Raw HTTP/1, HTTP/2, and HTTP/3 wire parsing is handled
by Hyper and `h3`; fuzz targets begin after those libraries have produced an
HTTP request.

## Install

Install the Cargo subcommand and AFL integration:

```sh
cargo install cargo-test-fuzz cargo-afl
```

If `afl-fuzz` cannot load `libpython*.so`, add the matching Python library
directory to `LD_LIBRARY_PATH` for the fuzz command. If AFL reports that the
system-wide core-pattern configuration prevents fuzzing, configure the host
with `cargo afl system-config`; that command uses `sudo`. For a short smoke
run only, AFL's `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` override avoids
changing that system setting, but is not recommended for persistent fuzzing.

## Running

`scripts/fuzz.sh` fuzzes every target in turn and keeps what the run learned:

```sh
scripts/fuzz.sh              # 300 seconds per target
scripts/fuzz.sh 3600         # one hour per target
scripts/fuzz.sh 60 waf::     # only targets whose name contains "waf::"
```

For each target it records the seeds, adds the saved corpus, fuzzes for the
given time, and then:

- copies the inputs that reached new coverage to `fuzz/corpus/<target>/`.
  The stored target name uses dots instead of Rust's `::` separators so the
  corpus can be uploaded as a GitHub Actions artifact; the script restores the
  original name under `target/corpus/` before running `test-fuzz`. Commit these
  inputs: they are the starting point of the next run, so coverage accumulates
  instead of being rediscovered, and they survive `cargo clean`.
- copies crashes and hangs to `fuzz/findings/<target>/` and exits non-zero.
  Replay a finding with `cargo test-fuzz --exact <target> --replay crashes`,
  turn it into an ordinary regression test, and delete it once fixed.

When a target's parameters change, its saved inputs no longer deserialize;
delete its dotted directory under `fuzz/corpus/` and let the next run rebuild
it.

To fuzz a single target by hand:

```sh
cargo test-fuzz --exact handler::tests::static_request --max-total-time 30
```

### Scheduling

Fuzzing only pays off when it runs regularly and for longer than a smoke
test. On a machine set up as above, a nightly cron entry is enough:

```cron
0 2 * * *  cd /path/to/project-charlotte && scripts/fuzz.sh 1200 >>fuzz/last-run.log 2>&1
```

A non-zero exit status means there is something under `fuzz/findings/`.
Commit the grown `fuzz/corpus/` periodically.

GitHub Actions runs the full test suite and a short fuzz pass on pushes to
`main` and pull requests. A nightly run fuzzes each target for five minutes;
manual runs can set the per-target duration. Fuzz logs, findings, and the
updated corpus are uploaded as workflow artifacts, and any crash or hang fails
the fuzz job.

## Seed corpus and fixture

The `fuzz_seed_*` unit tests call each target with representative inputs;
running the unit tests records those calls as the seed corpus under
`target/corpus/` and verifies that every seed passes:

```sh
cargo test --lib
cargo test-fuzz --list
```

Request-handling targets share an on-disk document root built by
`fuzz_support::fixture()`. It is created once per user under the system
temporary directory and reused by every test and fuzz process. A fuzzer can
only vary request bytes, so the fixture has to supply everything else a code
path depends on: directories with and without an index, file names that need
escaping in listings, a FastCGI directory index, symbolic links that leave
the root, and a file larger than the WAF response-inspection limit. When a
new feature depends on what is on disk, add it to the fixture (and bump
`FIXTURE_VERSION`), or the fuzzer cannot reach it.

## Targets

Targets that only call a function can find nothing but panics. Wherever
possible a target also asserts a property that must hold for every input;
those properties are listed here.

Request handling:

- `handler::tests::static_request` — the full static handler. Nothing outside
  the document root is disclosed, `Content-Length` matches the body, and
  `Content-Range` is in bounds and matches the body.
- `handler::tests::try_files_request` — the same with a fuzzed `try_files`
  list. Every list that configuration validation accepts must expand for
  every request.
- `vhost::tests::router_request` — dispatch through a router with no virtual
  hosts, with the static handler's properties.
- `vhost::tests::worker_roundtrip` — virtual-host selection, the TLS server
  name check, and the master-to-worker request rewrite, undone by the
  worker's own parser. The worker must recover the client addresses, the
  protocol version, and exactly the path and query the master (and so the
  WAF) saw. The HTTP/2 hop between the two processes is not included.
- `waf::tests::waf_request` — ModSecurity inspection through router dispatch.
  A request carrying `block=yes` is always refused, and the marker that the
  response rule blocks never appears in a response body.
- `fastcgi::tests::fastcgi_request` — script resolution, CGI parameters, and
  the FastCGI client against a well-behaved in-memory responder. Scripts stay
  inside the root, `HTTP_PROXY` is never set, and connection-level headers
  are not forwarded from the backend.
- `fastcgi::tests::fastcgi_backend_stream` — the FastCGI client against an
  arbitrary byte stream: malformed, truncated, and unexpected records. The
  client must finish once the backend closes the connection.
- `worker::tests::worker_metadata` — the worker's parsing of private metadata
  headers; they are always removed from the request.

Parsers and helpers:

- `handler::tests::request_path`, `byte_range`, `if_range`, `html_escape` —
  decoded paths contain only normal components, ranges are in bounds, a
  non-tag `If-Range` matches only as a date, and escaped text has no markup.
- `fastcgi::tests::cgi_headers` — CGI response headers. The status is valid
  and connection-level, `Server`, and `Date` headers are dropped.
- `httpdate::tests::http_date` — every parsed date survives formatting and
  reparsing.
- `vhost::tests::host_selection` — a wildcard matches subdomains only, never
  the apex or a different domain with the same ending.
- `tls::tests::sni_selection` — certificate selection returns the
  best-matching entry and uses the fallback only when nothing matches.
- `vhost::tests::worker_args` — a vhost configuration rendered as worker
  command-line arguments parses back to the same configuration.
- `waf::tests::rule_id_spec` — accepted rule exclusions render as plain IDs
  and ranges, and survive reparsing.
- `acme::tests::dns_name`, `challenge_path` — eligible names map to files
  directly inside the cache directory; challenge tokens use only the
  base64url alphabet.
- `config::tests::cli_args`, `fastcgi_backend`, `vhost::tests::vhost_yaml`,
  `mime::tests::mime_for_path` — panic-only.

Not fuzzed: certificate and key file loading (`rustls-pemfile`,
`x509-parser`), ACME provisioning, the QUIC/HTTP/3 and listener glue, and
process supervision.

AFL reports stability below 100% for the targets that run the request
handler, which makes their coverage feedback noisier. The cause has not been
traced; thread scheduling in Tokio's blocking pool, which serves file access,
is the likely source.
