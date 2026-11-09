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

## Seed corpus and target discovery

The seed tests call each annotated target with representative inputs. Run the
unit tests to record those calls and verify the seeds:

```sh
cargo test --bin project-charlotte
cargo test-fuzz --list
```

Each target has a corresponding corpus managed by `cargo test-fuzz`; do not
edit generated corpus files under `target/` by hand.

## Targets

- `config::tests::cli_args` and `config::tests::fastcgi_backend` — CLI parsing
  and FastCGI mapping validation.
- `httpdate::tests::http_date` and `mime::tests::mime_for_path` — HTTP date
  parsing/formatting and MIME extension lookup.
- `handler::tests::request_path`, `byte_range`, `if_range`, `html_escape`, and
  `static_request` — URL path safety, range and conditional handling, escaping,
  and the full static request handler.
- `fastcgi::tests::cgi_headers` and `fastcgi::tests::fastcgi_request` — CGI
  response parsing, script resolution, CGI parameters, and the FastCGI client
  against an in-memory responder.
- `vhost::tests::host_selection`, `vhost_toml`, and `router_request` — host
  normalization/matching, TOML validation, and fallback routing.
- `worker::tests::worker_metadata` — private worker metadata and URI restoration.
- `waf::tests::waf_request` — ModSecurity inspection through router dispatch.

Run one target for a bounded duration (replace the target name as needed):

```sh
cargo test-fuzz handler::tests::static_request --max-total-time 30
```

When using the smoke-run override described above, prefix that command with
`AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`.

Fuzz the other targets the same way. To inspect or replay findings, use the
`cargo test-fuzz` `--display` and `--replay` options; keep any discovered
regression cases as ordinary tests.