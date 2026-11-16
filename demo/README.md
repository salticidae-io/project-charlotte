# Browser-driven live demo

`demo/run.sh` builds Charlotte (unless `CHARLOTTE_BIN_DIR` points to existing
binaries), starts loopback-only demo services, launches Chromium, and drives a
checked sequence of feature scenes through the DevTools Protocol. The samples
and generated requests stay on `*.charlotte.test` and `127.0.0.1`; the abusive
traffic scenes are deliberately small and target only this local Charlotte
instance.

## Requirements

- Bash, Node.js 20+, OpenSSL, and Chromium/Chrome.
- A working Rust toolchain and the system development libraries required by
  `libmodsecurity3-rs` when building locally.
- Optional: `php-cgi` for the FastCGI PHP scene, and the `pebble` executable
  for real local HTTP-01 issuance. Missing optional tools produce visible
  skipped scenes.

Run `demo/run.sh` for presenter-paced playback. Advance with Enter in the
terminal or Space/Right Arrow in Chromium. Use `--auto` for unattended playback,
`--headless` for automated validation, `--only <scene-id>` to focus on one
scene, and `--speed <multiplier>` to change automatic pacing.

`CHARLOTTE_DEMO_STATE` selects the output directory; by default it is
`target/demo/` on the host and `/tmp/charlotte-demo` when running in `/workspace`.
Each invocation creates an isolated run directory containing generated
configuration, certificates, logs, and scene artifacts. Set
`CHARLOTTE_BIN_DIR` to use prebuilt `project-charlotte`, `charlotte-ctl`,
`apache2charlotte`, and `nginx2charlotte` binaries instead of invoking Cargo.
The harness uses the first browser that reports itself as Chromium or Chrome,
preferring real binaries such as `/usr/lib/chromium/chromium` over launcher
scripts on `PATH`; set `CHROMIUM_BIN` to choose one explicitly. The selected
browser is printed at startup.
Install the official Ubuntu `pebble` package, or set `PEBBLE_BIN` to a Pebble
executable. The harness generates Pebble's listener certificate, config, and
local CA at startup, so no Pebble source checkout or test assets are needed.
It fetches the fresh ACME issuing certificates from Pebble's management port
and trusts them only in the demo Chromium profile. The `/demo` VM image
installs Pebble from its OS package repository.

## Scenes

The browser overlay and terminal first describe each outgoing request, then
show the server status, selected response headers, and a short body excerpt;
the CGI, PHP FastCGI, static, and reverse-proxy pages also expose details of
the request or worker that produced them.

The guided presentation verifies static hosting and HTTP semantics, CGI and
supervised PHP FastCGI, reverse proxying, request/response WAF rules, rate
limiting, bot challenge/block/honeypot behavior, TLS/SNI, ACME HTTP-01 with
Pebble, HTTP/3 negotiation or `Alt-Svc`, access logging, control-socket CRUD,
vhost hot reload, and Apache/nginx configuration conversion.