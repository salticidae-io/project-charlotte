//! Gungraun benchmarks for date, routing, and static-file hot paths.

use std::{hint::black_box, sync::OnceLock};

use gungraun::prelude::*;

#[library_benchmark]
#[bench::imf_fixdate(args = ("Sun, 06 Nov 1994 08:49:37 GMT"))]
fn parse_http_date(value: &str) {
    black_box(project_charlotte::bench::parse_http_date(black_box(value)));
}

#[library_benchmark]
#[bench::fixed_timestamp(args = (1_500_000_000_i64))]
fn format_http_date(timestamp: i64) {
    let time = chrono::DateTime::<chrono::Utc>::from_timestamp(black_box(timestamp), 0)
        .expect("the benchmark timestamp is valid");
    black_box(project_charlotte::bench::format_http_date(time));
}

#[library_benchmark]
#[bench::wildcard_subdomain(args = ("*.example.com", "www.example.com"))]
fn match_wildcard_host(pattern: &str, host: &str) {
    black_box(project_charlotte::bench::match_host(
        black_box(pattern),
        black_box(host),
    ));
}

fn sni_entries() -> &'static [(String, usize)] {
    static ENTRIES: OnceLock<Vec<(String, usize)>> = OnceLock::new();
    ENTRIES.get_or_init(|| {
        vec![
            ("example.com".to_owned(), 0),
            ("*.example.com".to_owned(), 1),
            ("*.internal.example.com".to_owned(), 2),
        ]
    })
}

#[library_benchmark]
#[bench::wildcard_subdomain(args = ("www.example.com"))]
fn select_sni_entry(server_name: &str) {
    black_box(project_charlotte::bench::select_sni_entry(
        black_box(sni_entries()),
        None,
        Some(black_box(server_name)),
    ));
}

#[cfg(feature = "hosting")]
#[library_benchmark]
#[bench::encoded_static_path(args = ("/assets/site%20logo.svg"))]
fn decode_request_path(path: &str) {
    black_box(project_charlotte::bench::decode_request_path(black_box(
        path,
    )));
}

#[cfg(feature = "hosting")]
#[library_benchmark]
#[bench::bounded_range(args = ("bytes=4096-8191", 16_384_u64))]
fn parse_byte_range(value: &str, size: u64) {
    let _ = black_box(project_charlotte::bench::parse_byte_range(
        black_box(value),
        black_box(size),
    ));
}

#[cfg(feature = "hosting")]
#[library_benchmark]
#[bench::directory_listing_text(args = ("<img src=\"x\"> & details",))]
fn escape_html(value: &str) {
    let mut output = String::new();
    project_charlotte::bench::escape_html_into(&mut output, black_box(value));
    black_box(output);
}

#[cfg(feature = "hosting")]
#[library_benchmark]
#[bench::svg_file(args = ("assets/site.svg",))]
fn mime_lookup(path: &str) {
    black_box(project_charlotte::bench::mime_for_path(
        std::path::Path::new(black_box(path)),
    ));
}

#[cfg(feature = "hosting")]
library_benchmark_group!(
    name = hot_paths,
    benchmarks = [
        parse_http_date,
        format_http_date,
        match_wildcard_host,
        select_sni_entry,
        decode_request_path,
        parse_byte_range,
        escape_html,
        mime_lookup,
    ]
);

#[cfg(not(feature = "hosting"))]
library_benchmark_group!(
    name = hot_paths,
    benchmarks = [
        parse_http_date,
        format_http_date,
        match_wildcard_host,
        select_sni_entry,
    ]
);

main!(library_benchmark_groups = hot_paths);
