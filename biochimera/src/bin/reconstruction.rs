// reconstruction.rs
// -----------------------------------------------------------------------------
// Recon helper: inspect a target's DNS, proxy/CDN, and firewall/WAF surface.
//
// Given a host or URL it will:
//   * resolve DNS (A/AAAA via the system resolver) and report addresses
//   * fetch over HTTP(S) and flag proxy/CDN indicators (Via, X-Cache, CF-Ray,
//     Server, X-Served-By, Fastly/Cloudflare/Akamai headers, etc.)
//   * fingerprint common WAFs/firewalls from headers and blocking behaviour
//
// FOR AUTHORIZED SECURITY TESTING AND CTFs ONLY. Only run against systems you
// own or have explicit permission to test.
// -----------------------------------------------------------------------------

use clap::Parser;
use reqwest::blocking::Client;
use std::net::ToSocketAddrs;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "reconstruction",
    about = "Recon: check DNS, proxy/CDN and firewall/WAF for a target"
)]
struct Args {
    /// Target host or URL (e.g. example.com or https://example.com/path)
    target: String,

    /// Per-request timeout in seconds
    #[arg(short, long, default_value_t = 10)]
    timeout: u64,
}

fn host_and_url(target: &str) -> (String, String) {
    if target.starts_with("http://") || target.starts_with("https://") {
        let after = target.splitn(2, "://").nth(1).unwrap_or("");
        let host = after.split(['/', ':', '?']).next().unwrap_or("").to_string();
        (host, target.to_string())
    } else {
        let host = target
            .split(['/', ':', '?'])
            .next()
            .unwrap_or(target)
            .to_string();
        (host.clone(), format!("https://{host}"))
    }
}

fn dns_check(host: &str) {
    println!("=== DNS ===");
    match (host, 0u16).to_socket_addrs() {
        Ok(addrs) => {
            let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            if ips.is_empty() {
                println!("  No addresses resolved.");
            } else {
                for ip in ips {
                    println!("  {host} -> {ip}");
                }
            }
        }
        Err(e) => println!("  Resolution failed: {e}"),
    }
}

fn proxy_and_firewall_check(client: &Client, url: &str) {
    println!("\n=== HTTP / Proxy / Firewall ===");
    let resp = match client.get(url).send() {
        Ok(r) => r,
        Err(e) => {
            println!("  Request to {url} failed: {e}");
            return;
        }
    };

    let status = resp.status();
    println!("  Status: {status}");

    let headers = resp.headers().clone();
    let get = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };

    // Proxy / CDN indicators.
    let proxy_headers = [
        "via", "x-cache", "x-cache-hits", "x-served-by", "x-proxy-cache",
        "cf-ray", "cf-cache-status", "x-amz-cf-id", "x-fastly-request-id",
        "x-akamai-transformed", "x-varnish", "age", "x-cdn", "server",
    ];
    let mut proxy_hits = Vec::new();
    for h in proxy_headers {
        if let Some(v) = get(h) {
            proxy_hits.push(format!("    {h}: {v}"));
        }
    }
    println!("  Proxy / CDN headers:");
    if proxy_hits.is_empty() {
        println!("    (none observed)");
    } else {
        for line in &proxy_hits {
            println!("{line}");
        }
    }

    // CDN guess from Server / CF-Ray etc.
    let server = get("server").unwrap_or_default().to_lowercase();
    let mut cdn = Vec::new();
    if get("cf-ray").is_some() || server.contains("cloudflare") { cdn.push("Cloudflare"); }
    if server.contains("akamai") || get("x-akamai-transformed").is_some() { cdn.push("Akamai"); }
    if get("x-fastly-request-id").is_some() || server.contains("fastly") { cdn.push("Fastly"); }
    if get("x-amz-cf-id").is_some() || server.contains("cloudfront") { cdn.push("CloudFront"); }
    if get("x-varnish").is_some() { cdn.push("Varnish"); }
    if !cdn.is_empty() {
        println!("  Likely CDN/proxy: {}", cdn.join(", "));
    }

    // Firewall / WAF fingerprints from headers.
    let waf_signatures: [(&str, &str); 8] = [
        ("cf-ray", "Cloudflare"),
        ("x-sucuri-id", "Sucuri CloudProxy"),
        ("x-sucuri-cache", "Sucuri CloudProxy"),
        ("x-iinfo", "Imperva Incapsula"),
        ("x-cdn", "Incapsula/Generic"),
        ("x-akamai-transformed", "Akamai (Kona)"),
        ("x-amz-waf", "AWS WAF"),
        ("server", "see Server header"),
    ];
    let mut waf_hits = Vec::new();
    for (h, name) in waf_signatures {
        if let Some(v) = get(h) {
            if h == "server" {
                let sv = v.to_lowercase();
                for (needle, label) in [
                    ("cloudflare", "Cloudflare"),
                    ("awselb", "AWS ELB"),
                    ("mod_security", "ModSecurity"),
                    ("barracuda", "Barracuda"),
                    ("big-ip", "F5 BIG-IP"),
                ] {
                    if sv.contains(needle) {
                        waf_hits.push(label.to_string());
                    }
                }
            } else {
                waf_hits.push(format!("{name} (via {h})"));
            }
        }
    }
    println!("  Firewall / WAF indicators:");
    if waf_hits.is_empty() {
        println!("    (none observed from headers)");
    } else {
        waf_hits.sort();
        waf_hits.dedup();
        for w in &waf_hits {
            println!("    {w}");
        }
    }
    let s = status.as_u16();
    if s == 403 || s == 406 || s == 429 {
        println!("    Note: status {status} can indicate a WAF block page.");
    }
}

fn main() {
    let args = Args::parse();
    let (host, url) = host_and_url(&args.target);

    let client = Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .danger_accept_invalid_certs(true)
        .user_agent("reconstruction/0.1")
        .build()
        .expect("failed to build HTTP client");

    println!("[*] Target host: {host}");
    println!("[*] Probe URL:   {url}\n");

    dns_check(&host);
    proxy_and_firewall_check(&client, &url);
}
