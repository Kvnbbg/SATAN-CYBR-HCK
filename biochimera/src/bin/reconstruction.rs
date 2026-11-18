// reconstruction.rs — Red Team recon helper
// -----------------------------------------------------------------------------
// Inspect a target's DNS, proxy/CDN, firewall/WAF, exposed ports, and timing.
//
// Modules:
//   * DNS recon      — A/AAAA, MX, TXT, NS records + subdomain enumeration
//   * Proxy / WAF    — CDN and firewall fingerprinting from HTTP headers
//   * Origin-IP      — try to find the real server behind a CDN
//   * Port scan      — TCP connect scan of common service ports
//   * Timing probe   — response-time side channel over repeated requests
//   * WAF test       — benign probe payloads to measure WAF rule coverage (--waf-test)
//
// FOR AUTHORIZED SECURITY TESTING AND CTFs ONLY. Only run against systems you
// own or have explicit written permission to test.
// -----------------------------------------------------------------------------

use clap::Parser;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::Resolver;
use reqwest::blocking::Client;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(
    name = "reconstruction",
    about = "Red Team recon: DNS, proxy/WAF, origin-IP, ports, timing"
)]
struct Args {
    /// Target host or URL (e.g. example.com or https://example.com/path)
    target: String,

    /// Per-request timeout in seconds
    #[arg(short, long, default_value_t = 10)]
    timeout: u64,

    /// Skip the TCP port scan
    #[arg(long)]
    no_ports: bool,

    /// Skip subdomain enumeration
    #[arg(long)]
    no_subs: bool,

    /// Number of timing samples
    #[arg(long, default_value_t = 8)]
    timing_samples: u32,

    /// Run the WAF-coverage test (sends benign probe payloads and reports blocks)
    #[arg(long)]
    waf_test: bool,

    /// Query parameter name to inject WAF probes into
    #[arg(long, default_value = "q")]
    param: String,
}

fn host_and_url(target: &str) -> (String, String) {
    if target.starts_with("http://") || target.starts_with("https://") {
        let after = target.splitn(2, "://").nth(1).unwrap_or("");
        let host = after.split(['/', ':', '?']).next().unwrap_or("").to_string();
        (host, target.to_string())
    } else {
        let host = target.split(['/', ':', '?']).next().unwrap_or(target).to_string();
        (host.clone(), format!("https://{host}"))
    }
}

// ---------------------------------------------------------------------------
// DNS recon
// ---------------------------------------------------------------------------
fn dns_recon(resolver: &Resolver, host: &str) -> Vec<IpAddr> {
    println!("=== DNS ===");
    let mut ips = Vec::new();

    match resolver.lookup_ip(host) {
        Ok(r) => {
            for ip in r.iter() {
                println!("  A/AAAA  {host} -> {ip}");
                ips.push(ip);
            }
        }
        Err(e) => println!("  A/AAAA lookup failed: {e}"),
    }

    match resolver.mx_lookup(host) {
        Ok(r) => {
            for mx in r.iter() {
                println!("  MX      {} (pref {})", mx.exchange(), mx.preference());
            }
        }
        Err(_) => println!("  MX      (none)"),
    }

    match resolver.ns_lookup(host) {
        Ok(r) => {
            for ns in r.iter() {
                println!("  NS      {ns}");
            }
        }
        Err(_) => println!("  NS      (none)"),
    }

    match resolver.txt_lookup(host) {
        Ok(r) => {
            for txt in r.iter() {
                println!("  TXT     {txt}");
            }
        }
        Err(_) => println!("  TXT     (none)"),
    }

    ips
}

fn subdomain_enum(resolver: &Resolver, host: &str) {
    println!("\n=== Subdomain enumeration ===");
    let words = [
        "www", "mail", "ftp", "dev", "staging", "test", "api", "admin", "portal",
        "vpn", "ns1", "ns2", "smtp", "webmail", "autodiscover", "cpanel", "direct",
        "origin", "backend", "internal", "git", "gitlab", "jenkins", "db", "beta",
        "app", "cdn", "assets", "static", "img", "blog", "shop", "secure", "m",
    ];
    let mut found = 0;
    for w in words {
        let fqdn = format!("{w}.{host}");
        if let Ok(r) = resolver.lookup_ip(fqdn.as_str()) {
            let addrs: Vec<String> = r.iter().map(|a| a.to_string()).collect();
            if !addrs.is_empty() {
                println!("  {fqdn} -> {}", addrs.join(", "));
                found += 1;
            }
        }
    }
    if found == 0 {
        println!("  (no common subdomains resolved)");
    }
}

// ---------------------------------------------------------------------------
// Proxy / WAF fingerprinting
// ---------------------------------------------------------------------------
fn proxy_and_firewall(client: &Client, url: &str) -> bool {
    println!("\n=== HTTP / Proxy / Firewall ===");
    let resp = match client.get(url).send() {
        Ok(r) => r,
        Err(e) => {
            println!("  Request to {url} failed: {e}");
            return false;
        }
    };
    let status = resp.status();
    println!("  Status: {status}");
    let headers = resp.headers().clone();
    let get = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).map(String::from);

    let proxy_headers = [
        "via", "x-cache", "x-served-by", "cf-ray", "cf-cache-status", "x-amz-cf-id",
        "x-fastly-request-id", "x-akamai-transformed", "x-varnish", "age", "x-cdn", "server",
    ];
    let mut any = false;
    for h in proxy_headers {
        if let Some(v) = get(h) {
            println!("  {h}: {v}");
            any = true;
        }
    }
    if !any {
        println!("  (no proxy/CDN headers observed)");
    }

    let server = get("server").unwrap_or_default().to_lowercase();
    let mut behind_cdn = false;
    let mut cdn = Vec::new();
    if get("cf-ray").is_some() || server.contains("cloudflare") { cdn.push("Cloudflare"); behind_cdn = true; }
    if server.contains("akamai") || get("x-akamai-transformed").is_some() { cdn.push("Akamai"); behind_cdn = true; }
    if get("x-fastly-request-id").is_some() || server.contains("fastly") { cdn.push("Fastly"); behind_cdn = true; }
    if get("x-amz-cf-id").is_some() || server.contains("cloudfront") { cdn.push("CloudFront"); behind_cdn = true; }
    if get("x-sucuri-id").is_some() { cdn.push("Sucuri"); behind_cdn = true; }
    if get("x-iinfo").is_some() { cdn.push("Imperva Incapsula"); behind_cdn = true; }
    if !cdn.is_empty() {
        println!("  Likely CDN/WAF: {}", cdn.join(", "));
    }
    let s = status.as_u16();
    if s == 403 || s == 406 || s == 429 {
        println!("  Note: status {status} can indicate a WAF block page.");
    }
    behind_cdn
}

// ---------------------------------------------------------------------------
// Origin-IP discovery
// ---------------------------------------------------------------------------
fn origin_discovery(resolver: &Resolver, host: &str, fronted_ips: &[IpAddr]) {
    println!("\n=== Origin-IP discovery ===");
    println!("  Fronting IPs: {}",
        fronted_ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "));
    println!("  Checking records that often leak the real origin:");
    let candidates = ["direct", "origin", "www", "mail", "ftp", "cpanel", "webmail", "dev", "staging"];
    let fronted: std::collections::HashSet<String> =
        fronted_ips.iter().map(|i| i.to_string()).collect();
    let mut leaked = false;
    for c in candidates {
        let fqdn = format!("{c}.{host}");
        if let Ok(r) = resolver.lookup_ip(fqdn.as_str()) {
            for ip in r.iter() {
                let s = ip.to_string();
                if !fronted.contains(&s) {
                    println!("  [!] {fqdn} -> {s}  (differs from fronting IP — possible origin)");
                    leaked = true;
                }
            }
        }
    }
    // MX hosts often point at the real infrastructure, not the CDN.
    if let Ok(mx) = resolver.mx_lookup(host) {
        for rec in mx.iter() {
            let exch = rec.exchange().to_string();
            if let Ok(r) = resolver.lookup_ip(exch.as_str()) {
                for ip in r.iter() {
                    let s = ip.to_string();
                    if !fronted.contains(&s) {
                        println!("  [!] MX {exch} -> {s}  (mail host IP, often the real network)");
                        leaked = true;
                    }
                }
            }
        }
    }
    if !leaked {
        println!("  No obvious origin leak from common records.");
    }
}

// ---------------------------------------------------------------------------
// Port scan
// ---------------------------------------------------------------------------
fn port_scan(ip: IpAddr, timeout: Duration) {
    println!("\n=== Port scan ({ip}) ===");
    let ports: [(u16, &str); 20] = [
        (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"), (53, "dns"),
        (80, "http"), (110, "pop3"), (143, "imap"), (443, "https"), (445, "smb"),
        (993, "imaps"), (995, "pop3s"), (3306, "mysql"), (3389, "rdp"),
        (5432, "postgres"), (6379, "redis"), (8080, "http-alt"), (8443, "https-alt"),
        (9200, "elastic"), (27017, "mongodb"),
    ];
    let mut open = 0;
    for (p, name) in ports {
        let addr = SocketAddr::new(ip, p);
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            println!("  {p:>5}/tcp  open   {name}");
            open += 1;
        }
    }
    if open == 0 {
        println!("  No common ports open (or filtered).");
    }
}

// ---------------------------------------------------------------------------
// Timing side-channel probe
// ---------------------------------------------------------------------------
fn timing_probe(client: &Client, url: &str, samples: u32) {
    println!("\n=== Timing side-channel ({samples} samples) ===");
    let mut times = Vec::new();
    for _ in 0..samples {
        let start = Instant::now();
        let ok = client.get(url).send().is_ok();
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        if ok {
            times.push(elapsed);
        }
    }
    if times.is_empty() {
        println!("  No successful requests to measure.");
        return;
    }
    let n = times.len() as f64;
    let min = times.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = times.iter().cloned().fold(0.0_f64, f64::max);
    let mean = times.iter().sum::<f64>() / n;
    let var = times.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / n;
    let stddev = var.sqrt();
    println!("  samples: {}  min: {min:.1}ms  mean: {mean:.1}ms  max: {max:.1}ms  stddev: {stddev:.1}ms", times.len());
    if stddev > mean * 0.25 {
        println!("  High variance — response time may depend on input (possible side channel).");
    } else {
        println!("  Response times are stable.");
    }
}

// ---------------------------------------------------------------------------
// WAF coverage test
// ---------------------------------------------------------------------------
// Sends a set of suspicious-looking probe strings as a query parameter and
// reports which the WAF blocks (403/406/429/5xx or a block page) versus which
// pass through. These are detection probes, not exploits: they are meant to be
// rejected by a correctly configured WAF, so you can measure rule coverage.
fn waf_test(client: &Client, base_url: &str, param: &str) {
    println!("\n=== WAF coverage test (param: {param}) ===");

    // Baseline with a harmless value.
    let benign = format!("{base_url}{}{param}=hello", sep(base_url));
    let (base_status, base_len) = match client.get(&benign).send() {
        Ok(r) => {
            let st = r.status().as_u16();
            let len = r.bytes().map(|b| b.len() as u64).unwrap_or(0);
            println!("  Baseline (benign): status {st}, {len} bytes");
            (st, len)
        }
        Err(e) => {
            println!("  Baseline request failed: {e}");
            return;
        }
    };

    let probes: [(&str, &str); 10] = [
        ("SQLi",            "' OR '1'='1"),
        ("SQLi-union",      "1 UNION SELECT NULL--"),
        ("XSS",             "<script>alert(1)</script>"),
        ("XSS-img",         "<img src=x onerror=alert(1)>"),
        ("Path traversal",  "../../../../etc/passwd"),
        ("Path traversal2", "..%2f..%2f..%2fetc%2fpasswd"),
        ("Cmd injection",   "; cat /etc/passwd"),
        ("Cmd injection2",  "| whoami"),
        ("SSTI",            "{{7*7}}"),
        ("Log4Shell",       "${jndi:ldap://x/y}"),
    ];

    let mut blocked = 0;
    let mut passed = 0;
    for (name, payload) in probes {
        let enc = urlencode(payload);
        let url = format!("{base_url}{}{param}={enc}", sep(base_url));
        match client.get(&url).send() {
            Ok(r) => {
                let st = r.status().as_u16();
                let len = r.bytes().map(|b| b.len() as u64).unwrap_or(0);
                let is_block = matches!(st, 403 | 406 | 429 | 501) || (st >= 500)
                    || (st != base_status);
                if is_block {
                    println!("  [BLOCKED] {name:<16} status {st} ({len} bytes)");
                    blocked += 1;
                } else {
                    println!("  [PASSED ] {name:<16} status {st} ({len} bytes) — payload reached the app");
                    passed += 1;
                }
                let _ = base_len;
            }
            Err(e) => println!("  [ERROR  ] {name:<16} {e}"),
        }
    }
    println!("  ---");
    println!("  {blocked} blocked, {passed} passed of {} probes.", blocked + passed);
    if passed > 0 {
        println!("  Note: 'passed' probes were not blocked by the WAF. On an authorized");
        println!("  target, review whether those inputs are safely handled by the app.");
    }
}

fn sep(url: &str) -> char {
    if url.contains('?') { '&' } else { '?' }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn main() {
    let args = Args::parse();
    let (host, url) = host_and_url(&args.target);

    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())
        .expect("failed to build DNS resolver");

    let client = Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .danger_accept_invalid_certs(true)
        .user_agent("reconstruction/0.3")
        .build()
        .expect("failed to build HTTP client");

    println!("[*] Target host: {host}");
    println!("[*] Probe URL:   {url}\n");

    let ips = dns_recon(&resolver, &host);
    if !args.no_subs {
        subdomain_enum(&resolver, &host);
    }
    let behind_cdn = proxy_and_firewall(&client, &url);
    if behind_cdn {
        origin_discovery(&resolver, &host, &ips);
    }
    if !args.no_ports {
        // Prefer an origin-ish IP if DNS gave one, else the first resolved IP.
        let scan_ip = ips.first().copied().or_else(|| {
            (host.as_str(), 0u16).to_socket_addrs().ok().and_then(|mut a| a.next().map(|s| s.ip()))
        });
        match scan_ip {
            Some(ip) => port_scan(ip, Duration::from_secs(2)),
            None => println!("\n=== Port scan ===\n  No IP to scan."),
        }
    }
    if args.waf_test {
        waf_test(&client, &url, &args.param);
    }
    timing_probe(&client, &url, args.timing_samples);
}
