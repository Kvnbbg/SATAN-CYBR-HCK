# SATAN-CYBR-HCK

## Threat Intelligence

- [Hijacked Networks & Cryptocurrency Heists](docs/hijacked-networks-crypto-heists.md) — how attackers compromise off-chain infrastructure (routing, DNS, telecom, and servers) to steal cryptocurrency.
- [The Modern Cybercrime Economy: Old Weaknesses, New Attack Surfaces](docs/cybercrime-economy-defense.md) — how attackers combine new attack surfaces with old, unpatched weaknesses, then monetize access through theft, fraud, and extortion.

## Tools

- [Visual Tools for Reverse Engineering: Deobfuscators](docs/reverse-engineering-deobfuscation-tools.md) — browser-based tools that use AST transformations to restore variable names and generate visual control flow graphs for analysis.
- **[biochimera](biochimera/src/main.rs)** — a 403-bypass tester (Rust). Takes a URL that returns 403 and retries it with alternate path mutations, spoofed headers, and HTTP methods, then reports any variant whose status differs from the 403 baseline.
- **[reconstruction](biochimera/src/bin/reconstruction.rs)** — a Red Team recon helper (Rust). Runs five modules against a target:
  - **DNS recon** — A/AAAA, MX, TXT, NS records plus subdomain enumeration.
  - **Proxy / WAF** — CDN and firewall fingerprinting from HTTP headers.
  - **Origin-IP discovery** — tries to find the real server behind a CDN (via leak-prone subdomains and MX hosts).
  - **Port scan** — TCP connect scan of ~20 common service ports.
  - **Timing side-channel** — measures response-time mean/stddev to flag input-dependent timing.

> **Authorized testing only.** These tools send live DNS, TCP, and HTTP requests. Only run them against systems you own or have explicit written permission to test.

### Build & run

```bash
cd biochimera
cargo build --release

# 403-bypass tester
cargo run --release --bin biochimera -- https://target.example/admin

# Red Team recon (DNS, proxy/WAF, origin-IP, ports, timing)
cargo run --release --bin reconstruction -- https://target.example
# useful flags: --no-ports  --no-subs  --timing-samples <n>
```

Or use the interactive installer:

```bash
./install.sh
```
