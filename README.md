# SATAN-CYBR-HCK

## Threat Intelligence

- [Hijacked Networks & Cryptocurrency Heists](docs/hijacked-networks-crypto-heists.md) — how attackers compromise off-chain infrastructure (routing, DNS, telecom, and servers) to steal cryptocurrency.
- [The Modern Cybercrime Economy: Old Weaknesses, New Attack Surfaces](docs/cybercrime-economy-defense.md) — how attackers combine new attack surfaces with old, unpatched weaknesses, then monetize access through theft, fraud, and extortion.

## Tools

- [Visual Tools for Reverse Engineering: Deobfuscators](docs/reverse-engineering-deobfuscation-tools.md) — browser-based tools that use AST transformations to restore variable names and generate visual control flow graphs for analysis.
- **[biochimera](biochimera/src/main.rs)** — a 403-bypass tester (Rust). Takes a URL that returns 403 and retries it with alternate path mutations, spoofed headers, and HTTP methods, then reports any variant whose status differs from the 403 baseline.
- **[reconstruction](biochimera/src/bin/reconstruction.rs)** — a recon helper (Rust). Resolves a target's DNS and fingerprints proxy/CDN and firewall/WAF layers from HTTP headers and blocking behaviour.

> **Authorized testing only.** The Rust tools send live HTTP/DNS requests. Only run them against systems you own or have explicit written permission to test.

### Build & run

```bash
cd biochimera
cargo build --release

# 403-bypass tester
cargo run --release --bin biochimera -- https://target.example/admin

# Recon: DNS, proxy/CDN, firewall/WAF
cargo run --release --bin reconstruction -- https://target.example
```

Or use the interactive installer:

```bash
./install.sh
```
