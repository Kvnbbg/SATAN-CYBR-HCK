# Hijacked Networks & Cryptocurrency Heists

The intersection of **hijacked networks** and **cryptocurrency heists** describes a shift in how digital assets are stolen. Rather than solely attacking smart contracts, sophisticated actors increasingly compromise the **off-chain infrastructure**—the routing, domain, and server layers that the crypto ecosystem relies on—to execute large-scale thefts.

### 🦚 Hijacked Networks: Attacking the Off-Chain Layer

Attackers are targeting the foundational internet protocols that direct traffic and authenticate users, turning trusted infrastructure into a weapon.

**BGP Hijacking (Route Hijacking)**
The Border Gateway Protocol (BGP) is the internet’s routing system, but it lacks native authentication. Attackers can announce false routes to redirect traffic to servers they control. This was used against the DeFi platform **Balancer** in September 2025, where a BGP hijack redirected users to a phishing site, leading to the theft of approximately **$238,000**. The MyEtherWallet attack is a historic example, where **$150,000** was stolen in just two hours via a combined DNS/BGP attack.

**DNS Hijacking (Domain Hijacking)**
By compromising a domain’s registrar or DNS records, attackers can redirect a legitimate crypto website to a malicious clone. In November 2025, **Aerodrome Finance**, the largest DEX on Coinbase’s Base network, suffered such an attack. Users were redirected to a phishing site and prompted to sign malicious transactions, resulting in over **$1 million** in losses within hours.

**SIM-Swapping & Telecom Compromise**
Attackers hijack phone numbers by compromising telecom systems or bribing insiders. This allows them to bypass SMS-based two-factor authentication (2FA) on exchange accounts. In June 2026, Polish authorities arrested a group accused of stealing at least **$5 million** through such attacks, which involved hacking telecom-linked systems to take over victims' exchange accounts.

**Cloud & Server Infrastructure Compromise**
Attackers are also penetrating the cloud environments that host crypto services. A notable campaign linked to North Korea (tracked as **UNC4899** or **TraderTraitor**) involved a developer being tricked into installing malware via a trojanized file. The attackers then pivoted into the organization's cloud infrastructure, abusing legitimate DevOps workflows to manipulate databases and steal millions in cryptocurrency.

### 💰 Cryptocurrency Heists: The Scale of the Theft

The statistics on crypto theft are staggering, with a clear trend toward fewer but far more lucrative attacks.

- **Global Losses:** In the first ten months of 2026 alone, approximately **$8.7 billion** in cryptocurrency was stolen globally, more than triple the **$2.87 billion** lost in the entire previous year.
- **North Korea's Dominance:** State-sponsored North Korean hacking groups, primarily the **Lazarus Group**, are the single largest threat. They stole over **$2 billion** in 2025 (a 51% increase year-over-year) and were responsible for an estimated **76%** of global crypto hack losses in the first four months of 2026. Their cumulative known thefts since 2017 are estimated at **$6.75 billion**.

**Major Heists and Evolving Tactics**

- **The Bybit Hack (February 2025):** This remains the largest single crypto theft to date. North Korean actors stole roughly **$1.5 billion** in Ethereum from the exchange. Bybit later sued North Korea and the Lazarus Group over the breach.
- **The KelpDAO / LayerZero Bridge Exploit (April 2026):** This $292 million theft is a prime example of combining network and crypto attacks. The Lazarus Group spent six weeks inside LayerZero's infrastructure. They **compromised internal RPC servers** and then launched a **DDoS attack** against external nodes. This forced the bridge's verifier to rely solely on the poisoned internal nodes, which fed it false data to approve a fraudulent transfer of **$292 million** in rsETH.
- **The Binance Heist (October 2026):** In what is described as the largest security incident in crypto history, attackers drained approximately **$5.875 billion** in various assets from Binance. The FBI attributed the attack to the North Korean group **TraderTraitor**.

The common thread across these incidents is the exploitation of **trust and centralization points**—whether in internet routing, domain registration, telecom systems, or the verifier configurations of cross-chain bridges.
