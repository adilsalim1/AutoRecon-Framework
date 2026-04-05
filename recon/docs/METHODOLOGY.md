# Recon methodology alignment

This document maps common **bug-bounty recon playbooks** to **AutoRecon**: what the pipeline runs today, what `python recon/main.py --install-tools` can place on disk, and what stays **manual or out-of-band** (OSINT, commercial tools, or future plugins).

**Primary references (external):**

- [R-s0n — *My Full Bug Bounty Hunting Methodology - Recon* (DEF CON 32 Bug Bounty Village workshop)](https://github.com/R-s0n/bug-bounty-village-defcon32-workshop/blob/main/recon-methodology.md) — source: [`recon-methodology.md` on GitHub](https://raw.githubusercontent.com/R-s0n/bug-bounty-village-defcon32-workshop/main/recon-methodology.md)
- [Infosec Writeups — *Recon to Master: The Complete Bug Bounty Checklist*](https://infosecwriteups.com/recon-to-master-the-complete-bug-bounty-checklist-95b80ea55ff0)
- **Jason Haddix — *The Bug Hunter’s Methodology* (TBHM):** crosswalk in [`TBHM.md`](TBHM.md) (repo: [jhaddix/tbhm](https://github.com/jhaddix/tbhm))

The **workshop doc** is organized as a linear recon workflow (apex → subdomains → resolution/ports → live URLs → target selection → enumeration → post-recon automation). The **Infosec Writeups** piece is checklist-oriented; its themes map to **sections 2–6** below (breadth-first discovery, alive filtering, scanning, crawling/fuzzing, parameter and client-side follow-up). Anything that is **pure OSINT**, **paid SaaS**, or **closed-source lab tooling** stays **Manual** here.

**Legend**

| Symbol | Meaning |
|--------|---------|
| **Pipeline** | Invoked automatically when you enable the matching discovery provider or scanner plugin |
| **Bootstrap** | Install recipe in `recon/bootstrap/definitions.py`; included in `--install-tools` |
| **Manual** | You run separately or extend the framework with a new provider/scanner |
| **OSINT** | Human-driven or third-party web services; not wrapped as CLI plugins |

---

## 1. Apex domains & organization intelligence

| Technique / idea | Examples from methodology | AutoRecon |
|------------------|---------------------------|-----------|
| Company → seed domains | Shodan, DNS Dumpster, Reverse WhoIS, ASN lookup, Crunchbase, news/M&A | **Manual / OSINT** — feed resulting apex as `--domain` or config `domain` |
| Amass intel | Amass intel mode | **Manual** — this repo uses **Amass passive enum** as a discovery provider, not the full intel workflow |
| Google dorking | `site:`, `intitle:`, etc. | **Manual / OSINT** |
| Cloud IP ranges + cert scraping | [Clear-Sky](https://github.com/R-s0n/Clear-Sky)-style automation | **Manual** — export hosts and merge with pipeline output (no built-in cloud-range scanner) |
| LinkedIn + GitHub employee recon | Personal repos, leaked hostnames | **Manual / OSINT** |
| Trackers / favicon correlation | HackTricks-style external recon | **Manual / OSINT** |

---

## 2. Subdomains & host discovery

| Tool / source | Typical role | AutoRecon |
|---------------|--------------|-----------|
| **Certificate Transparency** | Broad subdomain hints from certs | **Pipeline** — provider `crtsh` / `crt.sh` / `crt_sh` |
| **Subfinder** | Fast passive enumeration | **Pipeline** + **Bootstrap** — `subfinder` |
| **Amass** (passive) | Heavy passive enum | **Pipeline** + **Bootstrap** — `amass` / `amass_passive` |
| **Assetfinder** | Related hosts | **Pipeline** + **Bootstrap** — `assetfinder` |
| **waybackurls** | Historical URLs → hostnames | **Pipeline** + **Bootstrap** — `waybackurls` |
| **github-subdomains** ([gwen001](https://github.com/gwen001/github-subdomains)) | Subdomains from GitHub code search | **Pipeline** + **Bootstrap** — provider `github_subdomains` / `github-subdomains`; needs **`GITHUB_TOKEN`** or `.tokens` in cwd |
| **Sublist3r** | Multi-source enum | **Bootstrap** only (`sublist3r` key) — run manually; no built-in provider yet |
| **ShuffleDNS** | DNS brute with wordlist | **Pipeline** + **Bootstrap** — needs `discovery.wordlist` + `discovery.resolvers` |
| **CeWL** | Wordlist from page content → feed ShuffleDNS | **Bootstrap** (Debian `cewl` package) — **Manual** chaining |
| **GAU** (GetAllUrls) | URL history like GAU | **Bootstrap** only (`gau`) — **Manual** or future provider |
| **massdns** | High-speed DNS | **Pipeline stub** — `massdns` provider exists but is not fully automated |

---

## 3. Resolution, ports, and “live” HTTP(S)

| Tool / step | Role | AutoRecon |
|-------------|------|-----------|
| Resolve FQDNs → IPs | Triage, ASN/CIDR validation | **Manual** — framework stores hostnames; validate ownership in your program rules |
| Port scanning | naabu, masscan, nmap, DNMasscan-style | **Bootstrap**: `nmap` (apt on Debian family). **Manual** for advanced port workflows |
| **httprobe** | Probe http/https | **Bootstrap** only (`httprobe`) — **Manual**; default live probe is **ProjectDiscovery httpx** |
| **httpx** (ProjectDiscovery) | Live web, tech, JSON | **Pipeline** — `httpx_scanner` (**Bootstrap**) |

---

## 4. Wide-band scanning & fingerprinting

| Tool | Role | AutoRecon |
|------|------|-----------|
| **Nuclei** | Template scanning, CVE/wide checks | **Pipeline** — `nuclei_scanner` + **Bootstrap** |
| **wafw00f** | WAF detection | **Pipeline** — `wafw00f_scanner` + **Bootstrap** |
| **Semgrep** | SAST on JS you can obtain | **Bootstrap** (`semgrep`) — **Manual** on artifacts you collect |
| **Retire.js** / npm audit style | Client dependency risk | **Manual** |
| **Wappalyzer / WhatWeb** (free CLIs) | Tech stack hints | **Manual** or pipeline `whatweb_scanner` / `wappalyzer_scanner` — httpx/Nuclei can partially overlap |

---

## 5. Link discovery, crawling, and content

| Tool | Role | AutoRecon |
|------|------|-----------|
| **Katana** | Crawl + JS-aware endpoints | **Bootstrap** only (`katana`) — **Manual** or future module |
| **GoSpider** | Spider | **Bootstrap** only (`gospider`) — **Manual** |
| **Subdomainizer** | JS/third-party subdomain leaks | **Manual** — install from [nsonaniya2010/SubDomainizer](https://github.com/nsonaniya2010/SubDomainizer) (no stable PyPI recipe in bootstrap) |
| **Burp**, **Caido** | Proxy / crawl / audit | **Manual** — commercial or separate install |
| **FFUF** | Directory/endpoint fuzz | **Pipeline** — `ffuf_scanner` when `scanning.ffuf_wordlist` is set + **Bootstrap** |

---

## 6. Parameters, verbs, headers, secrets

| Tool | Role | AutoRecon |
|------|------|-----------|
| **Arjun** | Hidden parameters | **Bootstrap** only (`arjun`) — **Manual** |
| **dnsx** | DNS operations / resolution at scale | **Bootstrap** only (`dnsx`) — **Manual** |
| **Param Miner**, **Burp Intruder** | Header/cookie/param fuzz | **Manual** |
| **SecretFinder** | Secrets in JS | **Pipeline** — `secretfinder_scanner` if `scanning.secretfinder_script` points to the script (**Manual** script path) |

---

## 7. Takeover checks & automation adjacent

| Tool | Role | AutoRecon |
|------|------|-----------|
| **subjack** | Takeover fingerprints | **Pipeline** — `subjack_scanner` + **Bootstrap** |
| **subzy** | Takeover checks | **Pipeline** — `subzy_scanner` + **Bootstrap** |

---

## 8. Post-recon: secrets, GitHub, CVE spraying

| Topic | Notes | AutoRecon |
|-------|-------|-----------|
| In-app leaked secrets | DOM, webpack, storage | **Manual** testing; **SecretFinder** plugin if configured |
| Pastebin / StackOverflow / GitHub dorking | OSINT | **Manual** |
| CVE spraying / custom Nuclei templates | Wide or targeted | **Pipeline** via **Nuclei**; add `-t` / tags in a **fork of tool args** or future config knob |

---

## Suggested config for “max built-in coverage”

Enable every **implemented** discovery source and common scanners (adjust wordlists, rates, and scope to your **authorized** target):

```yaml
discovery:
  providers:
    - crtsh
    - subfinder
    - amass_passive
    - assetfinder
    - waybackurls
    # - shuffledns   # set discovery.wordlist + discovery.resolvers first

scanning:
  plugins:
    - httpx_scanner
    - wafw00f_scanner
    - nuclei_scanner
    - subjack_scanner
    - subzy_scanner
    # - ffuf_scanner        # set scanning.ffuf_wordlist
    # - secretfinder_scanner # set scanning.secretfinder_script
```

Run `PYTHONPATH=. python recon/main.py --install-tools` once on a dev box to pull **Bootstrap** tools from `recon/bootstrap/definitions.py`, then add the ones you use to `tools:` with absolute paths if needed.

---

## Ebb & flow (from the workshop doc)

The workshop emphasizes alternating **deep recon** with **short manual testing loops** (a few attack vectors at a time), then returning to recon. AutoRecon is the **automation spine** for discovery + first-pass scanning; the methodology’s injection/logic testing phases remain **manual** unless you add custom plugins.
