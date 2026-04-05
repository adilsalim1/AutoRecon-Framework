# The Bug Hunter’s Methodology (TBHM) ↔ AutoRecon

**Attribution:** *The Bug Hunter’s Methodology* is by **Jason Haddix** ([@jhaddix](https://twitter.com/jhaddix)). Canonical text and evolving notes live in **[jhaddix/tbhm](https://github.com/jhaddix/tbhm)** (Discovery, Mapping, Authorization, tactical fuzzing topics, etc.).

**About your PDF:** *The Bug Hunter’s Methodology – Full Info Live* (Canva “TBHM Live 1 Pager”, author metadata: Jason Haddix) is a **visual** one-pager. Exported PDFs are often **image-only**, so automated text extraction may be empty. This file translates TBHM’s **documented** structure and recon themes into what AutoRecon automates vs what you still do manually—aligned with **[TBHM `02_Discovery.md`](https://github.com/jhaddix/tbhm/blob/master/02_Discovery.md)** and related repo sections.

---

## TBHM structure (repo) at a glance

| TBHM area | Intent | AutoRecon |
|-----------|--------|-----------|
| **Before You Get Hacking** (learning, content creators) | Skill building | **Manual** — out of scope for the pipeline |
| **Reconnaissance / Discovery** | Find assets, “road less traveled,” ports, acquisitions, mobile | **Partially automated** — discovery providers + scanners + optional tools (see below) |
| **Application analysis → Mapping** | Spider, JS, endpoints, surface map | **Partially automated** — FFUF, SecretFinder; **Katana / GAU / GoSpider** installable via bootstrap, run manually or via future plugins |
| **Authorization, sessions, XSS, SQLi, …** | Deep testing | **Manual** — findings from Nuclei/wafw00f guide you; exploitation is not this framework’s job |
| **Auxiliary** | Wordlists, notes, tooling | **Config** (`wordlists`, `tools.*`, output JSON) |

---

## Discovery (TBHM themes → this framework)

### Find the “road less traveled”

- **Wildcard / deep scope** (`*.target.com`): AutoRecon does not parse program rules; you supply `--domain` / `domain` as the apex or scoped root.
- **Less obvious hosts:** After analysis, subdomains that are **not** `www.` get a **`non_www`** tag (heuristic only—not all flagship sites use `www`).
- **Google / search dorking:** **Manual / OSINT** (TBHM cites `site:` style queries). Optionally feed newly found apex domains back into `--domain` on a later run.
- **Acquisitions, mobile, redesigns:** **Manual** program-intel (TBHM calls these out explicitly in [Discovery](https://github.com/jhaddix/tbhm/blob/master/02_Discovery.md)).

### Enumeration stack (overlap with TBHM / industry practice)

| Activity | TBHM-style note | In AutoRecon |
|----------|-----------------|--------------|
| Subdomains | Combine several sources | `crtsh`, `subfinder`, `amass_passive`, `assetfinder`, `waybackurls`, `shuffledns`, **`github_subdomains`**, etc. |
| Certificate transparency | SSL scraping | **`crtsh`** provider |
| Historical / passive URLs | Old links → hosts | **`waybackurls`**, **`gau`** (bootstrap; manual or script) |
| DNS brute force | Wordlist-driven | **`shuffledns`** (+ **CeWL** for custom lists on Debian) |
| GitHub code search | Hostnames in repos | **`github_subdomains`** (needs `GITHUB_TOKEN` or `.tokens`) |

### Port scanning (“not just for netpen”)

TBHM stresses **full or wide port discovery** on discovered hosts to find **non-standard web services** and extra attack surface.

| Tool | Role | AutoRecon |
|------|------|-----------|
| **nmap** | Deep fingerprint / scripts (e.g. `http-title` style workflows) | **Bootstrap** (`apt` on Debian family) — **manual** invocation on your host lists |
| **naabu** | Fast port discovery on many hosts | **Bootstrap** (`go install` + **`libpcap-dev`** on Debian before build) — **manual** chaining with your asset export |

AutoRecon does **not** yet run naabu/nmap automatically per asset (that would be high-risk and scope-sensitive). Export `assets_*.json` and pipe identifiers into naabu/nmap when authorized.

### Subdomain takeover fingerprints

Aligned with “low-hanging” surface checks: **`subjack_scanner`**, **`subzy_scanner`**.

### Live HTTP(S) probing

**`httpx_scanner`** (ProjectDiscovery) for live services and metadata; avoid the unrelated Python `httpx` CLI on `PATH`.

### Wide template scanning

**`nuclei_scanner`** maps to TBHM’s use of broad automated checks as **signal**, not a substitute for manual analysis.

---

## Mapping & content discovery (TBHM ↔ tooling)

| TBHM idea | Typical tools | AutoRecon |
|-----------|---------------|-----------|
| Crawl + JS parsing | Burp, **Katana**, browsers | **Katana** in bootstrap — **manual** or future plugin |
| Historical URLs | **GAU**, wayback | **waybackurls** provider; **gau** in bootstrap |
| Spider | **GoSpider**, crawlers | **GoSpider** in bootstrap |
| Directory / wordlist fuzz | **FFUF** | **`ffuf_scanner`** + wordlist path |
| Secrets in JS | TruffleHog-style, **SecretFinder** | **`secretfinder_scanner`** if `scanning.secretfinder_script` is set |
| Parameters | Arjun, Param Miner | **Arjun** in bootstrap — **manual** |

---

## Suggested “TBHM-aware” config (authorized targets only)

```yaml
discovery:
  providers:
    - crtsh
    - subfinder
    - amass_passive
    - assetfinder
    - waybackurls
    # - github_subdomains   # GITHUB_TOKEN / .tokens
    # - shuffledns           # wordlist + resolvers

scanning:
  plugins:
    - httpx_scanner
    - wafw00f_scanner
    - nuclei_scanner
    - subjack_scanner
    - subzy_scanner
    # - ffuf_scanner
    # - secretfinder_scanner
```

Then:

1. Run the pipeline → review **`non_www`**-tagged assets in `assets_*.json`.  
2. Export host list → **naabu** / **nmap** manually when your rules allow.  
3. Feed confirmed URLs into **Katana** / **GAU** / **Arjun** as separate steps.

---

## Related docs in this repo

- [`METHODOLOGY.md`](METHODOLOGY.md) — R-s0n / checklist-style crosswalk.  
- [`README.md`](../../README.md) — providers, scanners, bootstrap, env vars.

---

## References

- Jason Haddix — **The Bug Hunter’s Methodology** repository: [https://github.com/jhaddix/tbhm](https://github.com/jhaddix/tbhm)  
- Discovery chapter (port scan, Google, acquisitions, etc.): [02_Discovery.md](https://github.com/jhaddix/tbhm/blob/master/02_Discovery.md)  
- Mapping chapter: [03_Mapping.md](https://github.com/jhaddix/tbhm/blob/master/03_Mapping.md)  

*NahamCon and other talks expand the same themes; use the GitHub repo as the maintained source of truth.*
