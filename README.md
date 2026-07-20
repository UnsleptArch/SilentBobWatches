# silentbobwatches 

A defensiveish-security assessment tool for discovering, fingerprinting, and
evidence-scoring Intel AMT / ISM management interfaces on networks you are
authorized to assess. As the name implies it was mainly built around CVE-2017-5689 as I discovered the only real software to scan a target was a half baked MSF module. Discovery is passive by default; vulnerability
confirmation is opt-in, read-only, and consent-gated.

Built for speed (async, concurrent, single static binary) and for honesty about
what can and can't be known from the network alone.

## What this tool does

**Passive discovery (default, unauthenticated):**

- Finds AMT/ISM interfaces over HTTP (16992), HTTPS (16993), the redirection
  plane (16994/16995, SOL/IDE-R — connect-only presence, never HTTP-parsed), and
  ASF/RMCP presence-ping (UDP 623/664).
- Collects protocol evidence: HTTP status/headers/Digest realm/page title, full
  TLS certificate detail (subject, issuer, validity, SANs, cipher suite,
  self-signed heuristic), and ASF/RMCP OEM IANA enterprise data.
- Answers the posture questions that actually matter regardless of patch level:
  **is the AMT management plane reachable on this segment**, **is it provisioned
  and operational** (a live management interface means AMT is provisioned, not
  dormant), and **does it enforce authentication or answer unauthenticated**. The
  exact control mode (Client Control Mode vs Admin Control Mode) is not exposed to
  an unauthenticated caller, so its reported as an open item rather then guessed.
- Reports presence, unauthenticated-exposure, TLS hygiene, and an honest
  "advisories that apply — authenticate to confirm" reference. Without an
  authenticated firmware build, version-gated advisories stay `Insufficient`; the
  tool never scrapes a version out of page text and guesses.

**Active confirmation (opt-in, read-only):**

- `--active` runs the CVE-2017-5689 auth-bypass check: a Digest request with an
  empty response hash. A `200` to a protected GET confirms the bypass
  (`Confirmed`); a `401` marks it patched (`NotPresent`). Read-only — nothing is
  written.
- With `--amt-user`/`--amt-pass` (or a working bypass session), it reads the
  firmware build over WS-Management (`CIM_SoftwareIdentity`) and runs the
  advisory table against the *real* version. That resolves the memory-corruption
  advisories (INTEL-SA-00295, CVE-2020-8758, INTEL-SA-00391) deterministically —
  `Confirmed` or `NotPresent` — **without ever sending a malformed packet.**

Evidence states: **Confirmed** (bypass observed, or authenticated version in an
affected range), **NotPresent** (patched / out of range), **Insufficient**
(presence detected, no authenticated version available).

## What this tool deliberately does NOT do

- **No memory-corruption exploitation.** The OOB-read / buffer advisories are
  confirmed by authenticated version comparison, never by triggering them —
  there is no safe way to fire those without risking a firmware/host crash, so
  the tool doesn't.
- **No credential guessing**, no default-password spraying.
- **No state changes.** Every active check is a read (a GET, a WS-Man
  enumeration). It never powers, reboots, reconfigures, or provisions a device.

The active checks authenticate to a device, so they run only behind an explicit
`--active`/credential flag **and** a one-time consent prompt.

> **Note:** the Digest and WS-Management code paths are written to spec but have
> not yet been validated against live AMT hardware. Confirm behavior on a device
> you own before relying on active verdicts.

BASICALLYYYY that all amounts to don't get me in trouble please + claude safety slop,

## Building

Requires a stable Rust toolchain (edition 2021).

```bash
cargo build --release
./target/release/silentbobwatches --help
```

The pure logic (version-range comparison, the Digest/chunked/HTTP parsers, and
target/port expansion) is covered by unit tests. Run them with:

```bash
cargo test
```

Or use the included installer, which builds a release binary and installs it to
`/usr/local/bin` (or `~/.local/bin` as a fallback):

```bash
./install.sh
```

## Usage

```bash
silentbobwatches <targets> [OPTIONS]
```

`<targets>` accepts a single IP/hostname, a CIDR (`10.0.0.0/24`), a
comma-separated list, a last-octet range (`10.0.0.10-20`), or a file
(`@targets.txt`, one per line).

Common flags:

| Flag | Meaning |
|---|---|
| `--ports` | comma-separated ports (default `16992,16993,16994,16995,623,664`) |
| `--concurrency` | max probes in flight (default 200) |
| `--connect-timeout` / `--read-timeout` / `--host-timeout` | timeouts in seconds (default 3 / 5 / 12) |
| `--active` | enable the read-only CVE-2017-5689 bypass check (consent-gated) |
| `--amt-user` / `--amt-pass` | AMT credentials for WS-Man version read (or `AMT_USER` / `AMT_PASS` env) |
| `--yes` | skip the interactive consent prompt (already-authorized, scripted runs) |
| `-v` / `-vv` / `-vvv` | live verbosity (the final report is always full detail) |
| `--quiet` | suppress live chatter; still prints the full final report |
| `--log-dir` / `--json <path>` | evidence folder / extra JSON copy |
| `--no-color` | disable ANSI color |

### Examples

```bash
# Passive sweep of a /24 for AMT on the standard ports
silentbobwatches 10.20.0.0/24

# Passive discovery plus the read-only 2017-5689 confirmation (prompts for consent)
silentbobwatches 10.20.0.0/24 --active

# Authenticated version resolution for the memory-corruption advisories
AMT_USER=admin AMT_PASS=... silentbobwatches 10.20.0.5 --active --yes
```

## Output

Every run creates/updates `SilentBobWatchesLogs/` with a machine-readable
`scan_<timestamp>.json` and a human-readable `scan_<timestamp>.log`, and always
prints the full report to the terminal.

## CVE data sources

The advisory table in `src/cve_db.rs` is sourced from Intel's Security Center
advisories (linked in each entry), kept intentionally small and auditable rather
than exhaustive. Update it when Intel updates an advisory.

## License

GPLv3 or later. See `LICENSE`.

## Ethics / authorized use

For assessing systems you own or are explicitly authorized to test. Active
checks authenticate to a device — only point them at hosts you are authorized to
assess. Scanning or authenticating without authorization may be illegal
regardless of what the tool does; that responsibilty sits with the operator, not
the tool. Don't come crying to me when you get into trouble for using this. 
