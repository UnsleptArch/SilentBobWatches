# silentbobwatches — Code Documentation

Developer-facing documentation of the codebase: module responsibilities, data
flow, key types, and the design boundaries that shaped the tool. For usage and
flags, see `README.md`.

---

## Design principle

The tool separates **what can be observed passively** from **what requires
touching a device**, and never blurs the two.

- **Passive** (default): send only what a browser/console sends on first
  contact, record the reply. No credentials, no auth bypass, no version guessing.
- **Active** (opt-in, consent-gated): authenticate to a device to confirm a
  vulnerability, using only read operations. Two capabilities: the CVE-2017-5689
  auth-bypass check and an authenticated WS-Man firmware-version read.

Two hard rules the code enforces:

1. **No memory-corruption exploitation.** The OOB-read/buffer advisories
   (INTEL-SA-00295, CVE-2020-8758, INTEL-SA-00391) are resolved by comparing an
   *authenticated* firmware version against a range table — never by sending a
   malformed packet. There is no safe remote PoC for those, so none exists here.
2. **No state changes.** Every active operation is a read (GET / WS-Man
   enumerate). Nothing powers, reboots, reconfigures, or provisions a device.

---

## Module map

| Module | Responsibility |
|---|---|
| `main.rs` | CLI orchestration: target expansion, the async passive scan, the opt-in active phase, progress, reporting. |
| `cli.rs` | `clap` interface, target/port expansion, `ActiveConfig` resolution (flags + `AMT_USER`/`AMT_PASS` env). |
| `scanner.rs` | Passive acquisition: TCP/HTTP/HTTPS probes, TLS cert capture, redirection-port presence, ASF/RMCP ping. |
| `active.rs` | Opt-in active confirmation: consent gate, Digest client, CVE-2017-5689 bypass, WS-Man version read. |
| `analysis.rs` | Fingerprinting and finding generation; passive analysis plus `apply_active` for the active results. |
| `cve_db.rs` | Advisory table and the version-range comparison logic. |
| `models.rs` | Core data shapes (no logic): protocol planes, evidence, findings, the per-probe asset record. |
| `report.rs` | Renders the summary + per-host detail for both the terminal and the log file. |
| `logger.rs` | Writes the JSON and human-readable logs to `SilentBobWatchesLogs/`. |

---

## Data flow

```
targets ──► ScannerEngine::scan_one ──► AmtAsset (raw evidence)
                                             │
                                             ▼
                             AnalysisEngine::analyze  (passive findings)
                                             │
                        ┌────────────────────┴───────────────────┐
                   (--active / creds, consented)             (otherwise)
                        │                                         │
             active::confirm ──► ActiveOutcome                    │
                        │                                         │
             AnalysisEngine::apply_active                         │
                        └────────────────────┬───────────────────┘
                                             ▼
                               report::render_full + logger
```

One `AmtAsset` is produced per `(host, port)` probe. The passive pass fills in
evidence and findings; the active pass (when enabled and consented) mutates the
AMT-detected assets in place with confirmation results.

---

## Passive layer (`scanner.rs`)

`ScannerEngine::scan_one` dispatches on `ProtocolPlane::from_port`:

- **16992 → HTTP**, **16993 → HTTPS**: `GET /index.htm`, collect status line,
  headers, Digest realm/nonce, page title, body snippet; on HTTPS also capture
  full certificate metadata via an observe-only TLS verifier that accepts any
  chain (AMT devices are self-signed — the cert is recorded, never trusted).
- **16994/16995 → RedirectionAmt**: `probe_tcp_presence` — a TCP connect only.
  These ports speak the binary SOL/IDE-R protocol, not HTTP, so nothing is sent
  after the handshake. An open port is a supporting AMT signal.
- **623/664 → RmcpAsf**: a DMTF ASF 2.0 Presence Ping (12 bytes, message type
  `0x80`); a pong whose OEM IANA Enterprise Number is 343 indicates Intel.

A per-host time budget (`host_timeout`) guarantees one hung device can't stall
the scan. `build_tls_config` is `pub(crate)` so `active.rs` reuses the same TLS
setup.

---

## Analysis layer (`analysis.rs`)

**`analyze` (passive)** runs only on `Responsive` assets:

- `fingerprint` — sets `amt_detected` from the Digest realm (`Intel(R) AMT`),
  Server header, or page title, and extracts the device GUID from the realm.
  It does **not** infer a firmware version; AMT does not expose the build
  unauthenticated, so any scraped version would be noise.
- `presence_finding`, `provisioning_posture`, `unauthenticated_exposure_check`
  (a 200 to an unauthenticated GET), `tls_findings`, `rmcp_findings`,
  `redirection_finding`.
- `provisioning_posture` — answers the questions that hold regardless of patch
  level: is the management plane reachable here, is it provisioned/operational
  (a live interface means AMT is provisioned, not dormant), and does it enforce
  authentication. It populates `provisioning_state_hint` and emits a `Medium`
  finding. The exact control mode (CCM vs ACM) is *not* readable unauthenticated,
  so it is recorded as an open item and not guessed — same honesty rule as the
  version handling.
- `cve_reference` — with no authenticated version, emits one honest
  `Insufficient` finding listing the applicable advisories and how to confirm
  them, rather than one speculative finding per CVE.

**`apply_active`** folds an `ActiveOutcome` into an asset:

- Records the CVE-2017-5689 bypass verdict (`Confirmed` on success, `NotPresent`
  on rejection).
- On a bypass-session version read, adds a proof-of-impact finding
  (admin-scoped data retrieved without credentials).
- Sets `firmware_hint` to the real build, removes the `cve_reference` finding,
  and calls `correlate_versioned` for deterministic `Confirmed`/`NotPresent`
  verdicts against the whole advisory table.

**Evidence states** (`VulnState`): `Confirmed` (bypass observed, or authenticated
version in an affected range), `NotPresent`, `Insufficient`. The old `Suspected`
state — previously produced by scraping a version from page text — is no longer
generated.

---

## Active layer (`active.rs`)

Runs only when `ActiveConfig::requested()` and `consent_gate` returns true.

- **Consent gate** — prints the authorization notice, requires an explicit
  `yes` (or `--yes` for pre-authorized scripted runs), returns false otherwise.
- **Digest client** — `parse_challenge` reads the `WWW-Authenticate` header;
  `digest_header` builds the `Authorization`. For `Auth::Bypass` the `response`
  is empty (the CVE-2017-5689 primitive) while `qop`/`nc`/`cnonce`/`opaque` are
  still echoed for firmware compatibility. For `Auth::Creds` it computes the full
  RFC 2617 response (MD5 via the `md-5` crate).
- **`attempt_bypass`** — fetches a fresh challenge on `/index.htm`, replays with
  an empty-response Digest; HTTP 200 = vulnerable, 401 = patched.
- **`read_firmware_version`** — POSTs a WS-Enumeration `Enumerate` for
  `CIM_SoftwareIdentity` to `/wsman`, authenticated via the bypass session or
  supplied credentials, then `pick_amt_version` selects the most AMT-like
  `VersionString` (2–4 numeric segments, major 6–25).
- **Minimal HTTP(S) client** — `send` connects plain or over TLS, writes the
  request, reads to close; `parse_response` extracts status / `WWW-Authenticate`
  and de-chunks if needed. Kept local rather than pulling in a full HTTP crate.

### ⚠ Verification status

The Digest and WS-Management paths are **written to spec but not yet validated
against live AMT hardware.** They compile and are structurally faithful, but
before trusting active verdicts, confirm on a device you own:

1. Whether `OptimizeEnumeration` returns the items inline in the
   `EnumerateResponse` or requires a follow-up `Pull`.
2. The exact `ResourceURI` / namespace prefixes your firmware expects.
3. That the bypass header's `qop`/`cnonce` echo is accepted.

---

## CVE correlation (`cve_db.rs`)

`CveEntry` carries `affected_branches: &[(branch, fixed_before_build)]`. Given a
`major.minor.build` version:

- `evaluate_generic` — matches the `major.minor` branch and compares the build
  against the fixed threshold → `VulnerableRange` / `Fixed` / `NotApplicable`.
- `evaluate_2017_5689` — special-cased: scoped by whole major version, with
  "fixed" builds identified by a 4-digit build number whose leading digit is 3.

Only `VulnerableRange` produces a finding (`Confirmed`, via authenticated
version). `Fixed`/`NotApplicable` are silent — nothing actionable to report.

---

## Adding an advisory

1. Add a `CveEntry` const in `cve_db.rs` with the branch/threshold table from the
   Intel advisory.
2. Add it to `all_entries()`.
3. If it is scoped unusually (like CVE-2017-5689), add a bespoke evaluator and
   wire it in `analysis.rs::correlate_versioned`.

No exploitation logic is added for new advisories — confirmation is always by
authenticated version comparison.

---

## Tests

The pure, side-effect-free logic is covered by inline `#[cfg(test)]` modules
(run with `cargo test`). These are the functions where a silent regression would
produce a *wrong verdict*, so they are the parts worth pinning down:

| Module | What is tested |
|---|---|
| `cve_db.rs` | `parse_firmware_hint`, `evaluate_generic` (below/at/above threshold, unlisted branch), and the `evaluate_2017_5689` special case (leading-3 build = fixed, in-scope vs out-of-scope branches). |
| `active.rs` | `dechunk`, `field` / `parse_challenge`, `amt_version_segments` / `pick_amt_version`, `parse_response`, and that the bypass Digest header carries an *empty* response hash while a credentialed one does not. |
| `cli.rs` | `expand_ports` (parsing, trimming, rejection) and `expand_targets` (single, list, comment/blank skipping, dash-range, CIDR host expansion). |
| `scanner.rs` | `extract_between`, `hex_encode`, the `ASF_PRESENCE_PING` byte layout, and `parse_http_response` (status, Digest realm/nonce, page title, server header). |

The network I/O and the active device-touching paths are deliberately not
covered here — theres no substitute for validating those against real hardware
(see the verification-status note above). The tests lock down the deterministic
logic around them so a refactor cant quietly change a verdict.
