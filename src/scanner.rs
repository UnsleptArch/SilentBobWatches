//! Passive network acquisition: TCP reachability, unauthenticated HTTP/HTTPS
//! collection, TLS certificate metadata, and ASF/RMCP presence discovery.
//!
//! This layer stays strictly passive. It sends only what a browser or console
//! sends on first contact and records the reply; credentials, auth bypasses,
//! and anything that touches a vulnerable code path live in `active.rs`, never
//! here.

use std::sync::Arc;
use std::time::Instant;

use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

use crate::models::{AmtAsset, HostStatus, HttpInfo, ProtocolPlane, RmcpInfo, TlsInfo};

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub host_timeout: Duration,
    pub max_body_bytes: usize,
    pub user_agent: String,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            connect_timeout: Duration::from_secs(3),
            read_timeout: Duration::from_secs(5),
            host_timeout: Duration::from_secs(12),
            max_body_bytes: 65536,
            user_agent: "silentbobwatches/2.0 (+authorized security assessment)".to_string(),
        }
    }
}

// AMT devices almost always present self-signed certificates, so we accept any
// chain in order to capture it rather than fail the handshake. The certificate
// is observed, never trusted for a security decision.
#[derive(Debug)]
struct ObservationOnlyVerifier;

impl rustls::client::danger::ServerCertVerifier for ObservationOnlyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA1,
            ECDSA_SHA1_Legacy,
            RSA_PKCS1_SHA256,
            ECDSA_NISTP256_SHA256,
            RSA_PKCS1_SHA384,
            ECDSA_NISTP384_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
        ]
    }
}

pub(crate) fn build_tls_config() -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("static rustls protocol version list should always be valid")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ObservationOnlyVerifier))
        .with_no_client_auth();
    Arc::new(config)
}

// ============================================================
// Raw HTTP request/response plumbing
// ============================================================

fn build_http_request(host: &str, user_agent: &str) -> Vec<u8> {
    format!(
        "GET /index.htm HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {ua}\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\
         \r\n",
        host = host,
        ua = user_agent
    )
    .into_bytes()
}

async fn read_until_closed_or_idle<S>(
    stream: &mut S,
    read_timeout: Duration,
    max_bytes: usize,
) -> Vec<u8>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if buf.len() >= max_bytes {
            break;
        }
        match timeout(read_timeout, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if n < chunk.len() {
                    // Likely drained what the peer had buffered; give it one
                    // more short chance in case more is coming, otherwise stop.
                    match timeout(Duration::from_millis(250), stream.read(&mut chunk)).await {
                        Ok(Ok(0)) | Err(_) => break,
                        Ok(Ok(more)) => {
                            buf.extend_from_slice(&chunk[..more]);
                        }
                        Ok(Err(_)) => break,
                    }
                    break;
                }
            }
            Ok(Err(_)) => break,
            Err(_) => break, // timed out waiting for data
        }
    }
    buf
}

struct ParsedHttp {
    info: HttpInfo,
}

fn parse_http_response(raw: &[u8], round_trip_ms: u128) -> ParsedHttp {
    let text = String::from_utf8_lossy(raw);
    let mut info = HttpInfo::default();
    info.round_trip_ms = Some(round_trip_ms);

    let (head, body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h, b),
        None => (text.as_ref(), ""),
    };

    let mut lines = head.split("\r\n");
    if let Some(status_line) = lines.next() {
        info.status_line = Some(status_line.to_string());
        if let Some(code_str) = status_line.split_whitespace().nth(1) {
            info.status_code = code_str.parse().ok();
        }
    }

    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            let key_lower = key.to_lowercase();

            if key_lower == "www-authenticate" {
                info.www_authenticate = Some(val.clone());
                if let Some(realm) = extract_between(&val, "realm=\"", "\"") {
                    info.digest_realm = Some(realm);
                }
                if let Some(nonce) = extract_between(&val, "nonce=\"", "\"") {
                    info.digest_nonce = Some(nonce);
                }
            }
            if key_lower == "server" {
                info.server_header = Some(val.clone());
            }
            info.headers.insert(key, val);
        }
    }

    let body_bytes = body.as_bytes();
    info.body_length = Some(body_bytes.len());
    let snippet_len = body_bytes.len().min(512);
    info.body_snippet = Some(String::from_utf8_lossy(&body_bytes[..snippet_len]).to_string());
    info.page_title = extract_between(body, "<title>", "</title>")
        .or_else(|| extract_between(body, "<TITLE>", "</TITLE>"));

    ParsedHttp { info }
}

fn extract_between(haystack: &str, start: &str, end: &str) -> Option<String> {
    let start_idx = haystack.find(start)? + start.len();
    let rest = &haystack[start_idx..];
    let end_idx = rest.find(end)?;
    Some(rest[..end_idx].to_string())
}

// ============================================================
// Plain HTTP probe (16992 / 16994)
// ============================================================

async fn probe_http(host: &str, port: u16, cfg: &ScanConfig) -> AmtAsset {
    let mut asset = AmtAsset::new(host.to_string(), port, ProtocolPlane::from_port(port));
    let connect_start = Instant::now();

    let stream = match timeout(cfg.connect_timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            asset.status = if is_refused(&e) {
                HostStatus::Closed
            } else {
                HostStatus::Error
            };
            asset.notes.push(format!("TCP connect failed: {}", e));
            return asset;
        }
        Err(_) => {
            asset.status = HostStatus::Filtered;
            asset.notes.push("TCP connect timed out (no response)".to_string());
            return asset;
        }
    };

    asset.connect_ms = Some(connect_start.elapsed().as_millis());
    asset.status = HostStatus::Responsive;

    let mut stream = stream;
    let req = build_http_request(host, &cfg.user_agent);
    let req_start = Instant::now();

    if let Err(e) = timeout(cfg.read_timeout, stream.write_all(&req)).await {
        asset.notes.push(format!("write timed out: {}", e));
        return asset;
    }

    let raw = read_until_closed_or_idle(&mut stream, cfg.read_timeout, cfg.max_body_bytes).await;
    let rtt = req_start.elapsed().as_millis();

    if raw.is_empty() {
        asset
            .notes
            .push("connection accepted but no HTTP response received".to_string());
        return asset;
    }

    let parsed = parse_http_response(&raw, rtt);
    asset.http = Some(parsed.info);
    asset
}

// ============================================================
// TLS + HTTPS probe (16993 / 16995)
// ============================================================

async fn probe_https(host: &str, port: u16, cfg: &ScanConfig, tls_config: Arc<rustls::ClientConfig>) -> AmtAsset {
    let mut asset = AmtAsset::new(host.to_string(), port, ProtocolPlane::from_port(port));
    let connect_start = Instant::now();

    let tcp = match timeout(cfg.connect_timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            asset.status = if is_refused(&e) {
                HostStatus::Closed
            } else {
                HostStatus::Error
            };
            asset.notes.push(format!("TCP connect failed: {}", e));
            return asset;
        }
        Err(_) => {
            asset.status = HostStatus::Filtered;
            asset.notes.push("TCP connect timed out (no response)".to_string());
            return asset;
        }
    };
    asset.connect_ms = Some(connect_start.elapsed().as_millis());

    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(sn) => sn,
        Err(_) => {
            asset.status = HostStatus::Error;
            asset.notes.push("could not build TLS server name from host".to_string());
            return asset;
        }
    };

    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let handshake_start = Instant::now();

    let tls_stream = match timeout(cfg.connect_timeout, connector.connect(server_name, tcp)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            asset.status = HostStatus::Error;
            asset
                .notes
                .push(format!("TLS handshake failed (port open, not speaking TLS?): {}", e));
            return asset;
        }
        Err(_) => {
            asset.status = HostStatus::Filtered;
            asset.notes.push("TLS handshake timed out".to_string());
            return asset;
        }
    };

    let handshake_ms = handshake_start.elapsed().as_millis();
    asset.status = HostStatus::Responsive;

    let mut tls_info = TlsInfo::default();
    tls_info.handshake_ms = Some(handshake_ms);
    {
        let (_, conn) = tls_stream.get_ref();
        if let Some(version) = conn.protocol_version() {
            tls_info.protocol_version = Some(format!("{:?}", version));
        }
        if let Some(suite) = conn.negotiated_cipher_suite() {
            tls_info.cipher_suite = Some(format!("{:?}", suite.suite()));
        }
        if let Some(certs) = conn.peer_certificates() {
            tls_info.chain_length = Some(certs.len());
            if let Some(leaf) = certs.first() {
                populate_cert_info(&mut tls_info, leaf);
            }
        }
    }
    asset.tls = Some(tls_info);

    let mut tls_stream = tls_stream;
    let req = build_http_request(host, &cfg.user_agent);
    let req_start = Instant::now();

    if let Err(e) = timeout(cfg.read_timeout, tls_stream.write_all(&req)).await {
        asset.notes.push(format!("write timed out over TLS: {}", e));
        return asset;
    }

    let raw = read_until_closed_or_idle(&mut tls_stream, cfg.read_timeout, cfg.max_body_bytes).await;
    let rtt = req_start.elapsed().as_millis();

    if raw.is_empty() {
        asset
            .notes
            .push("TLS session established but no HTTP response received".to_string());
        return asset;
    }

    let parsed = parse_http_response(&raw, rtt);
    asset.http = Some(parsed.info);
    asset
}

fn populate_cert_info(tls_info: &mut TlsInfo, der: &CertificateDer<'_>) {
    match x509_parser::parse_x509_certificate(der.as_ref()) {
        Ok((_, cert)) => {
            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            tls_info.cert_likely_self_signed = Some(subject == issuer);
            tls_info.cert_subject = Some(subject);
            tls_info.cert_issuer = Some(issuer);
            tls_info.cert_serial = Some(cert.raw_serial_as_string());
            tls_info.cert_signature_algorithm = Some(cert.signature_algorithm.algorithm.to_id_string());

            let validity = cert.validity();
            tls_info.cert_not_before = Some(validity.not_before.to_string());
            tls_info.cert_not_after = Some(validity.not_after.to_string());

            let now = x509_parser::time::ASN1Time::now();
            let remaining_seconds = validity.not_after.timestamp() - now.timestamp();
            tls_info.cert_days_remaining = Some(remaining_seconds / 86400);
            tls_info.cert_expired = Some(remaining_seconds < 0);

            if let Ok(Some(san)) = cert.subject_alternative_name() {
                for name in san.value.general_names.iter() {
                    tls_info.cert_subject_alt_names.push(format!("{:?}", name));
                }
            }
        }
        Err(e) => {
            tls_info.cert_subject = Some(format!("<unparsable certificate: {}>", e));
        }
    }
}

fn is_refused(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
    )
}

// ============================================================
// TCP presence probe (AMT redirection ports 16994 / 16995)
//
// The redirection plane (Serial-over-LAN / IDE-R) speaks a binary Intel
// protocol, NOT HTTP, so we deliberately send nothing after the TCP
// handshake and never try to parse a response as HTTP. We only record
// whether the port accepts a connection: an open redirection port is itself
// a strong supporting signal that AMT redirection is enabled on the host.
// ============================================================

async fn probe_tcp_presence(host: &str, port: u16, cfg: &ScanConfig) -> AmtAsset {
    let mut asset = AmtAsset::new(host.to_string(), port, ProtocolPlane::from_port(port));
    let connect_start = Instant::now();

    match timeout(cfg.connect_timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(_stream)) => {
            asset.connect_ms = Some(connect_start.elapsed().as_millis());
            asset.status = HostStatus::Responsive;
            asset.notes.push(
                "redirection port accepted a TCP connection; this is the binary SOL/IDE-R plane, so no request was sent and no response was parsed".to_string(),
            );
        }
        Ok(Err(e)) => {
            asset.status = if is_refused(&e) {
                HostStatus::Closed
            } else {
                HostStatus::Error
            };
            asset.notes.push(format!("TCP connect failed: {}", e));
        }
        Err(_) => {
            asset.status = HostStatus::Filtered;
            asset.notes.push("TCP connect timed out (no response)".to_string());
        }
    }

    asset
}

// ============================================================
// RMCP / ASF presence ping (UDP 623 / 664)
//
// This is a standard DMTF ASF 2.0 "Presence Ping" -- the same discovery
// packet ipmitool / nmap send. It is a read-only discovery beacon, not an
// authentication attempt.
// ============================================================

const ASF_PRESENCE_PING: [u8; 12] = [
    0x06, 0x00, 0xff, 0x06, // RMCP header: version 1.0, reserved, seq=0xFF (no ACK), class=ASF (0x06)
    0x00, 0x00, 0x11, 0xbe, // ASF IANA enterprise number 4542 (0x000011BE)
    0x80, // Message Type = 0x80 (Presence Ping)
    0x00, // Message Tag
    0x00, // reserved
    0x00, // Data Length = 0 (no trailing data)
];

async fn probe_rmcp(host: &str, port: u16, cfg: &ScanConfig) -> AmtAsset {
    let mut asset = AmtAsset::new(host.to_string(), port, ProtocolPlane::from_port(port));

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            asset.status = HostStatus::Error;
            asset.notes.push(format!("could not open UDP socket: {}", e));
            return asset;
        }
    };

    if let Err(e) = socket.connect((host, port)).await {
        asset.status = HostStatus::Error;
        asset.notes.push(format!("UDP connect failed: {}", e));
        return asset;
    }

    let start = Instant::now();
    if let Err(e) = socket.send(&ASF_PRESENCE_PING).await {
        asset.status = HostStatus::Error;
        asset.notes.push(format!("UDP send failed: {}", e));
        return asset;
    }

    let mut buf = [0u8; 256];
    let mut rmcp_info = RmcpInfo::default();

    match timeout(cfg.read_timeout, socket.recv(&mut buf)).await {
        Ok(Ok(n)) => {
            let rtt = start.elapsed().as_millis();
            rmcp_info.responded = true;
            rmcp_info.rtt_ms = Some(rtt);
            rmcp_info.response_len = Some(n);
            rmcp_info.raw_response_hex = Some(hex_encode(&buf[..n]));

            // ASF Presence Pong layout (best-effort per DMTF ASF 2.0 spec):
            // bytes 0-3 RMCP header, 4-7 IANA enterprise (ASF=4542),
            // 8 message type, 9 message tag, 10 reserved, 11 data length,
            // 12-15 OEM IANA enterprise number, ...
            if n >= 16 {
                let oem_iana = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
                rmcp_info.oem_iana_enterprise = Some(oem_iana);
                // IANA Private Enterprise Number 343 is registered to Intel.
                rmcp_info.oem_iana_is_intel = Some(oem_iana == 343);
            }

            asset.status = HostStatus::Responsive;
        }
        Ok(Err(e)) => {
            asset.status = HostStatus::Error;
            asset.notes.push(format!("UDP recv error: {}", e));
        }
        Err(_) => {
            asset.status = HostStatus::Filtered;
            asset
                .notes
                .push("no ASF/RMCP presence-pong received (UDP is inherently unreliable; this is not conclusive)".to_string());
        }
    }

    asset.rmcp = Some(rmcp_info);
    asset
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ============================================================
// Coordinator: one call per (host, port), with a hard host-level time
// budget so a single slow/broken host can never stall the whole scan.
// ============================================================

pub struct ScannerEngine {
    cfg: ScanConfig,
    tls_config: Arc<rustls::ClientConfig>,
}

impl ScannerEngine {
    pub fn new(cfg: ScanConfig) -> Self {
        ScannerEngine {
            tls_config: build_tls_config(),
            cfg,
        }
    }

    pub async fn scan_one(&self, host: String, port: u16) -> AmtAsset {
        let start = Instant::now();
        let protocol = ProtocolPlane::from_port(port);
        let cfg = self.cfg.clone();
        let tls_config = self.tls_config.clone();
        let host_for_timeout = host.clone();

        let fut = async move {
            match protocol {
                ProtocolPlane::HttpAmt => probe_http(&host, port, &cfg).await,
                ProtocolPlane::HttpsAmt => probe_https(&host, port, &cfg, tls_config).await,
                ProtocolPlane::RedirectionAmt => probe_tcp_presence(&host, port, &cfg).await,
                ProtocolPlane::RmcpAsf => probe_rmcp(&host, port, &cfg).await,
                ProtocolPlane::Unknown => probe_http(&host, port, &cfg).await,
            }
        };

        let mut asset = match timeout(self.cfg.host_timeout, fut).await {
            Ok(asset) => asset,
            Err(_) => {
                let mut a = AmtAsset::new(host_for_timeout, port, protocol);
                a.status = HostStatus::TimedOut;
                a.notes.push(format!(
                    "host scan exceeded the {}s time budget and was suspected non-responsive/broken; skipped to keep the overall scan moving",
                    self.cfg.host_timeout.as_secs()
                ));
                a
            }
        };

        asset.scan_duration_ms = start.elapsed().as_millis();
        asset
    }
}
