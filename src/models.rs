//! Core data shapes: protocol planes, evidence, findings, and the per-probe
//! asset record. No network or analysis logic lives here.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================
// Enumerations
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolPlane {
    HttpAmt,
    HttpsAmt,
    RedirectionAmt,
    RmcpAsf,
    Unknown,
}

impl ProtocolPlane {
    pub fn label(&self) -> &'static str {
        match self {
            ProtocolPlane::HttpAmt => "Intel AMT HTTP Management Interface",
            ProtocolPlane::HttpsAmt => "Intel AMT HTTPS Management Interface",
            ProtocolPlane::RedirectionAmt => "Intel AMT Redirection Plane (SOL/IDE-R)",
            ProtocolPlane::RmcpAsf => "ASF/RMCP Management Plane",
            ProtocolPlane::Unknown => "Unknown Service",
        }
    }

    /// Best-effort protocol classification based on the well-known Intel AMT
    /// port assignments. This is a convenience default only -- it does not
    /// guarantee the service actually speaking on that port is AMT.
    pub fn from_port(port: u16) -> ProtocolPlane {
        match port {
            16992 => ProtocolPlane::HttpAmt,
            16993 => ProtocolPlane::HttpsAmt,
            16994 | 16995 => ProtocolPlane::RedirectionAmt,
            623 | 664 => ProtocolPlane::RmcpAsf,
            _ => ProtocolPlane::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthState {
    Unknown,
    NoneObserved,
    Digest,
    AccessDenied,
}

impl AuthState {
    pub fn label(&self) -> &'static str {
        match self {
            AuthState::Unknown => "Unknown",
            AuthState::NoneObserved => "No authentication challenge observed",
            AuthState::Digest => "HTTP Digest authentication challenge observed",
            AuthState::AccessDenied => "Access denied",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

/// Distinguishes between what was passively observed vs. what is inferred.
/// silentbobwatches never attempts exploitation, so `Confirmed` is only ever
/// used for facts that are directly observable without exercising a
/// vulnerability (e.g. "this endpoint returned content without
/// authentication"), never for "this CVE was successfully triggered".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnState {
    NotPresent,
    Insufficient,
    Suspected,
    Confirmed,
}

impl VulnState {
    pub fn label(&self) -> &'static str {
        match self {
            VulnState::NotPresent => "No vulnerability evidence",
            VulnState::Insufficient => "Insufficient evidence to determine",
            VulnState::Suspected => "Evidence suggests possible vulnerability",
            VulnState::Confirmed => "Directly observed without exploitation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn from_cvss(score: f32) -> Severity {
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score > 0.0 {
            Severity::Low
        } else {
            Severity::Info
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostStatus {
    /// Something answered on the port and we collected data.
    Responsive,
    /// TCP connect refused / port closed.
    Closed,
    /// No data at all (dropped packets, filtered).
    Filtered,
    /// Per-host time budget expired; scan moved on deliberately.
    TimedOut,
    /// An unexpected error occurred while probing.
    Error,
}

impl HostStatus {
    pub fn label(&self) -> &'static str {
        match self {
            HostStatus::Responsive => "responsive",
            HostStatus::Closed => "closed",
            HostStatus::Filtered => "filtered/no response",
            HostStatus::TimedOut => "skipped (time budget exceeded)",
            HostStatus::Error => "error",
        }
    }
}

// ============================================================
// Evidence & Findings
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub source: String,
    pub data: String,
    pub confidence: Confidence,
    pub timestamp: String,
}

impl Evidence {
    pub fn new(source: impl Into<String>, data: impl Into<String>, confidence: Confidence) -> Self {
        Evidence {
            source: source.into(),
            data: data.into(),
            confidence,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cve: Option<String>,
    pub advisory: Option<String>,
    pub state: VulnState,
    pub evidence: Vec<Evidence>,
    pub remediation: String,
}

// ============================================================
// Collected protocol data
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpInfo {
    pub status_line: Option<String>,
    pub status_code: Option<u16>,
    pub headers: HashMap<String, String>,
    pub www_authenticate: Option<String>,
    pub digest_realm: Option<String>,
    pub digest_nonce: Option<String>,
    pub server_header: Option<String>,
    pub body_snippet: Option<String>,
    pub body_length: Option<usize>,
    pub page_title: Option<String>,
    pub round_trip_ms: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsInfo {
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub cert_subject: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_not_before: Option<String>,
    pub cert_not_after: Option<String>,
    pub cert_days_remaining: Option<i64>,
    pub cert_expired: Option<bool>,
    pub cert_likely_self_signed: Option<bool>,
    pub cert_subject_alt_names: Vec<String>,
    pub cert_serial: Option<String>,
    pub cert_signature_algorithm: Option<String>,
    pub chain_length: Option<usize>,
    pub handshake_ms: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RmcpInfo {
    pub responded: bool,
    pub raw_response_hex: Option<String>,
    pub response_len: Option<usize>,
    pub oem_iana_enterprise: Option<u32>,
    pub oem_iana_is_intel: Option<bool>,
    pub rtt_ms: Option<u128>,
}

// ============================================================
// Asset (single host:port probe result)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmtAsset {
    pub host: String,
    pub port: u16,
    pub protocol: ProtocolPlane,
    pub status: HostStatus,
    pub connect_ms: Option<u128>,
    pub vendor: Option<String>,
    pub amt_detected: bool,
    pub amt_device_guid: Option<String>,
    pub firmware_hint: Option<String>,
    pub provisioning_state_hint: Option<String>,
    pub auth_state: AuthState,
    pub http: Option<HttpInfo>,
    pub tls: Option<TlsInfo>,
    pub rmcp: Option<RmcpInfo>,
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
    pub scanned_at: String,
    pub scan_duration_ms: u128,
}

impl AmtAsset {
    pub fn new(host: String, port: u16, protocol: ProtocolPlane) -> Self {
        AmtAsset {
            host,
            port,
            protocol,
            status: HostStatus::Filtered,
            connect_ms: None,
            vendor: None,
            amt_detected: false,
            amt_device_guid: None,
            firmware_hint: None,
            provisioning_state_hint: None,
            auth_state: AuthState::Unknown,
            http: None,
            tls: None,
            rmcp: None,
            findings: Vec::new(),
            notes: Vec::new(),
            scanned_at: chrono::Utc::now().to_rfc3339(),
            scan_duration_ms: 0,
        }
    }

    pub fn worth_reporting(&self) -> bool {
        matches!(self.status, HostStatus::Responsive) || !self.findings.is_empty()
    }
}

// ============================================================
// Scan configuration & summary
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMeta {
    pub tool: String,
    pub version: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub target_spec: String,
    pub total_hosts: usize,
    pub total_ports: usize,
    pub total_probes: usize,
    pub concurrency: usize,
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub host_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub meta: ScanMeta,
    pub assets: Vec<AmtAsset>,
}
