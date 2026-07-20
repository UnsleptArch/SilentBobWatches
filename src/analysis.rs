//! Turns collected evidence into fingerprints and findings.
//!
//! Passive analysis never invents a firmware version: AMT does not expose its
//! build over unauthenticated network protocols, so version-gated advisories
//! stay `Insufficient` until the active phase (`active.rs`) supplies a real,
//! authenticated build via `apply_active`. Nothing here exploits anything.

use crate::active::ActiveOutcome;
use crate::cve_db::{self, CveEntry, VersionVerdict};
use crate::models::{
    AmtAsset, AuthState, Confidence, Evidence, Finding, HostStatus, ProtocolPlane, Severity,
    VulnState,
};

const CVE_REFERENCE_TITLE: &str = "Intel AMT firmware advisories applicable to this platform";

pub struct AnalysisEngine;

impl AnalysisEngine {
    pub fn new() -> Self {
        AnalysisEngine
    }

    /// Passive pass: runs on collected network evidence only.
    pub fn analyze(&self, asset: &mut AmtAsset) {
        if !matches!(asset.status, HostStatus::Responsive) {
            return;
        }

        self.fingerprint(asset);

        if asset.amt_detected {
            asset.vendor = Some("Intel".to_string());
            self.presence_finding(asset);
            self.provisioning_posture(asset);
            self.unauthenticated_exposure_check(asset);
            self.cve_reference(asset);
        }

        self.tls_findings(asset);
        self.rmcp_findings(asset);
        self.redirection_finding(asset);
    }

    /// Folds the results of the opt-in active phase into an already-analyzed
    /// asset: the CVE-2017-5689 bypass verdict, a proof-of-impact record, and
    /// deterministic version correlation for the remaining advisories.
    pub fn apply_active(&self, asset: &mut AmtAsset, outcome: &ActiveOutcome) {
        match outcome.bypass_2017_5689 {
            Some(true) => asset.findings.push(Finding {
                title: "CVE-2017-5689 confirmed via authentication bypass".to_string(),
                description: "A Digest request with an empty response hash was accepted, returning protected content without valid credentials. This directly confirms the INTEL-SA-00075 authentication bypass.".to_string(),
                severity: Severity::Critical,
                cve: Some("CVE-2017-5689".to_string()),
                advisory: Some("INTEL-SA-00075".to_string()),
                state: VulnState::Confirmed,
                evidence: vec![Evidence::new(
                    "Active bypass check",
                    "empty-response Digest authenticated a protected GET (HTTP 200)",
                    Confidence::High,
                )],
                remediation: cve_db::CVE_2017_5689.remediation.to_string(),
            }),
            Some(false) => asset.findings.push(Finding {
                title: "CVE-2017-5689 not present".to_string(),
                description: "The empty-response Digest bypass was rejected, indicating patched firmware for INTEL-SA-00075.".to_string(),
                severity: Severity::Info,
                cve: Some("CVE-2017-5689".to_string()),
                advisory: Some("INTEL-SA-00075".to_string()),
                state: VulnState::NotPresent,
                evidence: vec![Evidence::new("Active bypass check", "empty-response Digest rejected (HTTP 401)", Confidence::High)],
                remediation: "No action required for this specific advisory.".to_string(),
            }),
            None => {}
        }

        if let Some(version) = &outcome.firmware_version {
            asset.firmware_hint = Some(version.clone());
            asset.findings.retain(|f| f.title != CVE_REFERENCE_TITLE);

            if matches!(outcome.version_source.as_deref(), Some("unauthenticated bypass session")) {
                asset.findings.push(Finding {
                    title: "Privileged firmware data retrieved without credentials".to_string(),
                    description: format!(
                        "An authenticated-only WS-Management query (CIM_SoftwareIdentity) was answered over the bypass session, returning firmware build {version}. Retrieving admin-scoped data with no credentials is direct proof of impact.",
                    ),
                    severity: Severity::High,
                    cve: None,
                    advisory: None,
                    state: VulnState::Confirmed,
                    evidence: vec![Evidence::new("WS-Management CIM_SoftwareIdentity", format!("firmware build {version}"), Confidence::High)],
                    remediation: "Unprovision/patch AMT; treat this host's management plane as compromised until remediated.".to_string(),
                });
            }

            self.correlate_versioned(asset, version, outcome.version_source.as_deref().unwrap_or("authenticated read"));
        }

        for note in &outcome.notes {
            asset.notes.push(format!("active: {note}"));
        }
    }

    // --------------------------------------------------------
    // Fingerprinting
    // --------------------------------------------------------

    fn fingerprint(&self, asset: &mut AmtAsset) {
        let Some(http) = &asset.http else { return };

        if let Some(realm) = &http.digest_realm {
            asset.auth_state = AuthState::Digest;
            let realm_lower = realm.to_lowercase();
            if realm_lower.contains("intel amt") || realm_lower.contains("intel(r) amt") {
                asset.amt_detected = true;
                asset.amt_device_guid = extract_device_guid(realm);
            }
        } else if http.status_code == Some(401) {
            asset.auth_state = AuthState::AccessDenied;
        } else {
            asset.auth_state = AuthState::NoneObserved;
        }

        if let Some(server) = &http.server_header {
            let s = server.to_lowercase();
            if s.contains("intel") && (s.contains("amt") || s.contains("management")) {
                asset.amt_detected = true;
            }
        }

        if let Some(title) = &http.page_title {
            let t = title.to_lowercase();
            if t.contains("intel")
                && (t.contains("amt") || t.contains("active management") || t.contains("standard manageability"))
            {
                asset.amt_detected = true;
            }
        }
    }

    // --------------------------------------------------------
    // Passive findings
    // --------------------------------------------------------

    fn presence_finding(&self, asset: &mut AmtAsset) {
        let mut evidence = Vec::new();
        if let Some(http) = &asset.http {
            if let Some(realm) = &http.digest_realm {
                evidence.push(Evidence::new("HTTP WWW-Authenticate", format!("Digest realm: {realm}"), Confidence::High));
            }
            if let Some(server) = &http.server_header {
                evidence.push(Evidence::new("HTTP Server header", server.clone(), Confidence::Medium));
            }
            if let Some(title) = &http.page_title {
                evidence.push(Evidence::new("HTML <title>", title.clone(), Confidence::Medium));
            }
        }

        asset.findings.push(Finding {
            title: "Intel AMT management interface identified".to_string(),
            description: format!(
                "{}:{} responded with signatures consistent with an Intel AMT/ISM management interface ({}).",
                asset.host, asset.port, asset.protocol.label()
            ),
            severity: Severity::Info,
            cve: None,
            advisory: None,
            state: VulnState::Confirmed,
            evidence,
            remediation: "Confirm this asset is authorized to run remote management firmware and is reachable only from an isolated management network.".to_string(),
        });
    }

    /// Answers the posture questions that matter regardless of patch level:
    /// is the AMT management plane reachable on this segment at all, and is it
    /// provisioned/operational? A live management interface means AMT is
    /// provisioned rather than dormant. The exact control mode (Client Control
    /// Mode vs Admin Control Mode) is not exposed to an unauthenticated caller,
    /// so we record that as an open item instead of guessing it.
    fn provisioning_posture(&self, asset: &mut AmtAsset) {
        let enforcing_auth = matches!(asset.auth_state, AuthState::Digest | AuthState::AccessDenied);
        let hint = if enforcing_auth {
            "Provisioned / operational (management interface reachable and enforcing authentication); control mode not determinable without an authenticated read"
        } else {
            "Provisioned / operational (management interface reachable); no authentication challenge observed on first contact"
        };
        asset.provisioning_state_hint = Some(hint.to_string());

        let mut evidence = vec![Evidence::new(
            "Reachability",
            format!("management plane answered on {}:{} ({})", asset.host, asset.port, asset.protocol.label()),
            Confidence::High,
        )];
        if enforcing_auth {
            evidence.push(Evidence::new("Auth state", asset.auth_state.label(), Confidence::High));
        }

        asset.findings.push(Finding {
            title: "Intel AMT management plane reachable on this segment".to_string(),
            description: format!(
                "The AMT management interface at {}:{} is reachable and operational, which means AMT is provisioned rather than dormant on this host. Whether it runs in Client Control Mode or Admin Control Mode cannot be read without authentication, so that stays an open item. AMT should generally be reachable only from an isolated out-of-band management network; reachability from a general-purpose segment is itself worth reviewing.",
                asset.host, asset.port
            ),
            severity: Severity::Medium,
            cve: None,
            advisory: None,
            state: VulnState::Confirmed,
            evidence,
            remediation: "Confirm AMT is required on this host. If so, restrict the management ports (16992-16995, 623, 664) to an isolated management VLAN; if not, unprovision it. Read the control mode (CCM/ACM) with an authenticated WS-Man query to complete the posture picture.".to_string(),
        });
    }

    /// A 200 to an unauthenticated GET (rather than a Digest challenge) is a
    /// direct misconfiguration observation, no bypass required.
    fn unauthenticated_exposure_check(&self, asset: &mut AmtAsset) {
        let Some(http) = &asset.http else { return };
        if http.status_code == Some(200) && !matches!(asset.auth_state, AuthState::Digest) {
            asset.findings.push(Finding {
                title: "Unauthenticated access to AMT management content".to_string(),
                description: "The management interface returned 200 OK to an unauthenticated request instead of a Digest challenge.".to_string(),
                severity: Severity::High,
                cve: None,
                advisory: None,
                state: VulnState::Confirmed,
                evidence: vec![Evidence::new("HTTP status line", http.status_line.clone().unwrap_or_default(), Confidence::High)],
                remediation: "Verify AMT is provisioned with authentication enforced.".to_string(),
            });
        }
    }

    /// Without an authenticated version the version-gated advisories can only be
    /// listed, not judged. One honest reference finding replaces per-CVE guesswork.
    fn cve_reference(&self, asset: &mut AmtAsset) {
        let ids: Vec<&str> = std::iter::once(cve_db::CVE_2017_5689.id)
            .chain(cve_db::all_entries().iter().map(|e| e.id))
            .collect();
        asset.findings.push(Finding {
            title: CVE_REFERENCE_TITLE.to_string(),
            description: format!(
                "Firmware build could not be determined without authentication, so these advisories can be neither confirmed nor excluded from the network alone: {}. Re-run with --active or --amt-user/--amt-pass to read the exact build and resolve them.",
                ids.join(", ")
            ),
            severity: Severity::Info,
            cve: None,
            advisory: None,
            state: VulnState::Insufficient,
            evidence: vec![Evidence::new("Fingerprint engine", "no firmware build observable over unauthenticated probing", Confidence::High)],
            remediation: "Confirm firmware build via authenticated WS-Man or local MEInfo, then patch per the referenced advisories.".to_string(),
        });
    }

    // --------------------------------------------------------
    // Deterministic version correlation (authenticated build only)
    // --------------------------------------------------------

    fn correlate_versioned(&self, asset: &mut AmtAsset, version: &str, source: &str) {
        let already_2017 = asset.findings.iter().any(|f| f.cve.as_deref() == Some("CVE-2017-5689"));
        if !already_2017 && cve_db::evaluate_2017_5689(version) == VersionVerdict::VulnerableRange {
            self.push_versioned(asset, &cve_db::CVE_2017_5689, version, source);
        }
        for entry in cve_db::all_entries() {
            if cve_db::evaluate_generic(entry, version) == VersionVerdict::VulnerableRange {
                self.push_versioned(asset, entry, version, source);
            }
        }
    }

    fn push_versioned(&self, asset: &mut AmtAsset, entry: &CveEntry, version: &str, source: &str) {
        asset.findings.push(Finding {
            title: format!("{} - {}", entry.id, entry.title),
            description: format!(
                "Authenticated firmware build {version} (via {source}) falls within the range affected by {}. {} Reference: {}",
                entry.advisory, entry.summary, entry.reference_url
            ),
            severity: entry.severity(),
            cve: Some(entry.id.to_string()),
            advisory: Some(entry.advisory.to_string()),
            state: VulnState::Confirmed,
            evidence: vec![Evidence::new("Authenticated version comparison", format!("build {version} in affected range for {}", entry.advisory), Confidence::High)],
            remediation: entry.remediation.to_string(),
        });
    }

    // --------------------------------------------------------
    // Protocol hygiene / supporting signals
    // --------------------------------------------------------

    fn tls_findings(&self, asset: &mut AmtAsset) {
        let Some(tls) = asset.tls.clone() else { return };

        if tls.cert_expired == Some(true) {
            asset.findings.push(Finding {
                title: "TLS certificate has expired".to_string(),
                description: format!("The certificate on {}:{} expired on {}.", asset.host, asset.port, tls.cert_not_after.clone().unwrap_or_default()),
                severity: Severity::Medium,
                cve: None,
                advisory: None,
                state: VulnState::Confirmed,
                evidence: vec![Evidence::new("TLS certificate validity", format!("not_after: {}", tls.cert_not_after.clone().unwrap_or_default()), Confidence::High)],
                remediation: "Reissue the management interface's TLS certificate.".to_string(),
            });
        }

        if let Some(version) = &tls.protocol_version {
            if version.contains("SSLv3") || version.contains("TLSv1_0") || version.contains("TLSv1_1") {
                asset.findings.push(Finding {
                    title: "Outdated TLS protocol version negotiated".to_string(),
                    description: format!("The server negotiated {version} rather than TLS 1.2 or newer."),
                    severity: Severity::Medium,
                    cve: None,
                    advisory: None,
                    state: VulnState::Confirmed,
                    evidence: vec![Evidence::new("TLS handshake", version.clone(), Confidence::High)],
                    remediation: "Disable legacy TLS versions on the management interface where the firmware allows it.".to_string(),
                });
            }
        }
    }

    fn rmcp_findings(&self, asset: &mut AmtAsset) {
        let Some(rmcp) = asset.rmcp.clone() else { return };
        if rmcp.responded && rmcp.oem_iana_is_intel == Some(true) {
            asset.findings.push(Finding {
                title: "ASF/RMCP presence-pong consistent with Intel hardware".to_string(),
                description: "An ASF presence ping drew a pong whose OEM IANA Enterprise Number (343) is registered to Intel, supporting evidence for a manageable Intel platform on this segment.".to_string(),
                severity: Severity::Info,
                cve: None,
                advisory: None,
                state: VulnState::Confirmed,
                evidence: vec![Evidence::new("ASF/RMCP presence-pong", format!("raw: {}", rmcp.raw_response_hex.clone().unwrap_or_default()), Confidence::Medium)],
                remediation: "Informational -- correlate with HTTP/HTTPS findings on the same host.".to_string(),
            });
        }
    }

    /// An open redirection port (SOL/IDE-R) is a directly-observed fact and a
    /// strong supporting signal of an active AMT stack, but not conclusive, so
    /// it stays Low and does not flip `amt_detected`.
    fn redirection_finding(&self, asset: &mut AmtAsset) {
        if !matches!(asset.protocol, ProtocolPlane::RedirectionAmt) {
            return;
        }
        asset.findings.push(Finding {
            title: "Intel AMT redirection port open (SOL/IDE-R)".to_string(),
            description: format!(
                "{}:{} accepted a TCP connection on an Intel AMT redirection port, which is generally reachable only when AMT redirection is enabled.",
                asset.host, asset.port
            ),
            severity: Severity::Low,
            cve: None,
            advisory: None,
            state: VulnState::Confirmed,
            evidence: vec![Evidence::new("TCP connect", format!("port {} accepted a connection", asset.port), Confidence::Medium)],
            remediation: "If AMT is not required, unprovision it; otherwise restrict these ports to an isolated management network.".to_string(),
        });
    }
}

fn extract_device_guid(realm: &str) -> Option<String> {
    // Real AMT realm: `Intel(R) AMT (ID:2E736473-EF63-DC11-BFFD-000EA68F75BC)`.
    let start = realm.find("ID:")? + 3;
    let rest = &realm[start..];
    let end = rest.find(')').unwrap_or(rest.len());
    Some(rest[..end].trim().to_string())
}
