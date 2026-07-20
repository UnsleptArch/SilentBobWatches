//! silentbobwatches - report.rs
//!
//! Renders scan results into a human-readable report. The same renderer
//! backs both the full-detail log file and the end-of-run terminal print,
//! so what you see on screen when the scan finishes always matches what
//! was written to disk.

use colored::Colorize;
use std::fmt::Write as _;

use crate::models::{AmtAsset, HostStatus, ScanMeta, Severity, VulnState};

pub fn render_summary(meta: &ScanMeta, assets: &[AmtAsset], color: bool) -> String {
    let mut out = String::new();

    let banner = "silentbobwatches - Intel AMT Assessment Report";
    let _ = writeln!(out, "{}", paint(banner, "cyan_bold", color));
    let _ = writeln!(out, "{}", "=".repeat(banner.len()));
    let _ = writeln!(out, "Tool version : {}", meta.version);
    let _ = writeln!(out, "Started      : {}", meta.started_at);
    if let Some(completed) = &meta.completed_at {
        let _ = writeln!(out, "Completed    : {}", completed);
    }
    let _ = writeln!(out, "Target spec  : {}", meta.target_spec);
    let _ = writeln!(
        out,
        "Scope        : {} host(s) x {} port(s) = {} probe(s)",
        meta.total_hosts, meta.total_ports, meta.total_probes
    );
    let _ = writeln!(
        out,
        "Tuning       : concurrency={} connect_timeout={}ms read_timeout={}ms host_timeout={}ms",
        meta.concurrency, meta.connect_timeout_ms, meta.read_timeout_ms, meta.host_timeout_ms
    );
    out.push('\n');

    let responsive = assets.iter().filter(|a| matches!(a.status, HostStatus::Responsive)).count();
    let closed = assets.iter().filter(|a| matches!(a.status, HostStatus::Closed)).count();
    let filtered = assets.iter().filter(|a| matches!(a.status, HostStatus::Filtered)).count();
    let timed_out = assets.iter().filter(|a| matches!(a.status, HostStatus::TimedOut)).count();
    let errored = assets.iter().filter(|a| matches!(a.status, HostStatus::Error)).count();
    let amt_detected = assets.iter().filter(|a| a.amt_detected).count();

    let _ = writeln!(out, "{}", paint("Probe outcomes", "bold", color));
    let _ = writeln!(out, "  Responsive             : {}", responsive);
    let _ = writeln!(out, "  Closed (refused)       : {}", closed);
    let _ = writeln!(out, "  Filtered / no response : {}", filtered);
    let _ = writeln!(out, "  Skipped (time budget)  : {}", timed_out);
    let _ = writeln!(out, "  Errors                 : {}", errored);
    let _ = writeln!(out, "  Intel AMT identified   : {}", paint(&amt_detected.to_string(), "green_bold", color));
    out.push('\n');

    let mut by_sev: Vec<(Severity, usize)> = vec![
        (Severity::Critical, 0),
        (Severity::High, 0),
        (Severity::Medium, 0),
        (Severity::Low, 0),
        (Severity::Info, 0),
    ];
    for asset in assets {
        for finding in &asset.findings {
            for entry in by_sev.iter_mut() {
                if entry.0 == finding.severity {
                    entry.1 += 1;
                }
            }
        }
    }
    let _ = writeln!(out, "{}", paint("Findings by severity", "bold", color));
    for (sev, count) in &by_sev {
        let label = sev.label().to_uppercase();
        let line = format!("  {:<9}: {}", label, count);
        let _ = writeln!(out, "{}", paint(&line, severity_color(*sev), color && *count > 0));
    }

    out
}

pub fn render_asset(asset: &AmtAsset, color: bool, full_detail: bool) -> String {
    let mut out = String::new();
    let header = format!("{}:{}", asset.host, asset.port);
    let _ = writeln!(out, "\n{}", "-".repeat(72));
    let _ = writeln!(
        out,
        "{}  [{}]  {}",
        paint(&header, "bold", color),
        asset.protocol.label(),
        paint(asset.status.label(), status_color(asset.status), color)
    );

    if let Some(ms) = asset.connect_ms {
        let _ = write!(out, "  connect: {}ms", ms);
    }
    let _ = writeln!(out, "  total probe time: {}ms", asset.scan_duration_ms);

    if asset.amt_detected {
        let _ = writeln!(
            out,
            "  {} Intel AMT detected{}",
            paint("[+]", "green_bold", color),
            asset
                .amt_device_guid
                .as_ref()
                .map(|g| format!(" (device ID: {g})"))
                .unwrap_or_default()
        );
    }

    let _ = writeln!(out, "  authentication: {}", asset.auth_state.label());

    if let Some(http) = &asset.http {
        let _ = writeln!(out, "  -- HTTP --");
        if let Some(status_line) = &http.status_line {
            let _ = writeln!(out, "     status       : {}", status_line);
        }
        if let Some(server) = &http.server_header {
            let _ = writeln!(out, "     server header: {}", server);
        }
        if let Some(realm) = &http.digest_realm {
            let _ = writeln!(out, "     digest realm : {}", realm);
        }
        if let Some(title) = &http.page_title {
            let _ = writeln!(out, "     page title   : {}", title);
        }
        if let Some(len) = http.body_length {
            let _ = writeln!(out, "     body length  : {} bytes", len);
        }
        if let Some(rtt) = http.round_trip_ms {
            let _ = writeln!(out, "     round trip   : {}ms", rtt);
        }
        if full_detail {
            if !http.headers.is_empty() {
                let _ = writeln!(out, "     all headers  :");
                let mut keys: Vec<&String> = http.headers.keys().collect();
                keys.sort();
                for k in keys {
                    let _ = writeln!(out, "       {}: {}", k, http.headers[k]);
                }
            }
            if let Some(snippet) = &http.body_snippet {
                if !snippet.trim().is_empty() {
                    let _ = writeln!(out, "     body snippet :");
                    for line in snippet.lines().take(8) {
                        let _ = writeln!(out, "       {}", line);
                    }
                }
            }
        }
    }

    if let Some(tls) = &asset.tls {
        let _ = writeln!(out, "  -- TLS --");
        if let Some(v) = &tls.protocol_version {
            let _ = writeln!(out, "     version        : {}", v);
        }
        if let Some(c) = &tls.cipher_suite {
            let _ = writeln!(out, "     cipher suite   : {}", c);
        }
        if let Some(ms) = tls.handshake_ms {
            let _ = writeln!(out, "     handshake time : {}ms", ms);
        }
        if let Some(subj) = &tls.cert_subject {
            let _ = writeln!(out, "     cert subject   : {}", subj);
        }
        if let Some(iss) = &tls.cert_issuer {
            let _ = writeln!(out, "     cert issuer    : {}", iss);
        }
        if let Some(nb) = &tls.cert_not_before {
            let _ = writeln!(out, "     cert not before: {}", nb);
        }
        if let Some(na) = &tls.cert_not_after {
            let _ = writeln!(out, "     cert not after : {}", na);
        }
        if let Some(days) = tls.cert_days_remaining {
            let _ = writeln!(out, "     cert days left : {}", days);
        }
        if let Some(selfsigned) = tls.cert_likely_self_signed {
            let _ = writeln!(out, "     likely self-signed: {}", selfsigned);
        }
        if full_detail && !tls.cert_subject_alt_names.is_empty() {
            let _ = writeln!(out, "     subject alt names: {}", tls.cert_subject_alt_names.join(", "));
        }
        if let Some(serial) = &tls.cert_serial {
            if full_detail {
                let _ = writeln!(out, "     cert serial    : {}", serial);
            }
        }
    }

    if let Some(rmcp) = &asset.rmcp {
        let _ = writeln!(out, "  -- ASF/RMCP --");
        let _ = writeln!(out, "     responded      : {}", rmcp.responded);
        if let Some(rtt) = rmcp.rtt_ms {
            let _ = writeln!(out, "     rtt            : {}ms", rtt);
        }
        if let Some(oem) = rmcp.oem_iana_enterprise {
            let _ = writeln!(out, "     OEM IANA PEN   : {} (Intel = 343)", oem);
        }
        if full_detail {
            if let Some(hex) = &rmcp.raw_response_hex {
                let _ = writeln!(out, "     raw response   : {}", hex);
            }
        }
    }

    if !asset.notes.is_empty() {
        let _ = writeln!(out, "  notes:");
        for n in &asset.notes {
            let _ = writeln!(out, "     - {}", n);
        }
    }

    if !asset.findings.is_empty() {
        let _ = writeln!(out, "  {}", paint("findings:", "bold", color));
        for finding in &asset.findings {
            let sev_label = finding.severity.label().to_uppercase();
            let _ = writeln!(
                out,
                "    [{}] {}",
                paint(&sev_label, severity_color(finding.severity), color),
                finding.title
            );
            if let Some(cve) = &finding.cve {
                let _ = writeln!(out, "        cve/id     : {}", cve);
            }
            if let Some(advisory) = &finding.advisory {
                let _ = writeln!(out, "        advisory   : {}", advisory);
            }
            let _ = writeln!(out, "        state      : {}", finding.state.label());
            let _ = writeln!(out, "        description: {}", finding.description);
            for ev in &finding.evidence {
                let _ = writeln!(
                    out,
                    "        evidence   : [{}] {}: {}",
                    ev.confidence.label(),
                    ev.source,
                    truncate(&ev.data, 200)
                );
            }
            let _ = writeln!(out, "        remediation: {}", finding.remediation);
        }
    }

    out
}

pub fn render_full(meta: &ScanMeta, assets: &[AmtAsset], color: bool) -> String {
    let mut out = render_summary(meta, assets, color);
    let mut reportable: Vec<&AmtAsset> = assets.iter().filter(|a| a.worth_reporting()).collect();
    reportable.sort_by(|a, b| (&a.host, a.port).cmp(&(&b.host, b.port)));

    if reportable.is_empty() {
        out.push_str("\nNo responsive or noteworthy hosts to report.\n");
        return out;
    }

    let _ = writeln!(out, "\n{}", paint("Per-host detail", "cyan_bold", color));
    for asset in reportable {
        out.push_str(&render_asset(asset, color, true));
    }
    out
}

fn severity_color(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "red_bold",
        Severity::High => "red",
        Severity::Medium => "yellow",
        Severity::Low => "blue",
        Severity::Info => "dim",
    }
}

fn status_color(status: HostStatus) -> &'static str {
    match status {
        HostStatus::Responsive => "green",
        HostStatus::Closed => "dim",
        HostStatus::Filtered => "dim",
        HostStatus::TimedOut => "yellow",
        HostStatus::Error => "red",
    }
}

fn paint(text: &str, style: &str, enabled: bool) -> String {
    if !enabled {
        return text.to_string();
    }
    match style {
        "red" => text.red().to_string(),
        "red_bold" => text.red().bold().to_string(),
        "yellow" => text.yellow().to_string(),
        "green" => text.green().to_string(),
        "green_bold" => text.green().bold().to_string(),
        "blue" => text.blue().to_string(),
        "cyan_bold" => text.cyan().bold().to_string(),
        "bold" => text.bold().to_string(),
        "dim" => text.dimmed().to_string(),
        _ => text.to_string(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('\u{2026}');
        t
    }
}

/// Used by VulnState in a couple of "no findings at all" edge cases.
#[allow(dead_code)]
fn _unused_state_reference(_s: VulnState) {}
