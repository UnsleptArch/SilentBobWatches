//! Command-line interface and target-list expansion.

use std::fs;
use std::net::IpAddr;
use std::str::FromStr;

use clap::Parser;
use ipnet::IpNet;

use crate::active::ActiveConfig;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "silentbobwatches",
    version,
    about = "Intel AMT discovery, fingerprinting, and evidence-based security assessment",
    long_about = "silentbobwatches performs authorized discovery and fingerprinting of Intel \
AMT / ISM management interfaces. Discovery is passive by default (an HTTP GET, a TLS handshake, \
an ASF/RMCP presence ping). Confirmation is opt-in: with --active it runs the read-only \
CVE-2017-5689 auth-bypass check, and with credentials it reads the firmware build over WS-Man to \
resolve version-gated advisories. Active checks are consent-gated and never change device state. \
It performs no memory-corruption exploitation and no credential guessing."
)]
pub struct Cli {
    /// Target(s): single IP/hostname, CIDR (10.0.0.0/24), comma-separated list,
    /// or @path/to/file.txt (one target per line)
    pub targets: String,

    /// Comma-separated list of ports to probe
    #[arg(long, default_value = "16992,16993,16994,16995,623,664")]
    pub ports: String,

    /// Maximum number of (host, port) probes running at once
    #[arg(long, default_value_t = 200)]
    pub concurrency: usize,

    /// TCP connect timeout, in seconds
    #[arg(long, default_value_t = 3)]
    pub connect_timeout: u64,

    /// Read timeout for an individual request/response, in seconds
    #[arg(long, default_value_t = 5)]
    pub read_timeout: u64,

    /// Hard per-(host,port) time budget, in seconds. If a probe hasn't
    /// finished by this point it is presumed broken/filtered and skipped so
    /// the rest of the scan keeps moving.
    #[arg(long, default_value_t = 12)]
    pub host_timeout: u64,

    /// Increase output verbosity: -v host summaries, -vv full evidence live,
    /// -vvv raw protocol debug detail live. The end-of-scan report is always
    /// written in full detail regardless of this flag.
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Suppress the live progress bar and per-host chatter; only print the
    /// final report
    #[arg(long)]
    pub quiet: bool,

    /// Directory to create for logs and captured evidence
    #[arg(long, default_value = "SilentBobWatchesLogs")]
    pub log_dir: String,

    /// Also write a copy of the final JSON report to this path
    #[arg(long)]
    pub json: Option<String>,

    /// Disable ANSI color in terminal output
    #[arg(long)]
    pub no_color: bool,

    /// Enable the opt-in CVE-2017-5689 auth-bypass check on detected AMT hosts
    /// (read-only; requires consent). Off by default.
    #[arg(long)]
    pub active: bool,

    /// AMT account for authenticated WS-Man version enumeration
    /// (falls back to the AMT_USER environment variable).
    #[arg(long)]
    pub amt_user: Option<String>,

    /// AMT password (falls back to the AMT_PASS environment variable; prefer
    /// the env var to keep it out of shell history).
    #[arg(long)]
    pub amt_pass: Option<String>,

    /// Skip the interactive consent prompt for active checks. Only use this on
    /// runs you have already confirmed are authorized.
    #[arg(long)]
    pub yes: bool,
}

impl Cli {
    /// Resolves the active-mode configuration, taking credentials from flags or
    /// the AMT_USER/AMT_PASS environment variables.
    pub fn active_config(&self) -> ActiveConfig {
        let user = self.amt_user.clone().or_else(|| std::env::var("AMT_USER").ok());
        let pass = self.amt_pass.clone().or_else(|| std::env::var("AMT_PASS").ok());
        let creds = match (user, pass) {
            (Some(u), Some(p)) => Some((u, p)),
            _ => None,
        };
        ActiveConfig {
            enabled: self.active,
            creds,
            assume_yes: self.yes,
        }
    }
}

pub fn expand_ports(spec: &str) -> anyhow::Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        ports.push(part.parse::<u16>().map_err(|_| anyhow::anyhow!("invalid port: {part}"))?);
    }
    if ports.is_empty() {
        anyhow::bail!("no ports specified");
    }
    Ok(ports)
}

pub fn expand_targets(spec: &str) -> anyhow::Result<Vec<String>> {
    let raw = if let Some(path) = spec.strip_prefix('@') {
        fs::read_to_string(path).map_err(|e| anyhow::anyhow!("could not read target file {path}: {e}"))?
    } else {
        spec.to_string()
    };

    let mut hosts = Vec::new();
    for item in raw.split(|c| c == ',' || c == '\n') {
        let item = item.trim();
        if item.is_empty() || item.starts_with('#') {
            continue;
        }

        if item.contains('/') {
            match IpNet::from_str(item) {
                Ok(net) => {
                    for ip in net.hosts() {
                        hosts.push(ip.to_string());
                    }
                }
                Err(e) => anyhow::bail!("invalid CIDR '{item}': {e}"),
            }
        } else if item.contains('-') && item.parse::<IpAddr>().is_err() {
            // Simple "a.b.c.d-e" last-octet range support.
            if let Some(expanded) = expand_dash_range(item) {
                hosts.extend(expanded);
            } else {
                hosts.push(item.to_string());
            }
        } else {
            hosts.push(item.to_string());
        }
    }

    if hosts.is_empty() {
        anyhow::bail!("no targets resolved from input");
    }
    Ok(hosts)
}

fn expand_dash_range(item: &str) -> Option<Vec<String>> {
    let (base, range_end) = item.rsplit_once('-')?;
    let mut octets: Vec<&str> = base.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let start: u8 = octets[3].parse().ok()?;
    let end: u8 = range_end.parse().ok()?;
    if end < start {
        return None;
    }
    let prefix = format!("{}.{}.{}", octets[0], octets[1], octets[2]);
    octets.clear();
    Some((start..=end).map(|o| format!("{prefix}.{o}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_ports_parses_and_trims() {
        assert_eq!(expand_ports("16992,16993,623").unwrap(), vec![16992, 16993, 623]);
        assert_eq!(expand_ports(" 80 , 443 ").unwrap(), vec![80, 443]);
    }

    #[test]
    fn expand_ports_rejects_empty_and_garbage() {
        assert!(expand_ports("").is_err());
        assert!(expand_ports("abc").is_err());
        assert!(expand_ports("70000").is_err()); // out of u16 range
    }

    #[test]
    fn expand_targets_single_and_list() {
        assert_eq!(expand_targets("10.0.0.5").unwrap(), vec!["10.0.0.5"]);
        assert_eq!(expand_targets("10.0.0.1,10.0.0.2").unwrap(), vec!["10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn expand_targets_skips_comments_and_blanks() {
        assert_eq!(expand_targets("# a comment\n10.0.0.9\n\n").unwrap(), vec!["10.0.0.9"]);
    }

    #[test]
    fn expand_targets_dash_range() {
        assert_eq!(
            expand_targets("10.0.0.10-12").unwrap(),
            vec!["10.0.0.10", "10.0.0.11", "10.0.0.12"]
        );
    }

    #[test]
    fn expand_targets_cidr_yields_usable_hosts() {
        // /30 has two usable host addresses (.1 and .2).
        assert_eq!(expand_targets("10.0.0.0/30").unwrap(), vec!["10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn dash_range_rejects_bad_input() {
        assert!(expand_dash_range("10.0.0.10-9").is_none()); // end < start
        assert!(expand_dash_range("bad-range").is_none()); // not four octets
    }
}
