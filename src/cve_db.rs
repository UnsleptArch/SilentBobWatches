//! Curated table of Intel AMT/ISM firmware advisories from Intel's Security
//! Center, plus the version-range comparison used to judge them.
//!
//! These verdicts require a real firmware build, which is only available from
//! the authenticated active phase. Without it the caller reports `Insufficient`
//! rather than guessing from network fingerprints.

use crate::models::Severity;

pub struct CveEntry {
    pub id: &'static str,
    pub advisory: &'static str,
    pub title: &'static str,
    pub cvss: f32,
    pub summary: &'static str,
    pub reference_url: &'static str,
    pub remediation: &'static str,
    /// (branch prefix e.g. "11.8", fixed-before build number)
    /// A firmware version is considered in-scope for this advisory if its
    /// major.minor branch matches one of these entries, and out of scope
    /// (not covered by this specific advisory) otherwise.
    pub affected_branches: &'static [(&'static str, u32)],
}

impl CveEntry {
    pub fn severity(&self) -> Severity {
        Severity::from_cvss(self.cvss)
    }
}

/// CVE-2017-5689 is special-cased: Intel's fixed builds are identified by a
/// leading build digit of "3" (X.X.XX.3XXX) rather than a simple numeric
/// threshold, so it is handled by `is_pre_2017_5689_fixed` instead of the
/// generic branch-threshold comparison.
pub const CVE_2017_5689: CveEntry = CveEntry {
    id: "CVE-2017-5689",
    advisory: "INTEL-SA-00075",
    title: "Intel AMT / ISM / SBT privilege escalation via network access",
    cvss: 8.4,
    summary: "An unprivileged network attacker may be able to gain control of the manageability features provided by Intel AMT, Intel Standard Manageability, or Intel Small Business Technology on provisioned systems.",
    reference_url: "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00075.html",
    remediation: "Apply the OEM firmware/BIOS update referenced in INTEL-SA-00075, or fully unprovision/disable Intel AMT if it is not required.",
    affected_branches: &[
        ("6", 0), ("7", 0), ("8", 0), ("9", 0), ("10", 0),
        ("11.0", 0), ("11.5", 0), ("11.6", 0),
    ],
};

pub const CVE_2020_0594_0595: CveEntry = CveEntry {
    id: "CVE-2020-0594 / CVE-2020-0595",
    advisory: "INTEL-SA-00295",
    title: "Intel AMT / ISM IPv6 subsystem out-of-bounds read",
    cvss: 9.8,
    summary: "An out-of-bounds read in the IPv6 subsystem of Intel AMT / ISM may allow an unauthenticated network attacker to escalate privileges.",
    reference_url: "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00295.html",
    remediation: "Update to the firmware versions referenced in INTEL-SA-00295 (11.8.77 / 11.12.77 / 11.22.77 / 12.0.64 or later on the matching branch).",
    affected_branches: &[
        ("11.8", 77), ("11.12", 77), ("11.22", 77), ("12.0", 64),
    ],
};

pub const CVE_2020_8758: CveEntry = CveEntry {
    id: "CVE-2020-8758",
    advisory: "Intel Security Advisory (2020) - verify exact INTEL-SA number for your firmware branch",
    title: "Intel AMT / ISM network subsystem improper buffer restriction",
    cvss: 9.8,
    summary: "Improper buffer restrictions in the network subsystem of provisioned Intel AMT / ISM may allow an unauthenticated attacker to escalate privileges via network access.",
    reference_url: "https://www.intel.com/content/www/us/en/security-center/default.html",
    remediation: "Update to the firmware versions that resolve CVE-2020-8758 (11.8.79 / 11.12.79 / 11.22.79 / 12.0.68 / 14.0.39 or later on the matching branch) via your OEM.",
    affected_branches: &[
        ("11.8", 79), ("11.12", 79), ("11.22", 79), ("12.0", 68), ("14.0", 39),
    ],
};

pub const INTEL_SA_00391: CveEntry = CveEntry {
    id: "See INTEL-SA-00391",
    advisory: "INTEL-SA-00391",
    title: "Intel AMT / ISM DHCP subsystem out-of-bounds read",
    cvss: 6.5,
    summary: "An out-of-bounds read in the DHCP subsystem of Intel AMT / ISM may allow an unauthenticated network attacker to trigger information disclosure.",
    reference_url: "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00391.html",
    remediation: "Update to the firmware versions referenced in INTEL-SA-00391 (11.8.80 / 11.12.80 / 11.22.80 / 12.0.70 / 14.0.45 or later on the matching branch).",
    affected_branches: &[
        ("11.8", 80), ("11.12", 80), ("11.22", 80), ("12.0", 70), ("14.0", 45),
    ],
};

pub fn all_entries() -> Vec<&'static CveEntry> {
    vec![&CVE_2020_0594_0595, &CVE_2020_8758, &INTEL_SA_00391]
}

/// Parsed `major.minor.build` firmware hint, e.g. "11.8.50" -> branch "11.8", build 50.
pub struct ParsedVersion {
    pub branch: String,
    pub build: u32,
}

pub fn parse_firmware_hint(hint: &str) -> Option<ParsedVersion> {
    let parts: Vec<&str> = hint.trim().split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let major: u32 = parts[0].parse().ok()?;
    let minor: u32 = parts[1].parse().ok()?;
    let build: u32 = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);
    Some(ParsedVersion {
        branch: format!("{}.{}", major, minor),
        build,
    })
}

/// Also returns a coarse "major-only" branch (e.g. "11") for advisories like
/// INTEL-SA-00075 that are scoped by whole major version rather than
/// major.minor.
pub fn major_branch(hint: &str) -> Option<String> {
    let major = hint.trim().split('.').next()?;
    Some(major.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionVerdict {
    /// Branch not covered by this advisory at all.
    NotApplicable,
    /// Branch covered, and build is at/after the fixed threshold.
    Fixed,
    /// Branch covered, and build is before the fixed threshold.
    VulnerableRange,
}

pub fn evaluate_generic(entry: &CveEntry, hint: &str) -> VersionVerdict {
    let Some(parsed) = parse_firmware_hint(hint) else {
        return VersionVerdict::NotApplicable;
    };
    for (branch, threshold) in entry.affected_branches {
        if *branch == parsed.branch {
            return if parsed.build < *threshold {
                VersionVerdict::VulnerableRange
            } else {
                VersionVerdict::Fixed
            };
        }
    }
    VersionVerdict::NotApplicable
}

/// CVE-2017-5689 special case: branch is a whole major version (or "11.0"
/// etc for the 11.x line), and "fixed" builds have a 4-digit build number
/// whose leading digit is 3 (e.g. 8.1.71.3608).
pub fn evaluate_2017_5689(hint: &str) -> VersionVerdict {
    let parsed = match parse_firmware_hint(hint) {
        Some(p) => p,
        None => return VersionVerdict::NotApplicable,
    };
    let major = major_branch(hint).unwrap_or_default();
    let in_scope = CVE_2017_5689
        .affected_branches
        .iter()
        .any(|(b, _)| *b == parsed.branch || *b == major);
    if !in_scope {
        return VersionVerdict::NotApplicable;
    }
    let build_str = hint.trim().split('.').nth(3).unwrap_or("");
    if build_str.len() == 4 {
        if let Some(leading) = build_str.chars().next() {
            if leading == '3' {
                return VersionVerdict::Fixed;
            }
        }
    }
    VersionVerdict::VulnerableRange
}
