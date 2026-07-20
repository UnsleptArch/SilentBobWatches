//! CLI orchestration: target expansion, the async passive scan, the opt-in
//! active confirmation phase, live progress, and end-of-run reporting.

mod active;
mod analysis;
mod cli;
mod cve_db;
mod logger;
mod models;
mod report;
mod scanner;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use colored::Colorize;
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};

use analysis::AnalysisEngine;
use cli::Cli;
use models::{AmtAsset, ProtocolPlane, ScanMeta};
use scanner::{ScanConfig, ScannerEngine};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.no_color {
        colored::control::set_override(false);
    }

    let quiet = cli.quiet;
    let verbose = cli.verbose;
    let color_enabled = !cli.no_color;

    let hosts = cli::expand_targets(&cli.targets)?;
    let ports = cli::expand_ports(&cli.ports)?;
    let total_hosts = hosts.len();
    let total_ports = ports.len();
    let total_probes = total_hosts * total_ports;

    println!(
        "{}",
        format!("silentbobwatches v{} - {} host(s) x {} port(s) = {} probe(s)", env!("CARGO_PKG_VERSION"), total_hosts, total_ports, total_probes).bold()
    );
    println!("{}", "Passive discovery by default. Active checks are opt-in, read-only, and consent-gated.".dimmed());
    println!();

    // Consent for the active phase is taken up front, before any device is
    // touched, so the operator confirms authorization before the scan runs.
    let active_cfg = cli.active_config();
    let run_active = active_cfg.requested() && active::consent_gate(&active_cfg);
    if active_cfg.requested() && !run_active {
        println!("{}", "Active checks declined; continuing with passive discovery only.".yellow());
    }

    let cfg = ScanConfig {
        connect_timeout: Duration::from_secs(cli.connect_timeout),
        read_timeout: Duration::from_secs(cli.read_timeout),
        host_timeout: Duration::from_secs(cli.host_timeout),
        ..ScanConfig::default()
    };

    let engine = Arc::new(ScannerEngine::new(cfg.clone()));
    let analyzer = Arc::new(AnalysisEngine::new());
    let amt_found = Arc::new(AtomicUsize::new(0));

    let started_at = chrono::Utc::now().to_rfc3339();
    let wall_clock_start = std::time::Instant::now();

    let progress = if quiet {
        None
    } else {
        let pb = ProgressBar::new(total_probes as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:38.cyan/blue}] {pos}/{len} probes ({percent}%) | eta {eta} | {msg}",
            )
            .unwrap()
            .progress_chars("█▓░"),
        );
        pb.enable_steady_tick(Duration::from_millis(120));
        pb.set_message("starting...");
        Some(pb)
    };

    let mut targets: Vec<(String, u16)> = Vec::with_capacity(total_probes);
    for host in &hosts {
        for port in &ports {
            targets.push((host.clone(), *port));
        }
    }

    let mut results: Vec<AmtAsset> = stream::iter(targets.into_iter())
        .map(|(host, port)| {
            let engine = engine.clone();
            let analyzer = analyzer.clone();
            let progress = progress.clone();
            let amt_found = amt_found.clone();
            async move {
                let mut asset = engine.scan_one(host, port).await;
                analyzer.analyze(&mut asset);

                if asset.amt_detected {
                    amt_found.fetch_add(1, Ordering::Relaxed);
                }

                if let Some(pb) = &progress {
                    pb.inc(1);
                    pb.set_message(format!("AMT identified: {}", amt_found.load(Ordering::Relaxed)));
                }

                if !quiet && verbose >= 1 && asset.worth_reporting() {
                    let line = report::render_asset(&asset, color_enabled, verbose >= 2);
                    match &progress {
                        Some(pb) => pb.println(line),
                        None => println!("{line}"),
                    }
                }

                asset
            }
        })
        .buffer_unordered(cli.concurrency.max(1))
        .collect()
        .await;

    if let Some(pb) = &progress {
        pb.finish_and_clear();
    }

    // Active phase: only AMT-detected web planes, only when consented. Run
    // sequentially -- there are few such hosts and this touches devices.
    if run_active {
        let amt_hosts = results.iter().filter(|a| a.amt_detected).count();
        if amt_hosts > 0 && !quiet {
            println!("{}", format!("Active confirmation on {amt_hosts} AMT host(s)...").bold());
        }
        for asset in results.iter_mut().filter(|a| a.amt_detected) {
            let tls = matches!(asset.protocol, ProtocolPlane::HttpsAmt);
            let outcome = active::confirm(&asset.host, asset.port, tls, &active_cfg, &cfg).await;
            analyzer.apply_active(asset, &outcome);
        }
    }

    let completed_at = chrono::Utc::now().to_rfc3339();
    let meta = ScanMeta {
        tool: "silentbobwatches".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        started_at,
        completed_at: Some(completed_at),
        target_spec: cli.targets.clone(),
        total_hosts,
        total_ports,
        total_probes,
        concurrency: cli.concurrency,
        connect_timeout_ms: cli.connect_timeout * 1000,
        read_timeout_ms: cli.read_timeout * 1000,
        host_timeout_ms: cli.host_timeout * 1000,
    };

    let run_logger = logger::RunLogger::init(&cli.log_dir)?;
    let json_path = run_logger.write_json(&meta, &results)?;
    let log_path = run_logger.write_text_log(&meta, &results)?;
    if let Some(extra) = &cli.json {
        run_logger.write_extra_copy(extra, &meta, &results)?;
    }

    // The final report always prints in full, regardless of verbosity.
    println!();
    println!("{}", report::render_full(&meta, &results, color_enabled));
    println!("{}", format!("Scan finished in {:.1}s. Logs written to:", wall_clock_start.elapsed().as_secs_f64()).bold());
    println!("  JSON : {}", json_path.display());
    println!("  Log  : {}", log_path.display());
    if let Some(extra) = &cli.json {
        println!("  Also : {}", extra);
    }

    Ok(())
}
