//! silentbobwatches - logger.rs
//!
//! Owns the on-disk "SilentBobWatchesLogs" evidence folder: creating it if
//! missing, and writing both a machine-readable JSON report and a
//! full-detail human-readable log for every scan run.

use std::fs;
use std::path::{Path, PathBuf};

use crate::models::{AmtAsset, ScanMeta};
use crate::report;

pub struct RunLogger {
    pub dir: PathBuf,
    pub run_stamp: String,
}

impl RunLogger {
    pub fn init(log_dir: &str) -> anyhow::Result<Self> {
        let dir = PathBuf::from(log_dir);
        if !dir.exists() {
            fs::create_dir_all(&dir)
                .map_err(|e| anyhow::anyhow!("could not create log directory {}: {}", dir.display(), e))?;
        }
        let run_stamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
        Ok(RunLogger { dir, run_stamp })
    }

    pub fn json_path(&self) -> PathBuf {
        self.dir.join(format!("scan_{}.json", self.run_stamp))
    }

    pub fn text_log_path(&self) -> PathBuf {
        self.dir.join(format!("scan_{}.log", self.run_stamp))
    }

    pub fn write_json(&self, meta: &ScanMeta, assets: &[AmtAsset]) -> anyhow::Result<PathBuf> {
        let report = crate::models::ScanReport {
            meta: meta.clone(),
            assets: assets.to_vec(),
        };
        let path = self.json_path();
        let text = serde_json::to_string_pretty(&report)?;
        fs::write(&path, text)?;
        Ok(path)
    }

    pub fn write_text_log(&self, meta: &ScanMeta, assets: &[AmtAsset]) -> anyhow::Result<PathBuf> {
        let path = self.text_log_path();
        let text = report::render_full(meta, assets, false);
        fs::write(&path, text)?;
        Ok(path)
    }

    pub fn write_extra_copy(&self, dest: &str, meta: &ScanMeta, assets: &[AmtAsset]) -> anyhow::Result<()> {
        let report = crate::models::ScanReport {
            meta: meta.clone(),
            assets: assets.to_vec(),
        };
        let text = serde_json::to_string_pretty(&report)?;
        let dest_path = Path::new(dest);
        if let Some(parent) = dest_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(dest_path, text)?;
        Ok(())
    }
}
