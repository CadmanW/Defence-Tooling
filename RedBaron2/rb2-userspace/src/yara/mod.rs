#[cfg(target_os = "linux")]
pub mod fanotify;
mod helper;
#[cfg(target_os = "linux")]
pub mod yara_scan;

pub use helper::handle_yara_match;

#[cfg(target_os = "linux")]
use self::fanotify::yara_init_fanotify_scan;
#[cfg(target_os = "linux")]
use self::yara_scan::yara_init_memory_scan;

#[cfg(target_os = "linux")]
use crate::config::yaml::YaraConfig;

use anyhow::Context;
#[cfg(target_os = "linux")]
use log::error;
use log::{debug, info, warn};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::thread;
use std::{
    fs::{self},
    path::PathBuf,
};
#[cfg(target_os = "linux")]
use tokio::sync::watch;
use yara_x::{Compiler, Rules};

#[cfg(target_os = "linux")]
pub type YaraFanotifyHandle = thread::JoinHandle<()>;

pub fn build_rules(
    disable_bundled_rules: bool,
    rules_dir: &Option<PathBuf>,
) -> anyhow::Result<Rules> {
    let mut compiler = Compiler::new();

    // bundled rules
    if !disable_bundled_rules {
        const EMBEDDED_RULES_COMPRESSED: &[u8] =
            include_bytes!(concat!(env!("OUT_DIR"), "/compiled_yara_rules.xz"));

        debug!("Loading and decompressing embedded YARA rules from build");

        let mut embedded_rules_bytes = Vec::new();
        lzma_rs::lzma_decompress(
            &mut std::io::BufReader::new(EMBEDDED_RULES_COMPRESSED),
            &mut embedded_rules_bytes,
        )
        .context("Failed to decompress embedded YARA rules")?;
        let embedded_rules = String::from_utf8(embedded_rules_bytes)
            .context("Embedded YARA rules not valid UTF-8")?;

        if !embedded_rules.is_empty() {
            compiler.add_source(embedded_rules.as_str())?;
        } else {
            info!("No embedded YARA rules found in binary");
        }
    } else {
        info!("Bundled YARA rules disabled via config");
    }

    // extra rules
    if let Some(dir) = rules_dir {
        if dir.exists() {
            info!("Loading additional YARA rules from: {}", dir.display());
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if let Some(ext) = path.extension().and_then(|s| s.to_str())
                    && (ext == "yara" || ext == "yar")
                {
                    let source = fs::read_to_string(&path)?;
                    compiler.add_source(source.as_str())?;
                }
            }
        } else {
            warn!("Rules directory {} does not exist, skipping", dir.display());
        }
    }

    if rules_dir.is_none() && disable_bundled_rules {
        Err(anyhow::anyhow!("No yara rules provided to scan"))
    } else {
        Ok(compiler.build())
    }
}

#[cfg(target_os = "linux")]
pub fn yara_init_scan(
    cfg: &YaraConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<Option<YaraFanotifyHandle>> {
    let rules = build_rules(cfg.disable_bundled_rules, &cfg.rules_dir)?;
    let rules = Arc::new(rules);
    {
        let rules = rules.clone();
        let cfg = cfg.clone();
        let shutdown_rx = shutdown_rx.clone();
        thread::spawn(move || {
            const YARA_NICE_LEVEL: i32 = 10;
            unsafe { libc::nice(YARA_NICE_LEVEL) };
            let actual_nice = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
            debug!(
                "YARA memory scanning thread running with nice level {}",
                actual_nice
            );

            if let Err(e) = yara_init_memory_scan(&cfg, &rules, shutdown_rx) {
                error!("YARA memory scanning failed: {}", e);
            }
        });
    }
    let fanotify_handle = if cfg.fanotify_enabled {
        let rules = rules;
        let cfg = cfg.clone();
        let shutdown_rx = shutdown_rx.clone();
        let handle = thread::spawn(move || {
            if let Err(e) = yara_init_fanotify_scan(&cfg, &rules, shutdown_rx) {
                error!("YARA fanotify scanning failed: {}", e);
            }
        });
        Some(handle)
    } else {
        info!("Fanotify disabled by config");
        None
    };

    Ok(fanotify_handle)
}
