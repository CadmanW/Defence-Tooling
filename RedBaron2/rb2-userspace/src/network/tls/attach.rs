use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use aya::programs::UProbe;
use aya::{Ebpf, EbpfLoader};
use log::{debug, info, warn};

use super::event::TlsLibrary;

#[derive(Debug, Clone, Copy)]
struct ProbePair {
    enter_program: &'static str,
    exit_program: &'static str,
    symbol: &'static str,
    optional: bool,
}

#[derive(Debug, Clone, Copy)]
struct LibraryDefinition {
    kind: TlsLibrary,
    file_prefixes: &'static [&'static str],
    probes: &'static [ProbePair],
}

#[derive(Debug, Clone)]
struct DetectedLibrary {
    definition: &'static LibraryDefinition,
    path: PathBuf,
    matched_symbols: HashSet<&'static str>,
}

const OPENSSL_PROBES: &[ProbePair] = &[
    ProbePair {
        enter_program: "handle_openssl_write_enter",
        exit_program: "handle_openssl_write_exit",
        symbol: "SSL_write",
        optional: false,
    },
    ProbePair {
        enter_program: "handle_openssl_write_ex_enter",
        exit_program: "handle_openssl_write_ex_exit",
        symbol: "SSL_write_ex",
        optional: true,
    },
];

const GNUTLS_PROBES: &[ProbePair] = &[ProbePair {
    enter_program: "handle_gnutls_record_send_enter",
    exit_program: "handle_gnutls_record_send_exit",
    symbol: "gnutls_record_send",
    optional: false,
}];

const NSS_PROBES: &[ProbePair] = &[
    ProbePair {
        enter_program: "handle_nss_pr_write_enter",
        exit_program: "handle_nss_pr_write_exit",
        symbol: "PR_Write",
        optional: false,
    },
    ProbePair {
        enter_program: "handle_nss_pr_send_enter",
        exit_program: "handle_nss_pr_send_exit",
        symbol: "PR_Send",
        optional: false,
    },
];

const SEARCH_ROOTS: &[&str] = &[
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/lib",
    "/usr/local/lib64",
];

const LIBRARIES: &[LibraryDefinition] = &[
    LibraryDefinition {
        kind: TlsLibrary::OpenSsl,
        file_prefixes: &["libssl.so"],
        probes: OPENSSL_PROBES,
    },
    LibraryDefinition {
        kind: TlsLibrary::GnuTls,
        file_prefixes: &["libgnutls.so"],
        probes: GNUTLS_PROBES,
    },
    LibraryDefinition {
        kind: TlsLibrary::Nss,
        file_prefixes: &["libnspr4.so"],
        probes: NSS_PROBES,
    },
];

fn path_matches_prefixes(path: &Path, prefixes: &[&str]) -> bool {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };

    prefixes.iter().any(|prefix| {
        file_name == *prefix
            || file_name
                .strip_prefix(prefix)
                .is_some_and(|suffix| suffix.starts_with('.'))
    })
}

fn canonicalized_insert(seen: &mut HashSet<PathBuf>, path: PathBuf) -> bool {
    let canonical = fs::canonicalize(&path).unwrap_or(path);
    seen.insert(canonical)
}

fn collect_search_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut seen = HashSet::new();

    if let Some(paths) = env::var_os("LD_LIBRARY_PATH") {
        for path in env::split_paths(&paths) {
            if path.is_absolute() && path.is_dir() && canonicalized_insert(&mut seen, path.clone())
            {
                roots.push(path);
            }
        }
    }

    for root in SEARCH_ROOTS {
        let root = PathBuf::from(root);
        if !root.is_dir() {
            continue;
        }

        if canonicalized_insert(&mut seen, root.clone()) {
            roots.push(root.clone());
        }

        if let Ok(entries) = fs::read_dir(&root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && canonicalized_insert(&mut seen, path.clone()) {
                    roots.push(path);
                }
            }
        }
    }

    roots
}

fn collect_directory_candidates(
    definition: &LibraryDefinition,
    seen: &mut HashSet<PathBuf>,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    for root in collect_search_roots() {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() || !path_matches_prefixes(&path, definition.file_prefixes) {
                continue;
            }

            if canonicalized_insert(seen, path.clone()) {
                candidates.push(path);
            }
        }
    }

    candidates
}

fn file_contains_probe_strings(
    path: &Path,
    probes: &[ProbePair],
) -> anyhow::Result<HashSet<&'static str>> {
    let bytes =
        fs::read(path).with_context(|| format!("read library candidate {}", path.display()))?;
    let mut found = HashSet::new();

    for probe in probes {
        if bytes
            .windows(probe.symbol.len())
            .any(|window| window == probe.symbol.as_bytes())
        {
            found.insert(probe.symbol);
        }
    }

    Ok(found)
}

fn detect_libraries() -> Vec<DetectedLibrary> {
    let mut detected = Vec::new();

    for definition in LIBRARIES {
        let mut seen = HashSet::new();
        let candidates = collect_directory_candidates(definition, &mut seen);

        for path in candidates {
            let available_symbols = match file_contains_probe_strings(&path, definition.probes) {
                Ok(symbols) => symbols,
                Err(err) => {
                    debug!("skipping TLS library candidate {}: {err:#}", path.display());
                    continue;
                }
            };

            let missing_required = definition
                .probes
                .iter()
                .filter(|probe| !probe.optional)
                .any(|probe| !available_symbols.contains(probe.symbol));
            if missing_required {
                continue;
            }

            detected.push(DetectedLibrary {
                definition,
                path,
                matched_symbols: available_symbols,
            });
        }
    }

    detected
}

fn attach_probe_pair(
    ebpf: &mut Ebpf,
    library: &DetectedLibrary,
    pair: ProbePair,
) -> anyhow::Result<bool> {
    if !library.matched_symbols.contains(pair.symbol) {
        if pair.optional {
            debug!(
                "skipping optional https symbol {} in {}: string not found",
                pair.symbol,
                library.path.display()
            );
            return Ok(false);
        }

        return Err(anyhow!(
            "required symbol string {} not found in {}",
            pair.symbol,
            library.path.display()
        ));
    }

    let exit_probe: &mut UProbe = ebpf
        .program_mut(pair.exit_program)
        .ok_or_else(|| anyhow!("program {} not found", pair.exit_program))?
        .try_into()?;
    exit_probe.load()?;

    exit_probe
        .attach(Some(pair.symbol), 0, &library.path, None)
        .with_context(|| {
            format!(
                "attach {} to {} ({})",
                pair.exit_program,
                library.path.display(),
                pair.symbol
            )
        })?;

    let enter_probe: &mut UProbe = ebpf
        .program_mut(pair.enter_program)
        .ok_or_else(|| anyhow!("program {} not found", pair.enter_program))?
        .try_into()?;
    enter_probe.load()?;
    enter_probe
        .attach(Some(pair.symbol), 0, &library.path, None)
        .with_context(|| {
            format!(
                "attach {} to {} ({})",
                pair.enter_program,
                library.path.display(),
                pair.symbol
            )
        })?;

    Ok(true)
}

fn attach_library(ebpf: &mut Ebpf, library: &DetectedLibrary) -> bool {
    let mut attached_any = false;
    for pair in library.definition.probes {
        match attach_probe_pair(ebpf, library, *pair) {
            Ok(true) => attached_any = true,
            Ok(false) => {}
            Err(err) => warn!(
                "https capture failed to attach library={} path={} symbol={}: {err:#}",
                library.definition.kind.name(),
                library.path.display(),
                pair.symbol
            ),
        }
    }
    attached_any
}

pub(super) fn load_and_attach_ebpf(
    max_capture_bytes: u32,
) -> anyhow::Result<Option<(Ebpf, Vec<String>)>> {
    let libraries = detect_libraries();
    if libraries.is_empty() {
        warn!("https capture enabled but no supported TLS libraries were detected");
        return Ok(None);
    }

    let mut ebpf = EbpfLoader::new()
        .set_global("max_capture_size", &max_capture_bytes, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/https_capture.bpf.o"
        )))?;

    let mut attached = Vec::new();
    for library in &libraries {
        if attach_library(&mut ebpf, library) {
            info!(
                "https capture attached library={} path={}",
                library.definition.kind.name(),
                library.path.display()
            );
            attached.push(format!(
                "{}:{}",
                library.definition.kind.name(),
                library.path.display()
            ));
        }
    }

    if attached.is_empty() {
        warn!("https capture enabled but no TLS write probes could be attached");
        return Ok(None);
    }

    Ok(Some((ebpf, attached)))
}

#[cfg(test)]
mod tests {
    use super::{OPENSSL_PROBES, path_matches_prefixes};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    fn split_library_path(value: &OsString) -> Vec<PathBuf> {
        std::env::split_paths(value).collect()
    }

    #[test]
    fn prefix_match_handles_versioned_shared_objects() {
        assert!(path_matches_prefixes(
            Path::new("/usr/lib/libssl.so.3"),
            &["libssl.so"]
        ));
        assert!(path_matches_prefixes(
            Path::new("/usr/lib/libssl.so"),
            &["libssl.so"]
        ));
        assert!(!path_matches_prefixes(
            Path::new("/usr/lib/libcrypto.so.3"),
            &["libssl.so"]
        ));
    }

    #[test]
    fn probe_symbols_remain_stable() {
        assert_eq!(OPENSSL_PROBES[0].symbol, "SSL_write");
        assert_eq!(OPENSSL_PROBES[1].symbol, "SSL_write_ex");
    }

    #[test]
    fn ld_library_path_splits_multiple_entries() {
        let raw = OsString::from("/opt/custom/lib:/srv/app/lib64");
        assert_eq!(
            split_library_path(&raw),
            vec![
                PathBuf::from("/opt/custom/lib"),
                PathBuf::from("/srv/app/lib64")
            ]
        );
    }
}
