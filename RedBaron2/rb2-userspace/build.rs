use std::{env, fs, path::Path, process::Command};

/// eBPF object files expected by `include_bytes!` in the crate
const EXPECTED_EBPF_OBJECTS: &[&str] = &[
    "firewall_events.bpf.o",
    "nfq_firewall.bpf.o",
    "network_capture.bpf.o",
    "https_capture.bpf.o",
    "process_start.bpf.o",
    "auth_pam.bpf.o",
    "tty_view.bpf.o",
];

fn clang_available() -> bool {
    Command::new("clang")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn create_dummy_ebpf_outputs(out_dir: &str) {
    for name in EXPECTED_EBPF_OBJECTS {
        let path = Path::new(out_dir).join(name);
        fs::write(&path, []).expect("Failed to create dummy eBPF output");
    }
}

fn main() {
    let target = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let is_linux = target == "linux";
    let out_dir = env::var("OUT_DIR").unwrap();
    let ebpf_dir = Path::new("../rb2-ebpf");

    // Check if we're in a dependency-only build (common in Nix/Crane builds)
    let is_deps_only = env::var("CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_DEBUG").is_ok()
        || env::var("CRANE_BUILD_DEPS_ONLY").is_ok()
        || !ebpf_dir.exists()
        || !ebpf_dir.join("Makefile").exists();

    // Skip eBPF if explicitly requested (for fmt/clippy without clang)
    let skip_ebpf_env = env::var("RB2_SKIP_EBPF").is_ok();

    // Skip if clang is not available (e.g. minimal dev environment)
    let clang_available = clang_available();

    // Always set up rerun-if-changed for the eBPF directory if it exists
    for file in visit_dir(ebpf_dir) {
        println!("cargo:rerun-if-changed={file}");
    }

    compile_yara_rules(&out_dir);
    compile_rhai_rules(&out_dir);

    let skip_ebpf = !is_linux || is_deps_only || skip_ebpf_env || !clang_available;

    if skip_ebpf {
        let reason = if !is_linux {
            "target is not Linux"
        } else if is_deps_only {
            "dependency-only build or missing eBPF files"
        } else if skip_ebpf_env {
            "RB2_SKIP_EBPF is set"
        } else {
            "clang not found (install clang for full eBPF build)"
        };
        println!("cargo:warning=Skipping eBPF compilation ({reason})");
        create_dummy_ebpf_outputs(&out_dir);
        return;
    }

    // Run the actual eBPF compilation
    println!("cargo:warning=Starting eBPF compilation");

    let output = Command::new("make")
        .arg(format!("OUT_DIR={out_dir}"))
        .current_dir(ebpf_dir)
        .output()
        .expect("Failed to run make");

    let stderr_content = String::from_utf8_lossy(&output.stderr);
    let stdout_content = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "make command failed.\nstdout: {stdout_content}\nstderr: {stderr_content}"
    );

    println!("cargo:warning=eBPF side finished compiling");
}

fn compile_yara_rules(out_dir: &str) {
    let yara_dir = Path::new("../yara_linux");

    if !yara_dir.exists() {
        println!(
            "cargo:warning=YARA rules directory ./yara_linux not found, skipping YARA compilation"
        );
        let output_path = Path::new(out_dir).join("compiled_yara_rules.xz");
        fs::write(&output_path, []).expect("Failed to write empty YARA rules file");
        return;
    }

    println!("cargo:warning=Compiling YARA rules from ./yara_linux");

    // Set up rerun-if-changed for YARA rules
    for file in visit_dir(yara_dir) {
        println!("cargo:rerun-if-changed={file}");
    }

    // Read all YARA rule files and concatenate them
    let mut all_rules = String::new();
    let mut rule_count = 0;

    let mut rule_paths = Vec::new();
    if let Ok(entries) = fs::read_dir(yara_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file()
                && let Some(ext) = path.extension()
                && (ext == "yar" || ext == "yara")
            {
                rule_paths.push(path);
            }
        }
    }

    // Sort paths to ensure deterministic concatenation order
    rule_paths.sort();

    for path in rule_paths {
        match fs::read_to_string(&path) {
            Ok(content) => {
                all_rules.push_str(&content);
                all_rules.push('\n');
                rule_count += 1;
            }
            Err(e) => {
                println!(
                    "cargo:warning=Failed to read YARA rule {}: {e}",
                    path.display()
                );
            }
        }
    }

    // Validate that we have at least one rule
    if rule_count == 0 || all_rules.is_empty() {
        println!(
            "cargo:warning=No YARA rules found in ./yara_linux - binary will have no embedded rules"
        );
        // Create empty compressed file to avoid build errors
        let output_path = Path::new(out_dir).join("compiled_yara_rules.xz");
        fs::write(&output_path, []).expect("Failed to write empty YARA rules file");
        return;
    }

    // Compress the concatenated rules using XZ (level 6 = good balance of speed/ratio)
    let uncompressed_size = all_rules.len();
    let mut compressed_data = Vec::new();
    lzma_rs::lzma_compress(&mut all_rules.as_bytes(), &mut compressed_data)
        .expect("Failed to compress YARA rules");
    let compressed_size = compressed_data.len();

    // Write the compressed rules to a file in OUT_DIR
    let output_path = Path::new(out_dir).join("compiled_yara_rules.xz");
    fs::write(&output_path, compressed_data).expect("Failed to write compressed YARA rules");

    println!(
        "cargo:warning=Compiled {rule_count} YARA rules into binary ({uncompressed_size} bytes -> {compressed_size} bytes, {:.1}% reduction)",
        (1.0 - (compressed_size as f64 / uncompressed_size as f64)) * 100.0
    );
}

fn compile_rhai_rules(out_dir: &str) {
    let rhai_dir = Path::new("../flying-ace-engine/rules");

    if !rhai_dir.exists() {
        println!(
            "cargo:warning=RHAI rules directory not found at {:?}, skipping RHAI rule embedding",
            rhai_dir
        );
        let output_path = Path::new(out_dir).join("compiled_rhai_rules.xz");
        fs::write(&output_path, []).expect("Failed to write empty RHAI rules file");
        return;
    }

    // Set up rerun-if-changed for RHAI rules
    for file in visit_dir(rhai_dir) {
        println!("cargo:rerun-if-changed={file}");
    }

    // Read all YAML rule files and concatenate with a separator
    let mut all_rules = String::new();
    let mut rule_count = 0;

    // Recursively collect YAML files
    fn collect_yaml_files(dir: &Path, paths: &mut Vec<std::path::PathBuf>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    collect_yaml_files(&path, paths);
                } else if path.is_file()
                    && let Some(ext) = path.extension()
                    && (ext == "yaml" || ext == "yml")
                {
                    // Skip unit_test_*.yaml files - those are test-only fixtures
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                        && stem.starts_with("unit_test_")
                    {
                        continue;
                    }
                    paths.push(path);
                }
            }
        }
    }

    let mut rule_paths = Vec::new();
    collect_yaml_files(rhai_dir, &mut rule_paths);

    // Sort for deterministic output
    rule_paths.sort();

    for path in rule_paths {
        match fs::read_to_string(&path) {
            Ok(content) => {
                if !all_rules.is_empty() {
                    // YAML multi-document separator
                    all_rules.push_str("\n---\n");
                }
                all_rules.push_str(&content);
                rule_count += 1;
            }
            Err(e) => {
                println!(
                    "cargo:warning=Failed to read RHAI rule {}: {e}",
                    path.display()
                );
            }
        }
    }

    if rule_count == 0 || all_rules.is_empty() {
        println!("cargo:warning=No RHAI rules found - binary will have no embedded RHAI rules");
        let output_path = Path::new(out_dir).join("compiled_rhai_rules.xz");
        fs::write(&output_path, []).expect("Failed to write empty RHAI rules file");
        return;
    }

    // Compress with XZ
    let uncompressed_size = all_rules.len();
    let mut compressed_data = Vec::new();
    lzma_rs::lzma_compress(&mut all_rules.as_bytes(), &mut compressed_data)
        .expect("Failed to compress RHAI rules");
    let compressed_size = compressed_data.len();

    let output_path = Path::new(out_dir).join("compiled_rhai_rules.xz");
    fs::write(&output_path, compressed_data).expect("Failed to write compressed RHAI rules");

    println!(
        "cargo:warning=Compiled {rule_count} RHAI rules into binary ({uncompressed_size} bytes -> {compressed_size} bytes, {:.1}% reduction)",
        (1.0 - (compressed_size as f64 / uncompressed_size as f64)) * 100.0
    );
}

fn visit_dir(dir: &Path) -> Vec<String> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        files.push(dir.display().to_string());
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                files.push(path.display().to_string());
            } else if path.is_dir() {
                // don't rebuild if libbpf changes
                if path.file_name().unwrap() != "libbpf" {
                    files.extend(visit_dir(&path));
                }
            }
        }
    }
    files
}
