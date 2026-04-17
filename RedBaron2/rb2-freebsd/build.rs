use std::{fs, path::Path};

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    compile_rhai_rules(&out_dir);
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

    for file in visit_dir(rhai_dir) {
        println!("cargo:rerun-if-changed={file}");
    }

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
    rule_paths.sort();

    let mut all_rules = String::new();
    let mut rule_count = 0;
    for path in rule_paths {
        match fs::read_to_string(&path) {
            Ok(content) => {
                if !all_rules.is_empty() {
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
                files.extend(visit_dir(&path));
            }
        }
    }
    files
}
