use log::{debug, error, warn};
use reqwest::Client;
use std::error::Error as StdError;
use std::fmt;
use std::path::{Path, PathBuf};
use tar::Archive;
use tokio::fs;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

const INSTALL_PATH: &str = "/var/cache/downloaded.btf";
const DOWNLOAD_PATH: &str = "/var/cache/downloaded.btf.tar.xz";
const SYS_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
const OS_RELEASE_PATH: &str = "/etc/os-release";
const BTFHUB_URL_BASE: &str = "https://raw.githubusercontent.com/aquasecurity/btfhub-archive/main";

#[derive(Debug)]
pub enum BtfError {
    Io(io::Error),
    HttpStatus(u16),
    HttpRequest(String),
    EmptyArchive,
    SystemInfo(String),
    UnsupportedDistro(String),
    Utf8Error(std::string::FromUtf8Error),
}

impl fmt::Display for BtfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "IO error: {err}"),
            Self::HttpStatus(status) => write!(f, "HTTP error: status {status}"),
            Self::HttpRequest(msg) => write!(f, "HTTP request error: {msg}"),
            Self::EmptyArchive => write!(f, "No files found in BTF archive"),
            Self::SystemInfo(msg) => write!(f, "Failed to detect system info: {msg}"),
            Self::UnsupportedDistro(name) => write!(f, "Unsupported distribution: {name}"),
            Self::Utf8Error(err) => write!(f, "UTF-8 conversion error: {err}"),
        }
    }
}

impl StdError for BtfError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Utf8Error(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for BtfError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<std::string::FromUtf8Error> for BtfError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Self::Utf8Error(err)
    }
}

impl From<reqwest::Error> for BtfError {
    fn from(err: reqwest::Error) -> Self {
        Self::HttpRequest(err.to_string())
    }
}

/// Returns the path to an available BTF file, downloading it if necessary
pub async fn get_btf_file() -> Result<PathBuf, BtfError> {
    // Check if system BTF file exists
    let sys_btf = Path::new(SYS_BTF_PATH);
    if fs::try_exists(sys_btf).await.unwrap_or(false) {
        debug!("Using system BTF: {SYS_BTF_PATH}");
        return Ok(sys_btf.to_path_buf());
    }

    // Check if cached BTF file exists
    let install_path = Path::new(INSTALL_PATH);
    if fs::try_exists(install_path).await.unwrap_or(false) {
        debug!("Using cached BTF: {INSTALL_PATH}");
        return Ok(install_path.to_path_buf());
    }

    // Download and extract BTF file
    let url = get_url().await?;
    debug!("Downloading BTF archive: {url}");

    if let Err(e) = download_btf(&url).await {
        error!("Failed to download BTF archive from {url}: {e}");
        // best-effort cleanup
        let _ = fs::remove_file(DOWNLOAD_PATH).await;
        return Err(e);
    }

    if let Err(e) = extract_btf().await {
        error!("Failed to extract BTF archive {DOWNLOAD_PATH} -> {INSTALL_PATH}: {e}");
        // best-effort cleanup
        let _ = fs::remove_file(DOWNLOAD_PATH).await;
        return Err(e);
    }

    // Clean up the archive file (best-effort)
    if let Err(e) = fs::remove_file(DOWNLOAD_PATH).await {
        warn!("Failed to remove archive {DOWNLOAD_PATH}: {e}");
    }

    Ok(install_path.to_path_buf())
}

/// Downloads the BTF file from the given URL
async fn download_btf(url: &str) -> Result<(), BtfError> {
    let client = Client::builder()
        .user_agent("btf-fetch/1.0")
        .build()
        .map_err(BtfError::from)?;

    let resp = client.get(url).send().await?;

    let status = resp.status();
    if !status.is_success() {
        let status_code = status.as_u16();
        error!("BTF download returned HTTP {status_code}");
        return Err(BtfError::HttpStatus(status_code));
    }

    // Ensure parent dir exists
    if let Some(parent) = Path::new(DOWNLOAD_PATH).parent() {
        fs::create_dir_all(parent).await?;
    }

    let mut file = fs::File::create(DOWNLOAD_PATH).await?;

    let bytes = resp.bytes().await.map_err(BtfError::from)?;
    file.write_all(&bytes).await?;

    file.flush().await?;
    Ok(())
}

/// Extracts the BTF file from the downloaded archive
async fn extract_btf() -> Result<(), BtfError> {
    // Create parent directory if it doesn't exist
    if let Some(parent) = Path::new(INSTALL_PATH).parent() {
        fs::create_dir_all(parent).await?;
    }

    // Decompression + tar are blocking; run them on blocking pool.
    tokio::task::spawn_blocking(|| -> Result<(), BtfError> {
        use std::fs::File;
        use std::io::copy;

        let file = File::open(DOWNLOAD_PATH)?;
        let mut decompressed = Vec::new();
        lzma_rs::xz_decompress(&mut std::io::BufReader::new(file), &mut decompressed)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let mut archive = Archive::new(std::io::Cursor::new(decompressed));

        let mut entries = archive.entries()?;
        if let Some(entry) = entries.next() {
            let mut entry = entry?;
            let mut output_file = File::create(INSTALL_PATH)?;
            copy(&mut entry, &mut output_file)?;
            Ok(())
        } else {
            Err(BtfError::EmptyArchive)
        }
    })
    .await
    .map_err(|e| {
        error!("Join error extracting archive: {e}");
        BtfError::SystemInfo(format!("join error extracting archive: {e}"))
    })??;

    Ok(())
}

/// Detect the appropriate BTF download URL
async fn get_url() -> Result<String, BtfError> {
    let (distro, release) = get_distro_and_release().await?.ok_or_else(|| {
        error!("Could not determine Linux distribution info from {OS_RELEASE_PATH}");
        BtfError::SystemInfo("Could not determine Linux distribution info".to_string())
    })?;

    let distro = check_distro_support(&distro).ok_or_else(|| {
        error!("Unsupported distribution for BTF fetching: {distro}");
        BtfError::UnsupportedDistro(distro)
    })?;

    let arch = get_architecture().await?.unwrap_or_else(|| {
        warn!("Unknown/unsupported arch for BTF fetching, defaulting to x86_64");
        "x86_64".to_string()
    });

    let kernel = get_kernel_version().await?.ok_or_else(|| {
        error!("Unknown/no kernel version found via uname -r");
        BtfError::SystemInfo("Unknown/no kernel version found".to_string())
    })?;

    Ok(format!(
        "{BTFHUB_URL_BASE}/{distro}/{release}/{arch}/{kernel}.btf.tar.xz"
    ))
}

fn check_distro_support(distro: &str) -> Option<String> {
    let supported_distros = [
        "amzn", "centos", "debian", "fedora", "ol", "rhel", "sles", "ubuntu",
    ];
    supported_distros
        .contains(&distro)
        .then(|| distro.to_string())
}

async fn get_os_release_field(field: &str) -> Result<Option<String>, BtfError> {
    let file = match fs::File::open(OS_RELEASE_PATH).await {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            warn!("{OS_RELEASE_PATH} not found; cannot detect distro");
            return Ok(None);
        }
        Err(e) => {
            error!("Failed to open {OS_RELEASE_PATH}: {e}");
            return Err(BtfError::Io(e));
        }
    };

    let mut lines = BufReader::new(file).lines();

    while let Some(line) = lines.next_line().await? {
        if let Some((key, value)) = line.split_once('=')
            && key == field
        {
            return Ok(Some(value.trim_matches('"').to_string()));
        }
    }

    Ok(None)
}

async fn get_distro_and_release() -> Result<Option<(String, String)>, BtfError> {
    let id = match get_os_release_field("ID").await? {
        Some(v) => v,
        None => return Ok(None),
    };
    let version_id = match get_os_release_field("VERSION_ID").await? {
        Some(v) => v,
        None => return Ok(None),
    };

    // Validate version ID format
    if !version_id.chars().all(|c| c.is_ascii_digit() || c == '.') {
        warn!("VERSION_ID '{version_id}' contains invalid characters");
        return Ok(None);
    }

    Ok(Some((id, version_id)))
}

async fn get_architecture() -> Result<Option<String>, BtfError> {
    let out = Command::new("uname").arg("-m").output().await?;
    if !out.status.success() {
        warn!("uname -m returned non-zero status");
        return Ok(None);
    }

    let arch = String::from_utf8(out.stdout)?.trim().to_string();
    match arch.as_str() {
        "x86_64" | "arm64" => Ok(Some(arch)),
        _ => {
            warn!("Unsupported architecture '{arch}'");
            Ok(None)
        }
    }
}

async fn get_kernel_version() -> Result<Option<String>, BtfError> {
    let out = Command::new("uname").arg("-r").output().await?;
    if !out.status.success() {
        warn!("uname -r returned non-zero status");
        return Ok(None);
    }

    Ok(Some(String::from_utf8(out.stdout)?.trim().to_string()))
}
