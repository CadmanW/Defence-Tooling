use anyhow::{Context, anyhow};
use aya::maps::{MapData, RingBuf};
use aya::programs::UProbe;
use aya::{Btf, Ebpf, EbpfLoader, Endianness};
use std::path::{Path, PathBuf};
use tokio::io::unix::AsyncFd;

const TASK_COMM_LEN: usize = 16;
const AUTH_STR_LEN: usize = 48;

pub const AUTH_RC_UNSET: i32 = -1000000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PamStage {
    Start,
    GetUser,
    Authenticate,
    AcctMgmt,
    OpenSession,
    CloseSession,
    End,
    Unknown(i32),
}

impl PamStage {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Start => "pam_start",
            Self::GetUser => "pam_get_user",
            Self::Authenticate => "pam_authenticate",
            Self::AcctMgmt => "pam_acct_mgmt",
            Self::OpenSession => "pam_open_session",
            Self::CloseSession => "pam_close_session",
            Self::End => "pam_end",
            Self::Unknown(_) => "unknown",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::End)
    }

    pub const fn is_session(self) -> bool {
        matches!(self, Self::OpenSession | Self::CloseSession)
    }
}

impl From<i32> for PamStage {
    fn from(value: i32) -> Self {
        match value {
            1 => Self::Start,
            2 => Self::GetUser,
            3 => Self::Authenticate,
            4 => Self::AcctMgmt,
            5 => Self::OpenSession,
            6 => Self::CloseSession,
            7 => Self::End,
            _ => Self::Unknown(value),
        }
    }
}

const COMMON_LIBPAM_PATHS: &[&str] = &[
    "/lib/x86_64-linux-gnu/libpam.so.0",
    "/usr/lib/x86_64-linux-gnu/libpam.so.0",
    "/lib64/libpam.so.0",
    "/usr/lib64/libpam.so.0",
    "/lib/libpam.so.0",
    "/usr/lib/libpam.so.0",
];

#[repr(C)]
#[derive(Clone, Copy)]
struct AuthEvent {
    ts_ns: u64,
    pamh: u64,
    pid: u32,
    tgid: u32,
    audit_loginuid: u32,
    audit_sessionid: u32,
    stage: i32,
    rc: i32,
    auth_rc: i32,
    acct_rc: i32,
    session_rc: i32,
    session_opened: u8,
    comm: [u8; TASK_COMM_LEN],
    service: [u8; AUTH_STR_LEN],
    requested_user: [u8; AUTH_STR_LEN],
    resolved_user: [u8; AUTH_STR_LEN],
    rhost: [u8; AUTH_STR_LEN],
    ruser: [u8; AUTH_STR_LEN],
    tty: [u8; AUTH_STR_LEN],
}

#[derive(Debug, Clone)]
pub struct ParsedAuthEvent {
    pub pamh: u64,
    pub pid: u32,
    pub tgid: u32,
    pub audit_loginuid: u32,
    pub audit_sessionid: u32,
    pub stage: PamStage,
    pub rc: i32,
    pub auth_rc: i32,
    pub acct_rc: i32,
    pub session_rc: i32,
    pub session_opened: bool,
    pub comm: String,
    pub service: String,
    pub requested_user: String,
    pub resolved_user: String,
    pub rhost: String,
    pub ruser: String,
    pub tty: String,
}

const ATTACH_SPECS: &[(&str, &str)] = &[
    ("handle_pam_start_enter", "pam_start"),
    ("handle_pam_start_exit", "pam_start"),
    ("handle_pam_set_item_enter", "pam_set_item"),
    ("handle_pam_set_item_exit", "pam_set_item"),
    ("handle_pam_get_user_enter", "pam_get_user"),
    ("handle_pam_get_user_exit", "pam_get_user"),
    ("handle_pam_authenticate_enter", "pam_authenticate"),
    ("handle_pam_authenticate_exit", "pam_authenticate"),
    ("handle_pam_acct_mgmt_enter", "pam_acct_mgmt"),
    ("handle_pam_acct_mgmt_exit", "pam_acct_mgmt"),
    ("handle_pam_open_session_enter", "pam_open_session"),
    ("handle_pam_open_session_exit", "pam_open_session"),
    ("handle_pam_close_session_enter", "pam_close_session"),
    ("handle_pam_close_session_exit", "pam_close_session"),
    ("handle_pam_end_enter", "pam_end"),
    ("handle_pam_end_exit", "pam_end"),
];

fn decode_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).trim().to_string()
}

pub fn parse_auth_event(bytes: &[u8]) -> anyhow::Result<ParsedAuthEvent> {
    let need = std::mem::size_of::<AuthEvent>();
    if bytes.len() < need {
        return Err(anyhow!(
            "short auth event: got {} bytes need {}",
            bytes.len(),
            need
        ));
    }

    let raw = unsafe {
        let mut uninit = std::mem::MaybeUninit::<AuthEvent>::uninit();
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), uninit.as_mut_ptr() as *mut u8, need);
        uninit.assume_init()
    };

    Ok(ParsedAuthEvent {
        pamh: raw.pamh,
        pid: raw.pid,
        tgid: raw.tgid,
        audit_loginuid: raw.audit_loginuid,
        audit_sessionid: raw.audit_sessionid,
        stage: PamStage::from(raw.stage),
        rc: raw.rc,
        auth_rc: raw.auth_rc,
        acct_rc: raw.acct_rc,
        session_rc: raw.session_rc,
        session_opened: raw.session_opened != 0,
        comm: decode_string(&raw.comm),
        service: decode_string(&raw.service),
        requested_user: decode_string(&raw.requested_user),
        resolved_user: decode_string(&raw.resolved_user),
        rhost: decode_string(&raw.rhost),
        ruser: decode_string(&raw.ruser),
        tty: decode_string(&raw.tty),
    })
}

fn detect_libpam_path() -> Option<PathBuf> {
    COMMON_LIBPAM_PATHS
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

fn attach_probes(ebpf: &mut Ebpf, libpam_path: &Path) -> anyhow::Result<()> {
    for (prog_name, symbol) in ATTACH_SPECS {
        let probe: &mut UProbe = ebpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow!("program {prog_name} not found"))?
            .try_into()?;
        probe.load()?;
        probe
            .attach(Some(symbol), 0, libpam_path, None)
            .with_context(|| format!("attach {prog_name} to {}", libpam_path.display()))?;
    }
    Ok(())
}

pub async fn load_and_attach_ebpf<P: AsRef<Path>>(
    btf_file_path: P,
    libpam_path: Option<&Path>,
) -> anyhow::Result<Ebpf> {
    let btf = Btf::parse_file(btf_file_path.as_ref(), Endianness::default())
        .context("parse BTF for auth collector")?;

    let libpam_path = libpam_path
        .map(PathBuf::from)
        .or_else(detect_libpam_path)
        .ok_or_else(|| anyhow!("could not auto-detect libpam.so.0; set auth.libpam_path"))?;

    let mut ebpf = EbpfLoader::new()
        .btf(Some(&btf))
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/auth_pam.bpf.o"
        )))?;

    attach_probes(&mut ebpf, &libpam_path)?;
    Ok(ebpf)
}

pub fn take_ringbuf_asyncfd(mut ebpf: Ebpf) -> anyhow::Result<(AsyncFd<RingBuf<MapData>>, Ebpf)> {
    let map = ebpf
        .take_map("events")
        .context("auth ringbuf map not found (Ebpf::take_map)")?;

    let ring: RingBuf<MapData> =
        RingBuf::try_from(map).context("failed to convert auth map to RingBuf")?;
    let afd = AsyncFd::new(ring).context("failed to wrap auth RingBuf in AsyncFd")?;

    Ok((afd, ebpf))
}
