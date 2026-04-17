use crate::{ProcessEvent, RuleMode};
use serde::Deserialize;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

pub type FixtureResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Debug, Deserialize)]
pub struct RuleTestCase {
    pub cleartext: String,
    #[serde(default)]
    pub process_name: Option<String>,
    #[serde(default)]
    pub process_args: Option<String>,
    #[serde(default)]
    pub process_executable: Option<String>,
    #[serde(default)]
    pub process_pname: Option<String>,
    #[serde(default)]
    pub process_ppid: Option<u32>,
    #[serde(default)]
    pub process_working_directory: Option<String>,
    #[serde(default)]
    pub user_name: Option<String>,
    #[serde(default)]
    pub user_id: Option<u32>,
    #[serde(default)]
    pub event_category: Option<String>,
    pub should_match: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RuleFixture {
    #[serde(skip)]
    pub path: PathBuf,
    pub name: String,
    #[serde(default)]
    pub mode: RuleMode,
    pub eval: String,
    #[serde(default)]
    pub overlap_allowed_with: Vec<String>,
    #[serde(default)]
    pub tests: Vec<RuleTestCase>,
}

pub fn base_event() -> ProcessEvent {
    ProcessEvent {
        timestamp: "2025-06-04T12:00:00Z".into(),
        ecs_version: "8.11.0".into(),
        event_category: "process".into(),
        event_module: None,
        status: None,
        process_name: String::new(),
        process_pid: 0,
        process_sid: 0,
        process_args: None,
        process_executable: None,
        process_ppid: None,
        process_pname: None,
        process_working_directory: None,
        audit_loginuid: 0,
        audit_sessionid: 0,
        host_name: None,
        host_id: None,
        user_name: None,
        user_id: None,
    }
}

pub fn event_from_test_case(tc: &RuleTestCase) -> ProcessEvent {
    let mut ev = base_event();
    if let Some(name) = &tc.process_name {
        ev.process_name = name.clone();
    }
    if let Some(args) = &tc.process_args {
        ev.process_args = Some(args.clone());
    }
    if let Some(exe) = &tc.process_executable {
        ev.process_executable = Some(exe.clone());
    }
    if let Some(pname) = &tc.process_pname {
        ev.process_pname = Some(pname.clone());
    }
    if tc.process_ppid.is_some() {
        ev.process_ppid = tc.process_ppid;
    }
    if let Some(cwd) = &tc.process_working_directory {
        ev.process_working_directory = Some(cwd.clone());
    }
    if let Some(uname) = &tc.user_name {
        ev.user_name = Some(uname.clone());
    }
    if tc.user_id.is_some() {
        ev.user_id = tc.user_id;
    }
    if let Some(cat) = &tc.event_category {
        ev.event_category = cat.clone();
    }
    ev
}

pub fn collect_rule_yaml_files(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    fn collect(dir: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
        let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::path);

        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                collect(&path, files)?;
            } else if path.extension().and_then(std::ffi::OsStr::to_str) == Some("yaml") {
                files.push(path);
            }
        }

        Ok(())
    }

    let mut files = Vec::new();
    collect(root, &mut files)?;
    Ok(files)
}

pub fn load_rule_fixture(path: &Path) -> FixtureResult<RuleFixture> {
    let contents = fs::read_to_string(path)?;
    let mut fixture: RuleFixture = yaml_serde::from_str(&contents)?;
    fixture.path = path.to_path_buf();
    Ok(fixture)
}

pub fn load_rule_fixtures(root: &Path) -> FixtureResult<Vec<RuleFixture>> {
    let paths = collect_rule_yaml_files(root)?;
    let mut fixtures = Vec::with_capacity(paths.len());

    for path in paths {
        fixtures.push(load_rule_fixture(&path)?);
    }

    Ok(fixtures)
}
