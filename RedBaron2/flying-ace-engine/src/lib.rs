use regex::Regex;
use rhai::ImmutableString;
use rhai::{AST, Engine, Scope};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::{fmt, fs, path::Path};

#[cfg(feature = "tracing")]
use fastrace::prelude::*;

pub mod rule_fixtures;

type RegexCache = RwLock<HashMap<String, Arc<Regex>>>;

fn regex_cache() -> &'static RegexCache {
    static CACHE: OnceLock<RegexCache> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn get_or_compile_regex(pattern: &str) -> Result<Arc<Regex>, regex::Error> {
    let cached = regex_cache()
        .read()
        .expect("regex cache read lock poisoned")
        .get(pattern)
        .cloned();
    if let Some(regex) = cached {
        return Ok(regex);
    }

    let compiled = Arc::new(Regex::new(pattern)?);
    let mut cache = regex_cache()
        .write()
        .expect("regex cache write lock poisoned");

    if let Some(regex) = cache.get(pattern) {
        return Ok(regex.clone());
    }

    cache.insert(pattern.to_owned(), compiled.clone());
    drop(cache);
    Ok(compiled)
}

// -----------------------------------------------------------------------------
// Rule mode: alert (log only) or kill (terminate + log).  Defaults to Alert.
// -----------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleMode {
    #[default]
    Alert,
    Kill,
}

impl fmt::Display for RuleMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alert => write!(f, "alert"),
            Self::Kill => write!(f, "kill"),
        }
    }
}

/// Returned by the engine for every rule that fires on a given event.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub name: String,
    pub mode: RuleMode,
}

// -----------------------------------------------------------------------------
// ECS-compatible event struct (minimal subset - extend as needed)
// -----------------------------------------------------------------------------
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProcessEvent {
    pub timestamp: String,

    // process.*
    pub process_name: String,
    pub process_pid: u32,
    pub process_sid: u32,
    pub process_args: Option<String>,
    pub process_executable: Option<String>,
    pub process_ppid: Option<u32>,
    pub process_pname: Option<String>, // parent name
    pub process_working_directory: Option<String>,

    // audit info
    pub audit_loginuid: u32,
    pub audit_sessionid: u32,

    // user.*
    pub user_name: Option<String>,
    pub user_id: Option<u32>,

    // event.*
    pub event_category: String,
    pub event_module: Option<String>,
    #[serde(default, skip_serializing)]
    pub status: Option<String>,
    pub ecs_version: String,

    // host.*
    pub host_name: Option<String>,
    pub host_id: Option<String>,
}

impl fmt::Display for ProcessEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = if f.alternate() {
            serde_json::to_string_pretty(self)
        } else {
            serde_json::to_string(self)
        }
        .map_err(|_| fmt::Error)?;
        f.write_str(&s)
    }
}

// -----------------------------------------------------------------------------
// Push nested ECS objects into a Rhai Scope
// -----------------------------------------------------------------------------
impl ProcessEvent {
    pub fn to_scope(&self) -> Scope<'_> {
        let mut scope = Scope::new();

        scope.push("e", self.clone());

        scope
    }

    // process.*
    fn get_process_name(&mut self) -> ImmutableString {
        self.process_name.clone().into()
    }
    fn get_process_args(&mut self) -> ImmutableString {
        self.process_args.clone().unwrap_or_default().into()
    }

    fn get_process_executable(&mut self) -> ImmutableString {
        self.process_executable.clone().unwrap_or_default().into()
    }

    const fn get_process_ppid(&mut self) -> i64 {
        if let Some(ppid) = self.process_ppid {
            ppid as i64
        } else {
            -1
        }
    }

    fn get_process_pname(&mut self) -> ImmutableString {
        self.process_pname.clone().unwrap_or_default().into()
    }

    fn get_process_working_directory(&mut self) -> ImmutableString {
        self.process_working_directory
            .clone()
            .unwrap_or_default()
            .into()
    }

    // host.*
    fn get_host_name(&mut self) -> ImmutableString {
        self.host_name.clone().unwrap_or_default().into()
    }
    fn get_host_id(&mut self) -> ImmutableString {
        self.host_id.clone().unwrap_or_default().into()
    }

    // user.*
    fn get_user_name(&mut self) -> ImmutableString {
        self.user_name.clone().unwrap_or_default().into()
    }
    const fn get_user_id(&mut self) -> i64 {
        if let Some(uid) = self.user_id {
            uid as i64
        } else {
            -1
        }
    }
}

// -----------------------------------------------------------------------------
// YAML rule representation
// -----------------------------------------------------------------------------
#[derive(Debug, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub mode: RuleMode,
    pub eval: String,
    // `tests` is only used by the test harness; ignored at runtime.
}

#[derive(Debug)]
struct CompiledRule {
    name: String,
    mode: RuleMode,
    ast: AST,
}

// -----------------------------------------------------------------------------
// Rhai Engine wrapper
// -----------------------------------------------------------------------------
pub struct EcsRhaiEngine {
    engine: Engine,
    rules: Vec<CompiledRule>,
}

impl EcsRhaiEngine {
    /// Create a new Rhai engine with all custom functions and type registrations.
    fn new_engine() -> Engine {
        let mut engine = Engine::new();
        engine.set_optimization_level(rhai::OptimizationLevel::Full);
        engine.set_fast_operators(true);
        engine.set_allow_loop_expressions(false);
        engine.set_allow_switch_expression(false);

        // add in custom functions to rhai language
        // XXX: may want to implement cache for pre-compiled regex rules
        engine.register_fn("re_match", |text: ImmutableString, pattern: &str| -> bool {
            let text = text.as_str();

            match get_or_compile_regex(pattern) {
                Ok(re) => re.is_match(text),
                Err(e) => {
                    eprintln!("Regex compile failed {e} {pattern:?}");
                    false
                }
            }
        });

        engine
            .register_type::<ProcessEvent>()
            // process.*
            .register_get("process_name", ProcessEvent::get_process_name)
            .register_get("process_args", ProcessEvent::get_process_args)
            .register_get("process_executable", ProcessEvent::get_process_executable)
            .register_get("process_ppid", ProcessEvent::get_process_ppid)
            .register_get("process_pname", ProcessEvent::get_process_pname)
            .register_get(
                "process_working_directory",
                ProcessEvent::get_process_working_directory,
            )
            // user.*
            .register_get("user_name", ProcessEvent::get_user_name)
            .register_get("user_id", ProcessEvent::get_user_id)
            // host.*
            .register_get("host_name", ProcessEvent::get_host_name)
            .register_get("host_id", ProcessEvent::get_host_id);

        engine
    }

    /// Try to compile a [`Rule`] and push it onto the compiled rules vec.
    /// Returns `true` if the rule was added, `false` if skipped or failed.
    /// if override_mode is enabled, the rules won't be able to enforce, only alert
    fn try_add_rule(
        engine: &Engine,
        rules: &mut Vec<CompiledRule>,
        rule: Rule,
        override_mode: bool,
    ) -> bool {
        match engine.compile(&rule.eval) {
            Ok(ast) => {
                rules.push(CompiledRule {
                    name: rule.name,
                    mode: if override_mode {
                        RuleMode::Alert
                    } else {
                        rule.mode
                    },
                    ast,
                });
                true
            }
            Err(err) => {
                eprintln!("Failed to compile rule '{name}': {err}", name = rule.name);
                false
            }
        }
    }

    /// Load rules from a directory of YAML files (original behaviour, used by tests).
    /// Recursively traverses subdirectories.
    /// files loaded from directories can't enforce, only alert
    pub fn new_from_dir<P: AsRef<Path>>(rules_dir: P) -> Self {
        let engine = Self::new_engine();
        let mut rules = Vec::new();

        fn load_rules_recursive(dir: &Path, engine: &rhai::Engine, rules: &mut Vec<CompiledRule>) {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        load_rules_recursive(&path, engine, rules);
                    } else if let Ok(contents) = fs::read_to_string(&path)
                        && let Ok(rule) = yaml_serde::from_str::<Rule>(&contents)
                    {
                        EcsRhaiEngine::try_add_rule(engine, rules, rule, true);
                    }
                }
            }
        }

        load_rules_recursive(rules_dir.as_ref(), &engine, &mut rules);
        Self { engine, rules }
    }

    /// Load rules from a multi-document YAML string (documents separated by
    /// `\n---\n`).  This is the format produced by the build script when
    /// embedding rules into the binary.
    pub fn new_from_yaml_str(yaml: &str) -> Self {
        let engine = Self::new_engine();
        let mut rules = Vec::new();

        for doc in yaml.split("\n---\n") {
            let doc = doc.trim();
            if doc.is_empty() {
                continue;
            }
            match yaml_serde::from_str::<Rule>(doc) {
                Ok(rule) => {
                    Self::try_add_rule(&engine, &mut rules, rule, false);
                }
                Err(err) => {
                    eprintln!("Failed to parse embedded RHAI rule: {err}");
                }
            }
        }
        Self { engine, rules }
    }

    pub fn new_from_yaml_file(path: &Path) -> std::io::Result<Self> {
        let yaml = fs::read_to_string(path)?;
        Ok(Self::new_from_yaml_str(&yaml))
    }

    /// Build a combined engine from embedded YAML, an optional on-disk rules
    /// directory, and an optional list of rule names to disable.
    ///
    /// Disabled rules are removed after all sources have been loaded, so a
    /// name from any source can be suppressed.
    ///
    /// files loaded from directories can't enforce, only alert
    pub fn new_combined(
        embedded_yaml: &str,
        extra_rules_dir: Option<&Path>,
        disabled_rules: &[String],
    ) -> Self {
        let engine = Self::new_engine();

        let mut rules = Vec::new();

        // 1. Embedded rules
        for doc in embedded_yaml.split("\n---\n") {
            let doc = doc.trim();
            if doc.is_empty() {
                continue;
            }
            if let Ok(rule) = yaml_serde::from_str::<Rule>(doc) {
                Self::try_add_rule(&engine, &mut rules, rule, false);
            }
        }

        // 2. Extra rules from disk (can override / add to embedded set)
        // Recursively load from extra_rules_dir
        if let Some(dir) = extra_rules_dir {
            fn load_rules_recursive(
                dir: &Path,
                engine: &rhai::Engine,
                rules: &mut Vec<CompiledRule>,
            ) {
                if let Ok(entries) = fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            load_rules_recursive(&path, engine, rules);
                        } else if let Ok(contents) = fs::read_to_string(&path)
                            && let Ok(rule) = yaml_serde::from_str::<Rule>(&contents)
                        {
                            EcsRhaiEngine::try_add_rule(engine, rules, rule, true);
                        }
                    }
                }
            }
            load_rules_recursive(dir, &engine, &mut rules);
        }

        // 3. Remove disabled rules
        if !disabled_rules.is_empty() {
            rules.retain(|r| !disabled_rules.contains(&r.name));
        }

        Self { engine, rules }
    }

    /// Return the number of loaded rules.
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn eval(&self, event: &ProcessEvent) -> Vec<RuleMatch> {
        let mut scope = event.to_scope();

        self.rules
            .iter()
            .filter(|rule| self.eval_rule(&mut scope, rule))
            .map(|rule| RuleMatch {
                name: rule.name.clone(),
                mode: rule.mode,
            })
            .collect()
    }

    pub fn matches_rule(&self, event: &ProcessEvent, rule_name: &str) -> bool {
        let mut scope = event.to_scope();

        self.rules
            .iter()
            .find(|rule| rule.name == rule_name)
            .is_some_and(|rule| self.eval_rule(&mut scope, rule))
    }

    #[cfg(feature = "tracing")]
    fn eval_rule(&self, scope: &mut rhai::Scope, rule: &CompiledRule) -> bool {
        let rule_span = Span::enter_with_local_parent("rhai.rule").with_properties(|| {
            vec![
                ("rule.name", rule.name.clone()),
                ("rule.mode", rule.mode.to_string()),
            ]
        });

        let matched = match self.engine.eval_ast_with_scope::<bool>(scope, &rule.ast) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Failed to evalulate rule {name} {e}", name = rule.name);
                false
            }
        };

        rule_span.add_property(|| ("rule.matched", matched.to_string()));
        matched
    }

    #[cfg(not(feature = "tracing"))]
    fn eval_rule(&self, scope: &mut rhai::Scope, rule: &CompiledRule) -> bool {
        match self.engine.eval_ast_with_scope::<bool>(scope, &rule.ast) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Failed to evalulate rule {name} {e}", name = rule.name);
                false
            }
        }
    }
}
