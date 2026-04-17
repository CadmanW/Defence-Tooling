use crate::config::yaml;
use chrono::DateTime;
use fastrace::prelude::*;
use flying_ace_engine::{EcsRhaiEngine, ProcessEvent as EngineEvent, RuleMode};
use log::{debug, info, warn};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rb2_ml::OnlineScorer;
use serde_json::json;
use std::{convert::Infallible, io};
use tokio::sync::mpsc;

fn kill_pid(pid: i32) -> io::Result<()> {
    let me = nix::unistd::getpid().as_raw();

    if pid == me {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to kill self",
        ));
    }

    kill(Pid::from_raw(pid), Signal::SIGKILL)
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;

    Ok(())
}

/// Initialize the RHAI rule engine from embedded + optional extra rules.
pub fn init_rhai_engine(cfg: &yaml::ProcessConfig) -> Option<EcsRhaiEngine> {
    if !cfg.rhai_enabled {
        info!("RHAI rule engine disabled via config (process.rhai_enabled: false)");
        return None;
    }

    const EMBEDDED_RHAI_RULES_XZ: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/compiled_rhai_rules.xz"));

    let embedded_yaml = {
        let mut raw = Vec::new();
        if EMBEDDED_RHAI_RULES_XZ.is_empty() {
            warn!("No embedded RHAI rules found in binary; continuing without embedded rules");
        } else if let Err(e) = lzma_rs::lzma_decompress(
            &mut std::io::BufReader::new(EMBEDDED_RHAI_RULES_XZ),
            &mut raw,
        ) {
            warn!("Failed to decompress embedded RHAI rules: {}", e);
        }
        String::from_utf8(raw).unwrap_or_default()
    };

    let extra_dir = cfg.rhai_rules_dir.as_deref();
    let eng = EcsRhaiEngine::new_combined(&embedded_yaml, extra_dir, &cfg.disabled_rules);
    info!(
        "RHAI engine initialized: {} rules loaded (extra_dir={:?}, disabled={})",
        eng.rule_count(),
        extra_dir,
        cfg.disabled_rules.len(),
    );
    Some(eng)
}

fn parse_argv(args: Option<&str>) -> Vec<String> {
    args.map_or_else(Vec::new, |s| {
        shell_words::split(s).unwrap_or_else(|_| vec![s.to_string()])
    })
}

/// Convert a flying-ace `EngineEvent` into an `rb2_ml::ExecEvent` for the
/// online scorer. Uses current Unix time when the event timestamp cannot be
/// parsed, so decay and learning use real time instead of 0 (which would make
/// all scores identical).
fn engine_event_to_ml(event: &EngineEvent) -> rb2_ml::ExecEvent {
    let ts = DateTime::parse_from_rfc3339(&event.timestamp)
        .map(|dt| dt.timestamp() as u64)
        .unwrap_or_else(|_| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });

    let user = event.user_name.as_deref().unwrap_or("unknown");
    let parent_exe = event.process_pname.as_deref().unwrap_or("unknown");
    let exe = event
        .process_executable
        .as_deref()
        .unwrap_or(&event.process_name);

    let argv: Vec<String> = parse_argv(event.process_args.as_deref());

    rb2_ml::make_event_from_strings(ts, user, parent_exe, exe, &argv)
}

/// Shared event-dispatch loop: logs events, optionally evaluates ML/RHAI
/// rules, and handles kill/alert actions. Both eBPF and auditd collectors
/// feed into this.
pub async fn run_event_pipeline(
    engine: Option<EcsRhaiEngine>,
    mut scorer: Option<OnlineScorer>,
    ml_debug: bool,
    mut rx: mpsc::Receiver<EngineEvent>,
) -> Infallible {
    let mut event_count: u64 = 0;
    loop {
        let event = match rx.recv().await {
            Some(e) => e,
            None => {
                debug!("event pipeline: all senders dropped, parking forever");
                std::future::pending::<()>().await;
                unreachable!()
            }
        };

        // Base process log, without ML.
        let mut process_log = json!({
            "timestamp": &event.timestamp,
            "process_name": &event.process_name,
            "process_pid": event.process_pid,
            "process_sid": event.process_sid,
            "process_args": &event.process_args,
            "process_executable": &event.process_executable,
            "process_ppid": event.process_ppid,
            "process_pname": &event.process_pname,
            "process_working_directory": &event.process_working_directory,
            "audit_sessionid": &event.audit_sessionid,
            "audit_loginuid": &event.audit_loginuid,
            "user_name": &event.user_name,
            "user_id": event.user_id,
            "event_category": &event.event_category,
            "event_module": &event.event_module,
            "status": &event.status,
            "host_name": &event.host_name,
            "host_id": &event.host_id,
        });

        let root = Span::root("process.pipeline", SpanContext::random()).with_properties(|| {
            let mut props = vec![
                ("process.pid", event.process_pid.to_string()),
                ("process.name", event.process_name.clone()),
            ];
            if let Some(user) = &event.user_name {
                props.push(("user.name", user.clone()));
            }
            if let Some(host) = &event.host_name {
                props.push(("host.name", host.clone()));
            }
            props
        });

        if let Some(scorer) = &mut scorer {
            let eval_span = Span::enter_with_parent("ml.eval", &root);

            let ml_event = engine_event_to_ml(&event);
            eval_span.add_property(|| ("ml.template", ml_event.template_display.clone()));

            let ml_score = scorer.observe(&ml_event);
            eval_span.add_property(|| ("ml.score", ml_score.final_score.to_string()));

            if ml_debug {
                process_log["ml"] = json!({
                    "score": ml_score.final_score,
                    "parent_child": ml_score.s_parent_child,
                    "parent_template": ml_score.s_parent_template,
                    "template_global": ml_score.s_template_global,
                    "user_exe": ml_score.s_user_exe,
                    "shape_deviation": ml_score.s_shape_deviation,
                    "centroid_distance": ml_score.s_centroid_distance,
                    "template": ml_event.template_display,
                });
            } else {
                process_log["ml_score"] = json!(ml_score.final_score);
            }

            event_count += 1;
            if event_count.is_multiple_of(1000) {
                scorer.prune(ml_event.ts);
            }
        }

        debug!("Event {}", process_log);
        info!(target: "rb2_process", "{}", process_log);

        if let Some(engine) = &engine {
            let eval_span = Span::enter_with_parent("rhai.eval", &root)
                .with_properties(|| vec![("rhai.rule_count", engine.rule_count().to_string())]);
            let _eval_guard = eval_span.set_local_parent();

            let matches = engine.eval(&event);

            eval_span.add_property(|| ("rhai.match_count", matches.len().to_string()));

            for m in &matches {
                let action_taken = match m.mode {
                    RuleMode::Kill => "kill",
                    RuleMode::Alert => "alert",
                };

                if m.mode == RuleMode::Kill {
                    let pid = event.process_pid as i32;
                    match kill_pid(pid) {
                        Ok(()) => {
                            info!("Killed process pid={} (rule={})", pid, m.name)
                        }
                        Err(e) => {
                            warn!("Failed to kill pid={} (rule={}): {}", pid, m.name, e)
                        }
                    }
                }

                debug!("RHAI rule hit: '{}' (mode={})", m.name, m.mode);

                let alert = serde_json::json!({
                    "timestamp": &event.timestamp,
                    "rule_name": &m.name,
                    "rule_mode": m.mode.to_string(),
                    "action_taken": action_taken,
                    "event": &event,
                });

                info!(target: "rb2_ace", "{}", alert);
            }

            debug!("RHAI eval result: {} match(es)", matches.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_argv;

    #[test]
    fn argv_simple() {
        assert_eq!(parse_argv(Some("ls -la /tmp")), vec!["ls", "-la", "/tmp"]);
    }

    #[test]
    fn argv_quoted() {
        assert_eq!(
            parse_argv(Some(r#"bash -c "wall hi""#)),
            vec!["bash", "-c", "wall hi"]
        );
    }

    #[test]
    fn argv_escaped() {
        assert_eq!(
            parse_argv(Some(r#"cmd --path /tmp/a\ b"#)),
            vec!["cmd", "--path", "/tmp/a b"]
        );
    }

    #[test]
    fn argv_none() {
        assert!(parse_argv(None).is_empty());
    }
}
