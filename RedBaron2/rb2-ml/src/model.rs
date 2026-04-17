use std::collections::HashMap;

use crate::config::{Config, DecayedValue};
use crate::stats::{ExeProfile, FeatureVec, RunningCentroid, ShapeFeatures};

#[derive(Debug, Clone)]
pub struct ExecEvent {
    pub ts: u64,
    pub user: String,
    pub parent_exe: String,
    pub exe: String,
    pub argv: Vec<String>,
    pub template: u64,
    pub template_display: String,
    pub shape: ShapeFeatures,
    pub parent_id: u64,
    pub exe_id: u64,
    pub user_id: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ScoreBreakdown {
    pub s_parent_child: f32,
    pub s_parent_template: f32,
    pub s_template_global: f32,
    pub s_user_exe: f32,
    pub s_shape_deviation: f32,
    pub s_centroid_distance: f32,
    pub explicit_score: f32,
    pub final_score: f32,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PendingLearn {
    pub count: u32,
    pub last_ts: u64,
}

pub struct OnlineScorer {
    pub cfg: Config,
    parent_child: HashMap<(u64, u64), DecayedValue>,
    parent_template: HashMap<(u64, u64), DecayedValue>,
    template_global: HashMap<u64, DecayedValue>,
    user_exe: HashMap<(u64, u64), DecayedValue>,
    exe_profiles: HashMap<u64, ExeProfile>,
    exe_centroids: HashMap<u64, RunningCentroid>,
    pub(crate) pending_templates: HashMap<u64, PendingLearn>,
}

impl OnlineScorer {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            parent_child: HashMap::new(),
            parent_template: HashMap::new(),
            template_global: HashMap::new(),
            user_exe: HashMap::new(),
            exe_profiles: HashMap::new(),
            exe_centroids: HashMap::new(),
            pending_templates: HashMap::new(),
        }
    }

    pub fn score_event(&self, ev: &ExecEvent) -> ScoreBreakdown {
        let parent_id = ev.parent_id;
        let exe_id = ev.exe_id;
        let user_id = ev.user_id;

        let pc_weight = self
            .parent_child
            .get(&(parent_id, exe_id))
            .map_or(0.0, |v| v.get(ev.ts, self.cfg.hl_parent_child_secs));
        let pt_weight = self
            .parent_template
            .get(&(parent_id, ev.template))
            .map_or(0.0, |v| v.get(ev.ts, self.cfg.hl_parent_template_secs));
        let tg_weight = self
            .template_global
            .get(&ev.template)
            .map_or(0.0, |v| v.get(ev.ts, self.cfg.hl_template_global_secs));
        let ue_weight = self
            .user_exe
            .get(&(user_id, exe_id))
            .map_or(0.0, |v| v.get(ev.ts, self.cfg.hl_user_exe_secs));

        let s_parent_child = crate::rarity(pc_weight);
        let s_parent_template = crate::rarity(pt_weight);
        let s_template_global = crate::rarity(tg_weight);
        let s_user_exe = crate::rarity(ue_weight);
        let s_shape_deviation = self
            .exe_profiles
            .get(&exe_id)
            .map_or(0.0, |p| p.deviation_score(&ev.shape));

        let feature_vec = Self::build_feature_vec(
            s_parent_child,
            s_parent_template,
            s_template_global,
            s_user_exe,
            s_shape_deviation,
            &ev.shape,
        );

        let s_centroid_distance = self
            .exe_centroids
            .get(&exe_id)
            .map_or(0.0, |c| c.distance_score(&feature_vec));

        // XXX: this floating point operation can be optimized, but I couldn't find a
        // readable/clean way to do it
        #[expect(
            clippy::suboptimal_flops,
            reason = "expanded weighted sum stays easier to read"
        )]
        let explicit_score = self.cfg.weight_parent_child * s_parent_child
            + self.cfg.weight_parent_template * s_parent_template
            + self.cfg.weight_template_global * s_template_global
            + self.cfg.weight_user_exe * s_user_exe
            + self.cfg.weight_shape_deviation * s_shape_deviation
            + self.cfg.weight_centroid_distance * s_centroid_distance;

        ScoreBreakdown {
            s_parent_child,
            s_parent_template,
            s_template_global,
            s_user_exe,
            s_shape_deviation,
            s_centroid_distance,
            explicit_score: crate::clamp01(explicit_score),
            final_score: crate::clamp01(explicit_score),
        }
    }

    pub fn observe(&mut self, ev: &ExecEvent) -> ScoreBreakdown {
        let score = self.score_event(ev);
        self.maybe_learn(ev, score.final_score);
        score
    }

    pub fn maybe_learn(&mut self, ev: &ExecEvent, final_score: f32) {
        if final_score < self.cfg.learn_low_cutoff {
            self.learn_benign(ev);
            self.pending_templates.remove(&ev.template);
            return;
        }

        let pending = self.pending_templates.entry(ev.template).or_default();
        pending.count += 1;
        pending.last_ts = ev.ts;
        if final_score < self.cfg.learn_medium_cutoff
            && pending.count >= self.cfg.learn_pending_required
        {
            self.learn_benign(ev);
            self.pending_templates.remove(&ev.template);
        }
    }

    pub fn learn_benign(&mut self, ev: &ExecEvent) {
        let parent_id = ev.parent_id;
        let exe_id = ev.exe_id;
        let user_id = ev.user_id;

        self.parent_child
            .entry((parent_id, exe_id))
            .or_default()
            .touch(ev.ts, self.cfg.hl_parent_child_secs, 1.0);
        self.parent_template
            .entry((parent_id, ev.template))
            .or_default()
            .touch(ev.ts, self.cfg.hl_parent_template_secs, 1.0);
        self.template_global.entry(ev.template).or_default().touch(
            ev.ts,
            self.cfg.hl_template_global_secs,
            1.0,
        );
        self.user_exe.entry((user_id, exe_id)).or_default().touch(
            ev.ts,
            self.cfg.hl_user_exe_secs,
            1.0,
        );

        self.exe_profiles
            .entry(exe_id)
            .or_default()
            .update(&ev.shape);

        let feature_vec = Self::build_feature_vec(
            0.0,
            0.0,
            0.0,
            0.0,
            self.exe_profiles
                .get(&exe_id)
                .map_or(0.0, |p| p.deviation_score(&ev.shape)),
            &ev.shape,
        );
        self.exe_centroids
            .entry(exe_id)
            .or_default()
            .update(&feature_vec);
    }

    pub fn prune(&mut self, now: u64) {
        let min_w = self.cfg.prune_min_weight;
        self.parent_child
            .retain(|_, v| v.get(now, self.cfg.hl_parent_child_secs) >= min_w);
        self.parent_template
            .retain(|_, v| v.get(now, self.cfg.hl_parent_template_secs) >= min_w);
        self.template_global
            .retain(|_, v| v.get(now, self.cfg.hl_template_global_secs) >= min_w);
        self.user_exe
            .retain(|_, v| v.get(now, self.cfg.hl_user_exe_secs) >= min_w);
        self.pending_templates
            .retain(|_, p| now.saturating_sub(p.last_ts) <= 6 * 3600);
    }

    fn build_feature_vec(
        s_parent_child: f32,
        s_parent_template: f32,
        s_template_global: f32,
        s_user_exe: f32,
        s_shape_deviation: f32,
        shape: &ShapeFeatures,
    ) -> FeatureVec {
        [
            s_parent_child,
            s_parent_template,
            s_template_global,
            s_user_exe,
            s_shape_deviation,
            crate::clamp01(shape.arg_count as f32 / 16.0),
            crate::clamp01(shape.cmd_len as f32 / 256.0),
            crate::clamp01(shape.max_token_entropy / 6.0),
            crate::clamp01(shape.mean_token_entropy / 6.0),
            crate::clamp01(shape.suspicious_token_fraction),
            crate::clamp01(shape.shell_operator_count as f32 / 8.0),
        ]
    }
}

pub fn make_event(ts: u64, user: &str, parent_exe: &str, exe: &str, argv: &[&str]) -> ExecEvent {
    let argv_vec: Vec<String> = argv.iter().map(ToString::to_string).collect();
    let template_display = crate::normalize_template_display(&argv_vec);
    let template = crate::stable_hash(&template_display);
    let shape = crate::extract_shape_features(&argv_vec);
    ExecEvent {
        ts,
        parent_id: crate::stable_hash(parent_exe),
        exe_id: crate::stable_hash(exe),
        user_id: crate::stable_hash(user),
        user: user.to_string(),
        parent_exe: parent_exe.to_string(),
        exe: exe.to_string(),
        argv: argv_vec,
        template,
        template_display,
        shape,
    }
}

pub fn make_event_from_strings(
    ts: u64,
    user: &str,
    parent_exe: &str,
    exe: &str,
    argv: &[String],
) -> ExecEvent {
    let template_display = crate::normalize_template_display(argv);
    let template = crate::stable_hash(&template_display);
    let shape = crate::extract_shape_features(argv);
    ExecEvent {
        ts,
        parent_id: crate::stable_hash(parent_exe),
        exe_id: crate::stable_hash(exe),
        user_id: crate::stable_hash(user),
        user: user.to_string(),
        parent_exe: parent_exe.to_string(),
        exe: exe.to_string(),
        argv: argv.to_vec(),
        template,
        template_display,
        shape,
    }
}
