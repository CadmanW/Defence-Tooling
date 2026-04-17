/// Scoring configuration and simple decayed scalar.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub hl_parent_child_secs: f32,
    pub hl_parent_template_secs: f32,
    pub hl_template_global_secs: f32,
    pub hl_user_exe_secs: f32,
    pub prune_min_weight: f32,
    pub learn_low_cutoff: f32,
    pub learn_medium_cutoff: f32,
    pub learn_pending_required: u32,
    pub weight_parent_child: f32,
    pub weight_parent_template: f32,
    pub weight_template_global: f32,
    pub weight_user_exe: f32,
    pub weight_shape_deviation: f32,
    pub weight_centroid_distance: f32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hl_parent_child_secs: 8.0 * 3600.0,
            hl_parent_template_secs: 6.0 * 3600.0,
            hl_template_global_secs: 3.0 * 3600.0,
            hl_user_exe_secs: 6.0 * 3600.0,
            prune_min_weight: 0.05,
            // Allow relatively high-scoring events to be learned as benign
            // after enough repetition so recurring but boring commands can
            // cool down over time.
            learn_low_cutoff: 0.40,
            learn_medium_cutoff: 0.80,
            learn_pending_required: 3,
            weight_parent_child: 0.34,
            weight_parent_template: 0.24,
            weight_template_global: 0.12,
            weight_user_exe: 0.06,
            weight_shape_deviation: 0.18,
            weight_centroid_distance: 0.06,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DecayedValue {
    pub weight: f32,
    pub last_ts: u64,
}

impl DecayedValue {
    pub fn get(&self, now: u64, half_life_secs: f32) -> f32 {
        if self.weight <= 0.0 {
            return 0.0;
        }
        let elapsed = now.saturating_sub(self.last_ts) as f32;
        let factor = 0.5f32.powf(elapsed / half_life_secs.max(1.0));
        self.weight * factor
    }

    pub fn touch(&mut self, now: u64, half_life_secs: f32, amount: f32) {
        let cur = self.get(now, half_life_secs);
        self.weight = cur + amount;
        self.last_ts = now;
    }
}
