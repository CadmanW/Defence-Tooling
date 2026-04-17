use crate::clamp01;

#[derive(Debug, Clone, Copy, Default)]
pub struct RunningStat {
    pub n: f32,
    pub mean: f32,
    pub m2: f32,
}

impl RunningStat {
    pub fn update(&mut self, x: f32) {
        self.n += 1.0;
        let delta = x - self.mean;
        self.mean += delta / self.n;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
    }

    pub fn variance(&self) -> f32 {
        if self.n < 2.0 {
            0.0
        } else {
            self.m2 / (self.n - 1.0)
        }
    }

    pub fn stddev(&self) -> f32 {
        self.variance().sqrt()
    }

    pub fn zscore_abs(&self, x: f32) -> f32 {
        let s = self.stddev();
        if self.n < 5.0 || s < 1e-6 {
            0.0
        } else {
            ((x - self.mean) / s).abs()
        }
    }
}

pub const FEATURE_DIM: usize = 11;
pub type FeatureVec = [f32; FEATURE_DIM];

#[derive(Debug, Clone, Copy, Default)]
pub struct RunningCentroid {
    pub n: f32,
    pub mean: FeatureVec,
    pub m2: FeatureVec,
}

impl RunningCentroid {
    pub fn update(&mut self, x: &FeatureVec) {
        self.n += 1.0;
        for (i, &xi) in x.iter().enumerate().take(FEATURE_DIM) {
            let delta = xi - self.mean[i];
            self.mean[i] += delta / self.n;
            let delta2 = xi - self.mean[i];
            self.m2[i] += delta * delta2;
        }
    }

    pub fn distance_score(&self, x: &FeatureVec) -> f32 {
        if self.n < 5.0 {
            return 0.0;
        }
        let mut acc = 0.0;
        for (i, &xi) in x.iter().enumerate().take(FEATURE_DIM) {
            let var = if self.n > 1.0 {
                self.m2[i] / (self.n - 1.0)
            } else {
                0.0
            };
            let std = var.sqrt();
            let d = if std < 1e-6 {
                (xi - self.mean[i]).abs()
            } else {
                ((xi - self.mean[i]) / std).abs()
            };
            acc += d;
        }
        let avg = acc / FEATURE_DIM as f32;
        clamp01(avg / 4.0)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ShapeFeatures {
    pub arg_count: usize,
    pub cmd_len: usize,
    pub max_token_entropy: f32,
    pub mean_token_entropy: f32,
    pub suspicious_token_fraction: f32,
    pub shell_operator_count: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ExeProfile {
    pub arg_count: RunningStat,
    pub cmd_len: RunningStat,
    pub max_token_entropy: RunningStat,
    pub mean_token_entropy: RunningStat,
    pub suspicious_token_fraction: RunningStat,
    pub shell_operator_count: RunningStat,
}

impl ExeProfile {
    pub fn update(&mut self, s: &ShapeFeatures) {
        self.arg_count.update(s.arg_count as f32);
        self.cmd_len.update(s.cmd_len as f32);
        self.max_token_entropy.update(s.max_token_entropy);
        self.mean_token_entropy.update(s.mean_token_entropy);
        self.suspicious_token_fraction
            .update(s.suspicious_token_fraction);
        self.shell_operator_count
            .update(s.shell_operator_count as f32);
    }

    pub fn deviation_score(&self, s: &ShapeFeatures) -> f32 {
        let z1 = self.arg_count.zscore_abs(s.arg_count as f32);
        let z2 = self.cmd_len.zscore_abs(s.cmd_len as f32);
        let z3 = self.max_token_entropy.zscore_abs(s.max_token_entropy);
        let z4 = self.mean_token_entropy.zscore_abs(s.mean_token_entropy);
        let z5 = self
            .suspicious_token_fraction
            .zscore_abs(s.suspicious_token_fraction);
        let z6 = self
            .shell_operator_count
            .zscore_abs(s.shell_operator_count as f32);
        clamp01(z1.max(z2).max(z3).max(z4).max(z5).max(z6) / 4.0)
    }
}
