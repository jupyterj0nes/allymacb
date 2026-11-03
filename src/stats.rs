//! Statistical primitives for the hunt, taken from masstin's graph-hunt:
//!
//! * `empirical_p`: tail probability of an observation against the values
//!   the same statistic took on the baseline.
//! * `benjamini_hochberg`: false-discovery-rate control across the tested
//!   records.
//!
//! No tuning constants live here. The only number the analyst chooses in the
//! whole hunt is alpha (`--alpha`, default 0.05).

/// Empirical p-value with the add-one correction:
/// (1 + #null values at least as extreme) / (1 + N). Never 0; with an
/// empty null it is 1 (nothing to compare with = no evidence).
pub fn empirical_p(at_least_as_extreme: usize, n_null: usize) -> f64 {
    (1.0 + at_least_as_extreme as f64) / (1.0 + n_null as f64)
}

/// Benjamini-Hochberg adjusted p-values (q-values), in input order.
pub fn benjamini_hochberg(ps: &[f64]) -> Vec<f64> {
    let m = ps.len();
    if m == 0 {
        return Vec::new();
    }
    let mut idx: Vec<usize> = (0..m).collect();
    idx.sort_by(|&a, &b| ps[a].partial_cmp(&ps[b]).unwrap_or(std::cmp::Ordering::Equal));
    let mut q = vec![1.0; m];
    let mut running = 1.0f64;
    for rank in (0..m).rev() {
        let i = idx[rank];
        let v = (ps[i] * m as f64 / (rank as f64 + 1.0)).min(1.0);
        running = running.min(v);
        q[i] = running;
    }
    q
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bh_known() {
        let q = benjamini_hochberg(&[0.01, 0.04, 0.03, 0.2]);
        assert!((q[0] - 0.04).abs() < 1e-12);
        assert!((q[1] - 0.053_333_3).abs() < 1e-6);
        assert!((q[2] - 0.053_333_3).abs() < 1e-6);
        assert!((q[3] - 0.2).abs() < 1e-12);
    }

    #[test]
    fn empirical() {
        assert!((empirical_p(0, 9) - 0.1).abs() < 1e-12);
        assert_eq!(empirical_p(0, 0), 1.0);
    }
}
