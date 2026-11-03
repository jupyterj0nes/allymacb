//! Statistical primitives for the hunt, taken from masstin's graph-hunt:
//!
//! * `empirical_p`: tail probability of an observation against the values
//!   the same statistic took on the baseline.
//! * `benjamini_hochberg`: false-discovery-rate control across the tested
//!   records.
//! * `poisson_tail`: how likely a count at least this high is when events
//!   arrive at a known rate; the burst test of [`crate::context`].
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

/// `P(X >= k)` for `X ~ Poisson(lambda)`: 1 for `k = 0`; otherwise the
/// terms from `k` up, summed directly when `k` lies above the rate (so a
/// count far above it gets its tiny probability, not a rounding of 1), and
/// the complement of the terms below `k` when it does not. All in log space,
/// so a count in the thousands does not overflow.
pub fn poisson_tail(k: usize, lambda: f64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    if lambda <= 0.0 {
        return 0.0;
    }
    // ln of the terms i = 0 .. k, and their sum below k
    let mut below = 0.0f64;
    let mut log_term = -lambda;
    for i in 0..k {
        if i > 0 {
            log_term += lambda.ln() - (i as f64).ln();
        }
        below += log_term.exp();
    }
    if (k as f64) <= lambda {
        return (1.0 - below).clamp(0.0, 1.0);
    }
    log_term += lambda.ln() - (k as f64).ln(); // the term at k
    let mut tail = 0.0f64;
    let mut i = k;
    loop {
        let term = log_term.exp();
        tail += term;
        if term == 0.0 || term < tail * 1e-17 {
            break;
        }
        i += 1;
        log_term += lambda.ln() - (i as f64).ln();
    }
    tail.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poisson() {
        assert_eq!(poisson_tail(0, 3.0), 1.0);
        assert_eq!(poisson_tail(2, 0.0), 0.0);
        // P(X >= 1 | 1) = 1 - e^-1
        assert!((poisson_tail(1, 1.0) - (1.0 - (-1.0f64).exp())).abs() < 1e-12);
        // P(X >= 3 | 2) = 1 - e^-2 (1 + 2 + 2) = 0.3233
        assert!((poisson_tail(3, 2.0) - 0.323_323_6).abs() < 1e-6);
        // a count far above the rate is next to impossible, and far below it certain
        assert!(poisson_tail(300, 20.0) < 1e-100);
        assert!(poisson_tail(5, 2000.0) > 1.0 - 1e-12);
        // two among fifty at one in twenty-five: what the rate gives
        assert!(poisson_tail(2, 2.0) > 0.5);
    }

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
