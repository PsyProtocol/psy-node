use std::cmp::Ordering;

/// `(operator in infra-failed operators, quota_group in failed quota groups,
/// operator in any failed or quota-touched operators)`, compared
/// lexicographically with lower first. See spec §5.1.
pub(crate) type Tier = (bool, bool, bool);

#[derive(Clone, Copy, Debug)]
pub(crate) struct Candidate {
    pub index: usize,
    pub health: f64,
    pub available: bool,
    pub priority_weight: i32,
    pub tier: Tier,
}

/// Static preference: higher weight, then earlier config position.
fn preference(a: &Candidate, b: &Candidate) -> Ordering {
    a.priority_weight.cmp(&b.priority_weight).then(b.index.cmp(&a.index))
}

/// Best: among available providers in the lowest tier whose health is within
/// `tolerance` of the best, pick by static preference. With none available,
/// pick the least bad, ordered by lowest tier, then highest health, then
/// static preference.
pub(crate) fn select_best(candidates: &[Candidate], tolerance: f64) -> Option<usize> {
    let open: Vec<&Candidate> = candidates.iter().filter(|c| c.available).collect();
    if let Some(min_tier) = open.iter().map(|c| c.tier).min() {
        let open: Vec<&Candidate> = open.into_iter().filter(|c| c.tier == min_tier).collect();
        let best = open.iter().map(|c| c.health).max_by(f64::total_cmp)?;
        return open
            .into_iter()
            .filter(|c| c.health >= best - tolerance)
            .max_by(|a, b| preference(a, b))
            .map(|c| c.index);
    }
    candidates
        .iter()
        .max_by(|a, b| {
            b.tier.cmp(&a.tier).then_with(|| a.health.total_cmp(&b.health)).then_with(|| preference(a, b))
        })
        .map(|c| c.index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(index: usize, health: f64, available: bool, priority_weight: i32, tier: Tier) -> Candidate {
        Candidate { index, health, available, priority_weight, tier }
    }

    const T0: Tier = (false, false, false);

    #[test]
    fn equal_health_prefers_weight_then_config_order() {
        let all = [c(0, 100.0, true, 10, T0), c(1, 100.0, true, 11, T0), c(2, 100.0, true, 11, T0)];
        assert_eq!(select_best(&all, 2.0), Some(1));
        let tie = [c(0, 100.0, true, 10, T0), c(1, 100.0, true, 10, T0)];
        assert_eq!(select_best(&tie, 2.0), Some(0));
    }

    #[test]
    fn priority_wins_within_tolerance_but_not_beyond() {
        let within = [c(0, 98.0, true, 11, T0), c(1, 100.0, true, 10, T0)];
        assert_eq!(select_best(&within, 2.0), Some(0));
        let beyond = [c(0, 97.9, true, 11, T0), c(1, 100.0, true, 10, T0)];
        assert_eq!(select_best(&beyond, 2.0), Some(1));
    }

    #[test]
    fn unavailable_providers_are_skipped_even_with_better_health() {
        let all = [c(0, 100.0, false, 11, T0), c(1, 40.0, true, 10, T0)];
        assert_eq!(select_best(&all, 2.0), Some(1));
    }

    #[test]
    fn all_unavailable_falls_back_to_least_bad() {
        let all = [c(0, 10.0, false, 11, T0), c(1, 60.0, false, 9, T0), c(2, 60.0, false, 10, T0)];
        assert_eq!(select_best(&all, 2.0), Some(2));
    }

    #[test]
    fn empty_input_selects_nothing() {
        assert_eq!(select_best(&[], 2.0), None);
    }

    #[test]
    fn a_lower_tier_beats_higher_health_and_weight_among_available() {
        // Index 0 is in a worse tier but has far better health and weight;
        // index 1 is in the best tier and must still win.
        let all = [c(0, 100.0, true, 20, (true, true, true)), c(1, 40.0, true, 5, T0)];
        assert_eq!(select_best(&all, 2.0), Some(1));
    }

    #[test]
    fn an_available_worse_tier_beats_an_unavailable_better_tier() {
        let all = [c(0, 100.0, false, 20, T0), c(1, 40.0, true, 5, (true, true, true))];
        assert_eq!(select_best(&all, 2.0), Some(1));
    }

    #[test]
    fn least_bad_orders_by_tier_first() {
        // Both unavailable; index 0 has better health and weight but a worse
        // tier, so index 1 (lowest tier) must be the least-bad pick.
        let all = [c(0, 90.0, false, 20, (true, true, true)), c(1, 10.0, false, 5, T0)];
        assert_eq!(select_best(&all, 2.0), Some(1));
    }
}
