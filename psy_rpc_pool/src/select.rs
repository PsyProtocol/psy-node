use std::cmp::Ordering;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Candidate {
    pub index: usize,
    pub health: f64,
    pub available: bool,
    pub priority_weight: i32,
}

/// Static preference: higher weight, then earlier config position.
fn preference(a: &Candidate, b: &Candidate) -> Ordering {
    a.priority_weight.cmp(&b.priority_weight).then(b.index.cmp(&a.index))
}

/// Best: among available providers whose health is within `tolerance` of the
/// best, pick by static preference. With none available, pick the least bad.
pub(crate) fn select_best(candidates: &[Candidate], tolerance: f64) -> Option<usize> {
    let open: Vec<&Candidate> = candidates.iter().filter(|c| c.available).collect();
    if let Some(best) = open.iter().map(|c| c.health).max_by(f64::total_cmp) {
        return open
            .into_iter()
            .filter(|c| c.health >= best - tolerance)
            .max_by(|a, b| preference(a, b))
            .map(|c| c.index);
    }
    candidates
        .iter()
        .max_by(|a, b| a.health.total_cmp(&b.health).then_with(|| preference(a, b)))
        .map(|c| c.index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(index: usize, health: f64, available: bool, priority_weight: i32) -> Candidate {
        Candidate { index, health, available, priority_weight }
    }

    #[test]
    fn equal_health_prefers_weight_then_config_order() {
        let all = [c(0, 100.0, true, 10), c(1, 100.0, true, 11), c(2, 100.0, true, 11)];
        assert_eq!(select_best(&all, 2.0), Some(1));
        let tie = [c(0, 100.0, true, 10), c(1, 100.0, true, 10)];
        assert_eq!(select_best(&tie, 2.0), Some(0));
    }

    #[test]
    fn priority_wins_within_tolerance_but_not_beyond() {
        let within = [c(0, 98.0, true, 11), c(1, 100.0, true, 10)];
        assert_eq!(select_best(&within, 2.0), Some(0));
        let beyond = [c(0, 97.9, true, 11), c(1, 100.0, true, 10)];
        assert_eq!(select_best(&beyond, 2.0), Some(1));
    }

    #[test]
    fn unavailable_providers_are_skipped_even_with_better_health() {
        let all = [c(0, 100.0, false, 11), c(1, 40.0, true, 10)];
        assert_eq!(select_best(&all, 2.0), Some(1));
    }

    #[test]
    fn all_unavailable_falls_back_to_least_bad() {
        let all = [c(0, 10.0, false, 11), c(1, 60.0, false, 9), c(2, 60.0, false, 10)];
        assert_eq!(select_best(&all, 2.0), Some(2));
    }

    #[test]
    fn empty_input_selects_nothing() {
        assert_eq!(select_best(&[], 2.0), None);
    }
}
