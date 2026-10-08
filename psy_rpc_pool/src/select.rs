#[derive(Clone, Copy, Debug)]
pub(crate) struct Candidate {
    pub index: usize,
    pub health: f64,
    pub available: bool,
}

/// Health first; within tolerance, declaration order is authoritative.
/// Never bypass cooldown or an occupied recovery-probe slot.
pub(crate) fn select_best(candidates: &[Candidate], tolerance: f64) -> Option<usize> {
    let open: Vec<&Candidate> = candidates.iter().filter(|c| c.available).collect();
    let best = open.iter().map(|c| c.health).max_by(f64::total_cmp)?;
    open.into_iter().filter(|c| c.health >= best - tolerance).map(|c| c.index).min()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(index: usize, health: f64, available: bool) -> Candidate {
        Candidate { index, health, available }
    }

    #[test]
    fn equal_health_prefers_config_order() {
        let all = [c(0, 100.0, true), c(1, 100.0, true), c(2, 100.0, true)];
        assert_eq!(select_best(&all, 2.0), Some(0));
    }

    #[test]
    fn priority_wins_within_tolerance_but_not_beyond() {
        let within = [c(0, 98.0, true), c(1, 100.0, true)];
        assert_eq!(select_best(&within, 2.0), Some(0));
        let beyond = [c(0, 97.9, true), c(1, 100.0, true)];
        assert_eq!(select_best(&beyond, 2.0), Some(1));
    }

    #[test]
    fn unavailable_providers_are_skipped_even_with_better_health() {
        let all = [c(0, 100.0, false), c(1, 40.0, true)];
        assert_eq!(select_best(&all, 2.0), Some(1));
    }

    #[test]
    fn all_unavailable_does_not_bypass_cooldown() {
        let all = [c(0, 10.0, false), c(1, 60.0, false)];
        assert_eq!(select_best(&all, 2.0), None);
    }

    #[test]
    fn empty_input_selects_nothing() {
        assert_eq!(select_best(&[], 2.0), None);
    }

}
