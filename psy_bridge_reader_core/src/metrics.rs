//! Prometheus metrics of the Reader: one registry, typed update helpers and
//! the text exposition rendering served on `/metrics`.

use prometheus::{
    Encoder, Gauge, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder,
};
use psy_bridge_reader_api::Lane;

/// Metrics registry plus handles. Cloning is cheap (the handles are `Arc`s)
/// and every clone updates the same series.
///
/// Label rule (design section 10): labels are only `chain_id`, `chain_index`,
/// `reason`, `lane`, `endpoint`, `status` and `code`. No address, hash or
/// nullifier is ever a label value.
#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    memory_budget_bytes: u64,
    follow_lag_blocks: IntGaugeVec,
    view_age_seconds: Gauge,
    tick_seconds: Histogram,
    window_rows: IntGaugeVec,
    reorgs_total: IntCounter,
    tree_mismatch_total: IntCounter,
    reloads_total: IntCounterVec,
    startup_seconds: Gauge,
    resident_bytes: IntGauge,
    resident_budget_ratio: Gauge,
    process_rss_bytes: IntGauge,
    lane_queue: IntGaugeVec,
    lane_in_flight: IntGaugeVec,
    requests_total: IntCounterVec,
    request_seconds: HistogramVec,
    shed_total: IntCounterVec,
}

fn status_class(status: u16) -> &'static str {
    match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    }
}

const NS: &str = "psy_bridge_reader";

impl Metrics {
    /// `memory_budget_bytes` is the denominator of `resident_budget_ratio`.
    pub fn new(memory_budget_bytes: u64) -> Metrics {
        let registry = Registry::new();
        let opts = |name: &str, help: &str| Opts::new(name, help).namespace(NS);
        let hopts = |name: &str, help: &str| HistogramOpts::new(name, help).namespace(NS);
        // Registration of statically valid, distinct metrics cannot fail.
        macro_rules! reg {
            ($m:expr) => {{
                let m = $m.expect("valid metric definition");
                registry.register(Box::new(m.clone())).expect("unique metric name");
                m
            }};
        }
        let latency = vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];
        Metrics {
            memory_budget_bytes,
            follow_lag_blocks: reg!(IntGaugeVec::new(
                opts("follow_lag_blocks", "Envio progress minus Reader revision, in blocks."),
                &["chain_id"]
            )),
            view_age_seconds: reg!(Gauge::with_opts(opts(
                "view_age_seconds",
                "Age of the published view."
            ))),
            tick_seconds: reg!(Histogram::with_opts(
                hopts("tick_seconds", "Duration of one follow tick.").buckets(latency.clone())
            )),
            window_rows: reg!(IntGaugeVec::new(
                opts("window_rows", "Rows in the re-read window."),
                &["chain_index"]
            )),
            reorgs_total: reg!(IntCounter::with_opts(opts("reorgs_total", "Reorgs observed."))),
            tree_mismatch_total: reg!(IntCounter::with_opts(opts(
                "tree_mismatch_total",
                "Tree root mismatches against Envio."
            ))),
            reloads_total: reg!(IntCounterVec::new(
                opts("reloads_total", "Reloads by reason."),
                &["reason"]
            )),
            startup_seconds: reg!(Gauge::with_opts(opts(
                "startup_seconds",
                "Duration of start-up."
            ))),
            resident_bytes: reg!(IntGauge::with_opts(opts(
                "resident_bytes",
                "Estimated resident data bytes."
            ))),
            resident_budget_ratio: reg!(Gauge::with_opts(opts(
                "resident_budget_ratio",
                "resident_bytes divided by the memory budget."
            ))),
            process_rss_bytes: reg!(IntGauge::with_opts(opts(
                "process_rss_bytes",
                "Process resident set size."
            ))),
            lane_queue: reg!(IntGaugeVec::new(
                opts("lane_queue", "Requests waiting in a lane."),
                &["lane"]
            )),
            lane_in_flight: reg!(IntGaugeVec::new(
                opts("lane_in_flight", "Requests running in a lane."),
                &["lane"]
            )),
            requests_total: reg!(IntCounterVec::new(
                opts("requests_total", "Requests by endpoint, lane and status class."),
                &["endpoint", "lane", "status"]
            )),
            request_seconds: reg!(HistogramVec::new(
                hopts("request_seconds", "Request latency.").buckets(latency),
                &["endpoint", "lane"]
            )),
            shed_total: reg!(IntCounterVec::new(
                opts("shed_total", "Requests shed by lane and code."),
                &["lane", "code"]
            )),
            registry,
        }
    }

    pub fn set_follow_lag_blocks(&self, chain_id: u64, blocks: i64) {
        self.follow_lag_blocks.with_label_values(&[&chain_id.to_string()]).set(blocks);
    }

    pub fn set_view_age_seconds(&self, seconds: f64) {
        self.view_age_seconds.set(seconds);
    }

    pub fn observe_tick(&self, seconds: f64) {
        self.tick_seconds.observe(seconds);
    }

    pub fn set_window_rows(&self, chain_index: u64, rows: i64) {
        self.window_rows.with_label_values(&[&chain_index.to_string()]).set(rows);
    }

    /// Drops every `chain_id` and `chain_index` series, after a full reset.
    pub fn clear_chain_gauges(&self) {
        self.follow_lag_blocks.reset();
        self.window_rows.reset();
    }

    pub fn inc_reorgs(&self) {
        self.reorgs_total.inc();
    }

    pub fn inc_tree_mismatch(&self) {
        self.tree_mismatch_total.inc();
    }

    pub fn inc_reload(&self, reason: &'static str) {
        self.reloads_total.with_label_values(&[reason]).inc();
    }

    pub fn set_startup_seconds(&self, seconds: f64) {
        self.startup_seconds.set(seconds);
    }

    /// Sets the resident bytes and the ratio to the memory budget together.
    pub fn set_resident_bytes(&self, bytes: u64) {
        self.resident_bytes.set(i64::try_from(bytes).unwrap_or(i64::MAX));
        let ratio = if self.memory_budget_bytes == 0 {
            0.0
        } else {
            bytes as f64 / self.memory_budget_bytes as f64
        };
        self.resident_budget_ratio.set(ratio);
    }

    /// Reads the resident set size from `/proc/self/statm`; on other
    /// platforms or on a read failure the gauge is left unchanged.
    pub fn refresh_process_rss(&self) {
        if let Some(bytes) = read_process_rss() {
            self.process_rss_bytes.set(i64::try_from(bytes).unwrap_or(i64::MAX));
        }
    }

    pub fn set_lane_queue(&self, lane: Lane, len: i64) {
        self.lane_queue.with_label_values(&[lane.as_str()]).set(len);
    }

    pub fn set_lane_in_flight(&self, lane: Lane, count: i64) {
        self.lane_in_flight.with_label_values(&[lane.as_str()]).set(count);
    }

    /// Counts a finished request (status bucketed by class) and records its
    /// latency.
    pub fn observe_request(&self, endpoint: &'static str, lane: Lane, status: u16, seconds: f64) {
        let lane = lane.as_str();
        self.requests_total
            .with_label_values(&[endpoint, lane, status_class(status)])
            .inc();
        self.request_seconds.with_label_values(&[endpoint, lane]).observe(seconds);
    }

    pub fn inc_shed(&self, lane: Lane, code: &'static str) {
        self.shed_total.with_label_values(&[lane.as_str(), code]).inc();
    }

    /// Text exposition format, for `/metrics`.
    pub fn render(&self) -> String {
        let mut out = Vec::new();
        if TextEncoder::new().encode(&self.registry.gather(), &mut out).is_err() {
            return String::new();
        }
        String::from_utf8(out).unwrap_or_default()
    }
}

#[cfg(target_os = "linux")]
fn read_process_rss() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    // SAFETY: sysconf has no preconditions.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page = u64::try_from(page).ok().filter(|p| *p > 0)?;
    Some(pages * page)
}

#[cfg(not(target_os = "linux"))]
fn read_process_rss() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value_of(text: &str, series: &str) -> Option<f64> {
        text.lines()
            .find_map(|l| l.strip_prefix(series).and_then(|r| r.trim().parse().ok()))
    }

    #[test]
    fn render_contains_every_metric_name() {
        let m = Metrics::new(1000);
        m.set_follow_lag_blocks(1, 2);
        m.set_view_age_seconds(0.5);
        m.observe_tick(0.1);
        m.set_window_rows(0, 3);
        m.inc_reorgs();
        m.inc_tree_mismatch();
        m.inc_reload("identity_changed");
        m.set_startup_seconds(1.0);
        m.set_resident_bytes(10);
        m.refresh_process_rss();
        m.set_lane_queue(Lane::Background, 1);
        m.set_lane_in_flight(Lane::ClaimProof, 1);
        m.observe_request("deposits", Lane::Interactive, 200, 0.01);
        m.inc_shed(Lane::Background, "queue_full");
        let text = m.render();
        for name in [
            "follow_lag_blocks",
            "view_age_seconds",
            "tick_seconds",
            "window_rows",
            "reorgs_total",
            "tree_mismatch_total",
            "reloads_total",
            "startup_seconds",
            "resident_bytes",
            "resident_budget_ratio",
            "process_rss_bytes",
            "lane_queue",
            "lane_in_flight",
            "requests_total",
            "request_seconds",
            "shed_total",
        ] {
            let full = format!("psy_bridge_reader_{name}");
            assert!(text.contains(&full), "missing {full}");
        }
    }

    #[test]
    fn clear_chain_gauges_drops_every_chain_series() {
        let m = Metrics::new(1);
        m.set_follow_lag_blocks(1, 2);
        m.set_window_rows(3, 4);
        m.clear_chain_gauges();
        let text = m.render();
        assert!(!text.contains("chain_id=\"1\""), "{text}");
        assert!(!text.contains("chain_index=\"3\""), "{text}");
        m.set_window_rows(5, 6);
        assert_eq!(value_of(&m.render(), "psy_bridge_reader_window_rows{chain_index=\"5\"} "), Some(6.0));
    }

    #[test]
    fn budget_ratio_follows_resident_bytes() {
        let m = Metrics::new(1000);
        m.set_resident_bytes(400);
        let text = m.render();
        assert_eq!(value_of(&text, "psy_bridge_reader_resident_bytes "), Some(400.0));
        assert_eq!(value_of(&text, "psy_bridge_reader_resident_budget_ratio "), Some(0.4));
    }

    #[test]
    fn request_status_is_bucketed_by_class() {
        let m = Metrics::new(1);
        m.observe_request("deposits", Lane::Interactive, 200, 0.0);
        m.observe_request("deposits", Lane::Interactive, 409, 0.0);
        m.observe_request("deposits", Lane::Interactive, 503, 0.0);
        let text = m.render();
        for class in ["2xx", "4xx", "5xx"] {
            let s = format!(
                "psy_bridge_reader_requests_total{{endpoint=\"deposits\",lane=\"interactive\",status=\"{class}\"}} "
            );
            assert_eq!(value_of(&text, &s), Some(1.0), "{class}");
        }
        assert!(!text.contains("status=\"200\""));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rss_refresh_reports_a_positive_value_on_linux() {
        let m = Metrics::new(1);
        m.refresh_process_rss();
        let v = value_of(&m.render(), "psy_bridge_reader_process_rss_bytes ").unwrap();
        assert!(v > 0.0);
    }
}
