use serde::Serialize;

/// One recorded duration sample in milliseconds.
#[derive(Debug, Default)]
pub struct LatencySamples {
    samples: Vec<u64>,
}

impl LatencySamples {
    pub fn record(&mut self, elapsed: std::time::Duration) {
        self.samples.push(elapsed.as_millis() as u64);
    }

    pub fn summarize(&self) -> Option<LatencySummary> {
        summarize(&self.samples)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LatencySummary {
    pub count: usize,
    pub min_ms: u64,
    pub max_ms: u64,
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub p99_ms: u64,
}

/// Nearest-rank percentile over a sorted-or-sortable sample set.
pub fn percentile(sorted: &[u64], pct: f64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((pct / 100.0) * sorted.len() as f64).ceil() as usize;
    let rank = rank.clamp(1, sorted.len());
    Some(sorted[rank - 1])
}

pub fn summarize(samples: &[u64]) -> Option<LatencySummary> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    Some(LatencySummary {
        count: sorted.len(),
        min_ms: sorted[0],
        max_ms: sorted[sorted.len() - 1],
        p50_ms: percentile(&sorted, 50.0)?,
        p95_ms: percentile(&sorted, 95.0)?,
        p99_ms: percentile(&sorted, 99.0)?,
    })
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ScenarioCounts {
    pub initiated: u64,
    pub submitted: u64,
    pub included: u64,
    pub failed: u64,
    pub unknown: u64,
}

/// Secret-free benchmark report. RPC acceptance is not checkpoint inclusion:
/// `submitted` counts RPC acceptance while `included` counts EndCaps committed
/// in a Coordinator-authenticated checkpoint.
#[derive(Debug, Clone, Serialize)]
pub struct ScenarioReport {
    pub scenario: String,
    pub network: String,
    pub started_at_unix_ms: i64,
    pub finished_at_unix_ms: i64,
    pub wall_window_ms: u64,
    pub counts: ScenarioCounts,
    pub submit_latency_ms: Option<LatencySummary>,
    pub include_latency_ms: Option<LatencySummary>,
    pub trace_latency_ms: Option<LatencySummary>,
    pub prove_latency_ms: Option<LatencySummary>,
    pub notes: Vec<String>,
}

impl ScenarioReport {
    pub fn new(scenario: &str, network: &str, started_at_unix_ms: i64) -> Self {
        Self {
            scenario: scenario.to_string(),
            network: network.to_string(),
            started_at_unix_ms,
            finished_at_unix_ms: started_at_unix_ms,
            wall_window_ms: 0,
            counts: ScenarioCounts::default(),
            submit_latency_ms: None,
            include_latency_ms: None,
            trace_latency_ms: None,
            prove_latency_ms: None,
            notes: Vec::new(),
        }
    }

    pub fn finish(&mut self, finished_at_unix_ms: i64) {
        self.finished_at_unix_ms = finished_at_unix_ms;
        self.wall_window_ms = (finished_at_unix_ms - self.started_at_unix_ms).max(0) as u64;
    }
}

pub fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

/// Render a duration in milliseconds compactly: sub-second stays in ms,
/// anything longer switches to fractional seconds.
fn fmt_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{:.2}s", ms as f64 / 1000.0)
    }
}

fn fmt_latency_line(label: &str, summary: &LatencySummary) -> String {
    format!(
        "{label}: n={} p50={} p95={} p99={} min={} max={}",
        summary.count,
        fmt_ms(summary.p50_ms),
        fmt_ms(summary.p95_ms),
        fmt_ms(summary.p99_ms),
        fmt_ms(summary.min_ms),
        fmt_ms(summary.max_ms),
    )
}

const SUMMARY_NOTE_MAX_CHARS: usize = 160;

fn truncate_note(note: &str) -> String {
    if note.chars().count() <= SUMMARY_NOTE_MAX_CHARS {
        return note.to_string();
    }
    let truncated: String = note.chars().take(SUMMARY_NOTE_MAX_CHARS).collect();
    format!("{truncated} ...")
}

/// Human-readable end-of-run summary; the full JSON report stays available
/// through `--report-file`.
pub fn format_summary(report: &ScenarioReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!("==== {} summary ({}) ====", report.scenario, report.network));
    lines.push(format!("wall: {}", fmt_ms(report.wall_window_ms)));
    let counts = &report.counts;
    lines.push(format!(
        "initiated: {}  submitted: {}  included: {}  failed: {}  unknown: {}",
        counts.initiated, counts.submitted, counts.included, counts.failed, counts.unknown
    ));
    if report.wall_window_ms > 0 && counts.included > 0 {
        let wall_secs = report.wall_window_ms as f64 / 1000.0;
        lines.push(format!("throughput: {:.2} included/s", counts.included as f64 / wall_secs));
    }
    for (label, latency) in [
        ("submit", &report.submit_latency_ms),
        ("include", &report.include_latency_ms),
        ("trace", &report.trace_latency_ms),
        ("prove", &report.prove_latency_ms),
    ] {
        if let Some(summary) = latency {
            lines.push(fmt_latency_line(label, summary));
        }
    }
    if !report.notes.is_empty() {
        lines.push(format!("notes ({}):", report.notes.len()));
        for note in &report.notes {
            lines.push(format!("  - {}", truncate_note(note)));
        }
    }
    lines.join("\n")
}

pub fn print_summary(report: &ScenarioReport) -> anyhow::Result<()> {
    println!("{}", format_summary(report));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_nearest_rank() {
        let sorted: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&sorted, 50.0), Some(50));
        assert_eq!(percentile(&sorted, 95.0), Some(95));
        assert_eq!(percentile(&sorted, 99.0), Some(99));
        assert_eq!(percentile(&sorted, 100.0), Some(100));
        assert_eq!(percentile(&[], 50.0), None);
        assert_eq!(percentile(&[7], 99.0), Some(7));
    }

    #[test]
    fn summarize_reports_min_max_and_percentiles() {
        let summary = summarize(&[10, 20, 30, 40, 50]).unwrap();
        assert_eq!(summary.count, 5);
        assert_eq!(summary.min_ms, 10);
        assert_eq!(summary.max_ms, 50);
        assert_eq!(summary.p50_ms, 30);
        assert_eq!(summarize(&[]), None);
    }

    #[test]
    fn report_serializes_without_secrets() {
        let mut report = ScenarioReport::new("endcap", "localhost", 1_700_000_000_000);
        report.counts.submitted = 2;
        report.counts.included = 1;
        report.finish(1_700_000_120_000);
        let rendered = serde_json::to_string(&report).unwrap();
        assert!(!rendered.contains("private_key"));
        assert!(!rendered.contains("password"));
        assert_eq!(report.wall_window_ms, 120_000);
    }

    #[test]
    fn summary_renders_counts_throughput_latencies_and_truncates_notes() {
        let mut report = ScenarioReport::new("faucet", "staging", 1_000);
        report.counts = ScenarioCounts { initiated: 4, submitted: 4, included: 3, failed: 1, unknown: 0 };
        report.submit_latency_ms = summarize(&[100, 200, 300, 400]);
        report.notes.push("short note".to_string());
        report.notes.push("x".repeat(500));
        report.finish(2_000);
        let text = format_summary(&report);
        assert!(text.contains("faucet summary (staging)"));
        assert!(text.contains("wall: 1.00s"));
        assert!(text.contains("initiated: 4  submitted: 4  included: 3  failed: 1  unknown: 0"));
        assert!(text.contains("throughput: 3.00 included/s"));
        assert!(text.contains("submit: n=4 p50=200ms"));
        assert!(text.contains("notes (2):"));
        assert!(text.contains("- short note"));
        assert!(!text.contains(&"x".repeat(200)));
    }
}
