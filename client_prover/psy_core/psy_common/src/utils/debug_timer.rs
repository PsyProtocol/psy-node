#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
const TIME_LONG: &str = "\x1b[48;5;124m";
const TIME_MEDIUM: &str = "\x1b[48;5;24m";
const TIME_FAST: &str = "\x1B[38;5;230m\x1b[48;5;34m";
fn get_time_color(elapsed_ms: u64) -> &'static str {
    if elapsed_ms > 2000 {
        TIME_LONG
    } else if elapsed_ms > 500 {
        TIME_MEDIUM
    } else {
        TIME_FAST
    }
}
pub struct DebugTimer {
    #[cfg(not(target_arch = "wasm32"))]
    pub start_time: Instant,
    pub name: String,
}

#[cfg(not(target_arch = "wasm32"))]
impl DebugTimer {
    pub fn new(name: &str) -> Self {
        let n = name.to_string();
        Self {
            start_time: Instant::now(),
            name: n,
        }
    }
    pub fn lap(&mut self, event_name: &str) -> u64 {
        let elapsed = self.start_time.elapsed();
        let elapsed_ms = elapsed.as_millis() as u64;
        println!(
            "\x1b[96m{}\x1b[0m - \x1b[94m{}\x1b[0m: {} {}ms \x1b[0m",
            self.name,
            event_name,
            get_time_color(elapsed_ms),
            elapsed_ms
        );
        self.start_time = Instant::now();
        elapsed_ms
    }
    pub fn event(&mut self, event_name: String) -> u64 {
        let elapsed = self.start_time.elapsed();
        let elapsed_ms = elapsed.as_millis() as u64;
        println!(
            "\x1b[96m{}\x1b[0m - \x1b[94m{}\x1b[0m: {} {}ms \x1b[0m",
            self.name,
            event_name,
            get_time_color(elapsed_ms),
            elapsed_ms
        );
        self.start_time = Instant::now();
        elapsed_ms
    }
    pub fn batch_average(&mut self, event_name: &str, batch_item_type: &str, batch_size: usize) -> (u64, u64) {
        let elapsed = self.start_time.elapsed();
        let elapsed_ms = elapsed.as_millis() as u64;
        println!(
            "\x1b[96m{}\x1b[0m - \x1b[94m{} ({}x - {})\x1b[0m: {} {}ms \x1b[0m",
            self.name,
            event_name,
            batch_size,
            batch_item_type,
            get_time_color(elapsed_ms),
            elapsed_ms
        );
        let per_time = ((elapsed_ms as f64) / (batch_size as f64)).floor() as u64;
        println!(
            "\x1b[96m{}\x1b[0m - \x1b[94m({}) Per {}\x1b[0m: {} {}ms \x1b[0m",
            self.name,
            event_name,
            batch_item_type,
            get_time_color(per_time),
            per_time
        );
        self.start_time = Instant::now();
        (elapsed_ms, per_time)
    }
}

#[cfg(target_arch = "wasm32")]
impl DebugTimer {
    pub fn new(name: &str) -> Self {
        let n = name.to_string();
        Self { name: n }
    }
    pub fn lap(&mut self, event_name: &str) -> u64 {
        0
    }
    pub fn event(&mut self, event_name: String) -> u64 {
        0
    }
    pub fn batch_average(&mut self, event_name: &str, batch_item_type: &str, batch_size: usize) -> (u64, u64) {
        (0, 0)
    }
}
