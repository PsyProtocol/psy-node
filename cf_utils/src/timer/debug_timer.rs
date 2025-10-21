use std::time::{Duration, Instant};

// ANSI color codes for terminal output
const TIME_LONG: &str = "\x1b[48;5;124m"; // Red background
const TIME_MEDIUM: &str = "\x1b[48;5;208m"; // Orange background
const TIME_FAST: &str = "\x1B[38;5;230m\x1b[48;5;34m"; // Light text on green background
const RESET_COLOR: &str = "\x1b[0m";
const NAME_COLOR: &str = "\x1b[96m"; // Cyan text for timer name
const EVENT_COLOR: &str = "\x1b[94m"; // Blue text for event name

/// Determines the ANSI color code based on the elapsed time in milliseconds.
fn get_time_color(elapsed_ms: u64) -> &'static str {
    if elapsed_ms > 2000 {
        TIME_LONG
    } else if elapsed_ms > 500 {
        TIME_MEDIUM
    } else {
        TIME_FAST
    }
}

/// Formats a Duration into a human-readable string, automatically selecting the best unit.
fn get_time_text(duration: Duration) -> String {
    if duration.as_secs() > 0 {
        format!("{}.{:03}s", duration.as_secs(), duration.subsec_millis())
    } else if duration.as_millis() > 0 {
        format!("{}ms", duration.as_millis())
    } else if duration.as_micros() > 0 {
        format!("{}µs", duration.as_micros())
    } else {
        format!("{}ns", duration.as_nanos())
    }
}

/// A simple utility for timing and printing the duration of operations.
///
/// It's designed for quick debugging and performance checks directly in the console.
/// The timer is reset after each `lap` or `lap_batch` call.
///
/// # Example
/// ```
/// use std::thread;
/// use std::time::Duration;
///
/// // Create a timer for the 'DataProcessing' task
/// let mut timer = DebugTimer::new("DataProcessing");
///
/// // Simulate a quick operation
/// thread::sleep(Duration::from_micros(150));
/// timer.lap_micros("Task 1: Load cache");
///
/// // Simulate a longer operation
/// thread::sleep(Duration::from_millis(600));
/// timer.lap("Task 2: Heavy computation");
///
/// // Simulate a batch operation
/// let batch_size = 1000;
/// thread::sleep(Duration::from_millis(120));
/// timer.lap_batch("Task 3: Process items", "item", batch_size);
/// ```
pub struct DebugTimer {
    #[cfg(not(target_arch = "wasm32"))]
    start_time: Instant,
    name: String,
}

#[cfg(not(target_arch = "wasm32"))]
impl DebugTimer {
    /// Creates a new `DebugTimer` with a given name and starts the timer.
    pub fn new(name: &str) -> Self {
        Self {
            start_time: Instant::now(),
            name: name.to_string(),
        }
    }

    /// Private helper to print a formatted lap time.
    fn print_lap(&self, event_name: &str, elapsed: Duration) {
        println!(
            "{}{}{RESET_COLOR} - {}{}{RESET_COLOR}: {} {} {RESET_COLOR}",
            NAME_COLOR,
            self.name,
            EVENT_COLOR,
            event_name,
            get_time_color(elapsed.as_millis() as u64),
            get_time_text(elapsed)
        );
    }

    /// Measures the time since the last lap, prints it, and resets the timer.
    /// Returns the elapsed time in milliseconds.
    pub fn lap(&mut self, event_name: &str) -> u64 {
        let elapsed = self.start_time.elapsed();
        self.print_lap(event_name, elapsed);
        self.start_time = Instant::now();
        elapsed.as_millis() as u64
    }

    /// Measures the time since the last lap, prints it, and resets the timer.
    /// Returns the elapsed time in microseconds for higher precision.
    pub fn lap_micros(&mut self, event_name: &str) -> u128 {
        let elapsed = self.start_time.elapsed();
        self.print_lap(event_name, elapsed);
        self.start_time = Instant::now();
        elapsed.as_micros()
    }
    /// Measures the time since the last lap, prints it, and resets the timer.
    /// Returns the elapsed time in milliseconds.
    pub fn event(&mut self, event_name: String) -> u64 {
        self.lap(&event_name)
    }

    /// Measures the time since the last lap, prints it, and resets the timer.
    /// Returns the elapsed time in microseconds for higher precision.
    pub fn event_micros(&mut self, event_name: String) -> u128 {
        self.lap_micros(&event_name)
    }

    /// Measures and prints detailed stats for a batch operation, then resets the timer.
    ///
    /// This method prints three lines:
    /// 1. The total time taken for the entire batch.
    /// 2. The average time per item.
    /// 3. The throughput in items per second.
    ///
    /// Returns a tuple of `(total_duration, average_per_item_duration)`.
    pub fn lap_batch(
        &mut self,
        event_name: &str,
        item_type: &str,
        batch_size: usize,
    ) -> (Duration, Duration) {
        let elapsed = self.start_time.elapsed();
        self.start_time = Instant::now();

        // Handle case where batch size is 0 to avoid division by zero.
        if batch_size == 0 {
            println!(
                "{}{}{RESET_COLOR} - {}{} (0x {}){RESET_COLOR}: Batch size is zero, cannot calculate average.",
                NAME_COLOR, self.name, EVENT_COLOR, event_name, item_type
            );
            return (elapsed, Duration::new(0, 0));
        }

        // 1. Print total time for the batch
        println!(
            "{}{}{RESET_COLOR} - {}{} ({}x {}){RESET_COLOR}: {} {} {RESET_COLOR}",
            NAME_COLOR,
            self.name,
            EVENT_COLOR,
            event_name,
            batch_size,
            item_type,
            get_time_color(elapsed.as_millis() as u64),
            get_time_text(elapsed)
        );

        // 2. Calculate and print average time per item
        let per_item_duration = elapsed.div_f64(batch_size as f64);
        println!(
            "{}{}{RESET_COLOR} - {}(Avg per {}){RESET_COLOR}: {} {} {RESET_COLOR}",
            NAME_COLOR,
            self.name,
            EVENT_COLOR,
            item_type,
            get_time_color(per_item_duration.as_millis() as u64),
            get_time_text(per_item_duration)
        );
        
        // 3. Calculate and print throughput
        // Avoid division by zero if elapsed time is virtually zero.
        let elapsed_secs = elapsed.as_secs_f64();
        if elapsed_secs > 0.0 {
            let throughput = batch_size as f64 / elapsed_secs;
            println!(
                "{}{}{RESET_COLOR} - {}(Throughput){RESET_COLOR}: {:.2} {}s/sec",
                NAME_COLOR, self.name, EVENT_COLOR, throughput, item_type
            );
        }

        (elapsed, per_item_duration)
    }
    pub fn event_batch(
        &mut self,
        event_name: String,
        item_type: String,
        batch_size: usize,
    ) -> (Duration, Duration) {
        self.lap_batch(&event_name, &item_type, batch_size)
    }
    pub fn event_batch_event_ref(
        &mut self,
        event_name: &str,
        item_type: String,
        batch_size: usize,
    ) -> (Duration, Duration) {
        self.lap_batch(event_name, &item_type, batch_size)
    }
    pub fn event_batch_item_ref(
        &mut self,
        event_name: String,
        item_type: &str,
        batch_size: usize,
    ) -> (Duration, Duration) {
        self.lap_batch(&event_name, item_type, batch_size)
    }
}

// Dummy struct and functions for wasm32 to allow code to compile.
#[cfg(target_arch = "wasm32")]
impl DebugTimer {
    pub fn new(_name: &str) -> Self { Self }
    pub fn lap(&mut self, _event_name: &str) -> u64 { 0 }
    pub fn lap_micros(&mut self, _event_name: &str) -> u128 { 0 }
    pub fn lap_batch(&mut self, _event_name: &str, _item_type: &str, _batch_size: usize) -> (Duration, Duration) {
        (Duration::new(0,0), Duration::new(0,0))
    }
}
#[cfg(target_arch = "wasm32")]
pub struct DebugTimer;

