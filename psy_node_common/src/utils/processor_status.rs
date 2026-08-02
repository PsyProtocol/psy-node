use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc, OnceLock,
};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessorState {
    Starting = 0,
    Running = 1,
    Error = 2,
    Stopping = 3,
    Stopped = 4,
}

#[derive(Clone, Debug)]
pub struct ProcessorStatus {
    state: Arc<AtomicU8>,
    error: Arc<OnceLock<String>>,
}

impl ProcessorStatus {
    pub fn new() -> Self {
        Self {
            state: Arc::new(AtomicU8::new(ProcessorState::Starting as u8)),
            error: Arc::new(OnceLock::new()),
        }
    }

    pub fn state(&self) -> ProcessorState {
        match self.state.load(Ordering::Acquire) {
            0 => ProcessorState::Starting,
            1 => ProcessorState::Running,
            2 => ProcessorState::Error,
            3 => ProcessorState::Stopping,
            4 => ProcessorState::Stopped,
            _ => ProcessorState::Error,
        }
    }

    pub fn should_run(&self) -> bool {
        matches!(self.state(), ProcessorState::Starting | ProcessorState::Running)
    }

    pub fn error(&self) -> Option<&str> {
        self.error.get().map(String::as_str)
    }

    pub fn mark_running(&self) {
        let _ = self.state.compare_exchange(
            ProcessorState::Starting as u8,
            ProcessorState::Running as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub fn set_error(&self, error: impl Into<String>) {
        let _ = self.error.set(error.into());
        self.state.store(ProcessorState::Error as u8, Ordering::Release);
    }

    pub fn begin_shutdown(&self) {
        if self.state() != ProcessorState::Error {
            self.state.store(ProcessorState::Stopping as u8, Ordering::Release);
        }
    }

    pub fn mark_stopped(&self) {
        if self.state() != ProcessorState::Error {
            self.state.store(ProcessorState::Stopped as u8, Ordering::Release);
        }
    }
}

impl Default for ProcessorStatus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{ProcessorState, ProcessorStatus};

    #[test]
    fn error_stops_processor_and_is_not_overwritten() {
        let status = ProcessorStatus::new();

        status.mark_running();
        status.set_error("commit failed");
        status.mark_running();
        status.mark_stopped();

        assert_eq!(status.state(), ProcessorState::Error);
        assert_eq!(status.error(), Some("commit failed"));
        assert!(!status.should_run());
    }
}
