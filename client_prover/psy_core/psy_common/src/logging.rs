use std::sync::Once;

use tracing_subscriber::{prelude::*, EnvFilter};

static INIT: Once = Once::new();

pub fn setup_logging() -> anyhow::Result<()> {
    INIT.call_once(|| {
        let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_file(true)
            .with_line_number(true)
            .with_target(false)
            .with_ansi(false);

        tracing_subscriber::registry().with(env_filter).with(fmt_layer).init();
    });

    Ok(())
}
