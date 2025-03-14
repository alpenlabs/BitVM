use tracing::*;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

/// Initializes the logging subsystem with the provided config.
pub fn init() {
    let filt = tracing_subscriber::EnvFilter::from_default_env();

    // Stdout logging.
    let stdout_sub = tracing_subscriber::fmt::layer().compact().with_filter(filt);

    tracing_subscriber::registry().with(stdout_sub).init();

    info!("logging started");
}