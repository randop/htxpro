#![cfg_attr(not(target_os = "linux"), allow(unused))]

#[cfg(not(target_os = "linux"))]
compile_error!(
    "websrv requires Linux and io_uring; non-io_uring runtime drivers are not supported"
);

mod config;
mod controllers;
mod http1_server;
mod http2_server;
mod http_types;
mod quic_server;
mod static_site;

use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing::info;

fn main() -> Result<()> {
    let config_path = config_path_from_args()?;
    let config = config::Config::load(&config_path)?;
    init_tracing(&config.log_filter)?;
    info!(path = %config_path.display(), "loaded YAML configuration");

    let quic_config = quic_server::make_quic_config(&config)?;
    let shutdown = quic_server::install_shutdown_handler()?;

    // Intentionally select only Monoio's io_uring driver. There is no fusion/legacy
    // mode in Cargo features, and failure to create the ring aborts startup.
    let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
        .enable_timer()
        .build()
        .context("could not initialize the mandatory io_uring runtime; check kernel support and seccomp policy")?;

    runtime.block_on(quic_server::serve(config, quic_config, shutdown))
}

fn init_tracing(log_filter: &str) -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_new(log_filter)
        .context("invalid log_filter in config.yaml")?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_target(true)
        .try_init()
        .map_err(|error| anyhow::anyhow!("could not initialize structured logging: {error}"))?;
    Ok(())
}

fn config_path_from_args() -> Result<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    let mut config_path = PathBuf::from("config.yaml");
    while let Some(arg) = args.next() {
        if arg == "--config" || arg == "-c" {
            config_path = PathBuf::from(args.next().context("--config requires a path")?);
        } else if arg == "--help" || arg == "-h" {
            println!("Usage: websrv [--config <path>]\n\nOptions:\n  -c, --config <path>  YAML configuration file (default: config.yaml)\n  -h, --help           Show this help message");
            std::process::exit(0);
        } else if let Some(value) = arg.to_str().and_then(|arg| arg.strip_prefix("--config=")) {
            config_path = PathBuf::from(value);
        } else {
            anyhow::bail!("unknown argument {:?}; use --help for usage", arg);
        }
    }
    Ok(config_path)
}
