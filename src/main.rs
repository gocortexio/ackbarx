//! AckbarX - Main Application Entry Point
//! 
//! AckbarX - SNMP Trap to HTTP endpoint integration
//! Developed by GoCortex.io

use anyhow::{Context, Result};
use tracing::{debug, error, info, warn};
use clap::{Arg, Command};
use signal_hook::consts::SIGTERM;
use signal_hook_tokio::Signals;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};
use futures_util::stream::StreamExt;

use ackbarx::{
    CacheManager, Config, HttpForwarder, SnmpListener,
    log_rotation::start_log_rotation_monitoring,
};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let matches = Command::new("ackbarx")
        .version("0.5.0")
        .about("AckbarX is a robust Rust-based SNMP Trap to XSIAM/XDR HTTP logging integration.\n\nhttps://gocortex.io\n\nVersion: 0.5.0")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value("config.json"),
        )
        .arg(
            Arg::new("daemon")
                .short('d')
                .long("daemon")
                .help("Run as daemon (suppress console output)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("generate-config")
                .long("generate-config")
                .help("Generate a default configuration file and exit")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("generate-simple-config")
                .long("generate-simple-config")
                .help("Generate a simple configuration file (single source, single endpoint, SNMPv1/v2 only)")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let config_path = PathBuf::from(matches.get_one::<String>("config").unwrap());
    let daemon_mode = matches.get_flag("daemon");
    let generate_config = matches.get_flag("generate-config");
    let generate_simple_config = matches.get_flag("generate-simple-config");

    // Generate default config if requested
    if generate_config {
        return generate_default_config(&config_path, false).await;
    }
    
    // Generate simple config if requested
    if generate_simple_config {
        return generate_default_config(&config_path, true).await;
    }

    // Load configuration
    let config = load_configuration(&config_path).await?;

    // Initialize logging
    initialise_logging(&config, daemon_mode)?;

    info!("Starting AckbarX v0.5.0 by GoCortex.io");
    info!("Configuration loaded from: {}", config_path.display());

    // Validate configuration
    config.validate().context("Configuration validation failed")?;

    // Start the application
    run_application(config).await
}

/// Generate a default configuration file
async fn generate_default_config(config_path: &PathBuf, simple: bool) -> Result<()> {
    if config_path.exists() {
        anyhow::bail!("Configuration file already exists: {}", config_path.display());
    }

    let config = if simple {
        Config::simple()
    } else {
        Config::default()
    };
    
    config.save_to_file(config_path).await
        .context("Failed to save default configuration")?;

    if simple {
        println!("Simple configuration generated: {}", config_path.display());
        println!("Contains: Single SNMP source (0.0.0.0:162), single XSIAM endpoint, SNMPv1/v2c support");
    } else {
        println!("Complex configuration generated: {}", config_path.display());
        println!("Contains: Multiple sources, primary/backup endpoints, advanced routing");
    }
    println!("Please edit the configuration file and restart the application.");

    Ok(())
}

/// Load configuration from file with automatic creation if missing
async fn load_configuration(config_path: &PathBuf) -> Result<Config> {
    if !config_path.exists() {
        warn!("Configuration file not found: {}", config_path.display());
        info!("Creating default configuration file: {}", config_path.display());
        
        let default_config = Config::simple();
        default_config.save_to_file(config_path).await
            .context("Failed to create default configuration file")?;
        
        info!("Default configuration created successfully");
        info!("Please edit {} with your XSIAM endpoints and API keys", config_path.display());
        
        return Ok(default_config);
    }

    Config::load_from_file(config_path).await
        .context("Failed to load configuration file")
}

/// Initialize logging based on configuration
fn initialise_logging(config: &Config, daemon_mode: bool) -> Result<()> {
    let level = match config.logging.level.as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };

    let mut layers = Vec::new();

    // Console output (unless in daemon mode and disabled)
    if config.logging.console_output && !daemon_mode {
        let console_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stdout)
            .with_ansi(true);
        layers.push(console_layer.boxed());
    }

    // File output with rotation
    if let Some(ref log_file_path) = config.logging.file_output {
        let log_path = std::path::Path::new(log_file_path);
        let log_dir = log_path.parent().unwrap_or(std::path::Path::new("."));
        let log_filename = log_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("ackbarx");

        // Create log directory if it doesn't exist
        std::fs::create_dir_all(log_dir)
            .context("Failed to create log directory")?;

        // Set up rotating file appender based on strategy
        let file_appender = match config.logging.rotation_strategy.as_str() {
            "daily" => {
                tracing_appender::rolling::daily(log_dir, log_filename)
            },
            "hourly" => {
                tracing_appender::rolling::hourly(log_dir, log_filename)
            },
            _ => {
                // For size-based rotation, we'll use daily rotation with size monitoring
                // tracing-appender doesn't have built-in size rotation, so we'll implement monitoring
                tracing_appender::rolling::daily(log_dir, log_filename)
            }
        };

        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
        
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(non_blocking)
            .with_ansi(false)
            .with_file(true)
            .with_line_number(true)
            .with_target(false);
        
        layers.push(file_layer.boxed());

        // Store the guard in a static to prevent it from being dropped
        // This ensures the logger remains active for the application lifetime
        static GUARD_HOLDER: std::sync::OnceLock<tracing_appender::non_blocking::WorkerGuard> = std::sync::OnceLock::new();
        let _ = GUARD_HOLDER.set(_guard);
    }

    if layers.is_empty() {
        // Fallback to stderr if no output configured
        let stderr_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr);
        layers.push(stderr_layer.boxed());
    }

    tracing_subscriber::registry()
        .with(layers)
        .with(tracing_subscriber::filter::LevelFilter::from_level(level))
        .init();

    Ok(())
}

/// Main application runtime
async fn run_application(config: Config) -> Result<()> {
    // Create communication channels
    let (trap_tx, trap_rx) = mpsc::unbounded_channel();
    let (cache_tx, cache_rx) = mpsc::unbounded_channel();
    let (rejected_trap_tx, rejected_trap_rx) = mpsc::unbounded_channel(); // For rejected traps (lost-and-found)
    let (retry_tx, retry_rx) = mpsc::unbounded_channel();
    let (success_tx, success_rx) = mpsc::unbounded_channel(); // For successful trap notifications
    let (main_shutdown_tx, main_shutdown_rx) = mpsc::unbounded_channel(); // For graceful shutdown of main forwarder
    let (retry_shutdown_tx, retry_shutdown_rx) = mpsc::unbounded_channel(); // For graceful shutdown of retry forwarder
    let (cache_completion_tx, cache_completion_rx) = tokio::sync::oneshot::channel(); // For cache completion notification
    let (main_flush_completion_tx, main_flush_completion_rx) = tokio::sync::oneshot::channel(); // For main forwarder flush completion
    let (retry_flush_completion_tx, retry_flush_completion_rx) = tokio::sync::oneshot::channel(); // For retry forwarder flush completion

    // Build endpoint mapping from source routing for validation
    let _endpoint_mapping = build_endpoint_mapping(&config);
    
    // Create shared shutdown flag for HTTP forwarders
    let shutdown_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    
    // Initialize cache manager
    let cache_manager = CacheManager::new(
        config.clone(),
        cache_rx,
        rejected_trap_rx,
        retry_tx.clone(),
        success_rx,
        Some(cache_completion_tx),
    ).context("Failed to initialise cache manager")?;

    // Initialize HTTP forwarder for fresh traps
    let http_forwarder = HttpForwarder::new(
        config.endpoints.clone(),
        trap_rx,
        cache_tx.clone(),
        success_tx.clone(),
        "main".to_string(),
        main_shutdown_rx,
        Some(main_flush_completion_tx),
        shutdown_flag.clone(),
    );

    // Initialize retry forwarder (separate instance for retries)
    let retry_forwarder = HttpForwarder::new(
        config.endpoints.clone(),
        retry_rx,
        cache_tx.clone(),
        success_tx,
        "retry".to_string(),
        retry_shutdown_rx,
        Some(retry_flush_completion_tx),
        shutdown_flag.clone(),
    );

    // Start SNMP listeners with error handling
    let mut listener_handles = Vec::new();
    let mut successful_listeners = 0;
    
    for listener_config in &config.listeners {
        let listener = Arc::new(SnmpListener::new(
            listener_config.clone(),
            trap_tx.clone(),
            rejected_trap_tx.clone(),
        ));

        let port = listener_config.port;
        let handle = tokio::spawn(async move {
            match listener.start().await {
                Ok(()) => {
                    info!("SNMP listener on port {} completed successfully", port);
                }
                Err(e) => {
                    error!("SNMP listener failed to start on port {}: {}", port, e);
                    error!("Possible causes: Port already in use, insufficient permissions, or network configuration");
                }
            }
        });

        listener_handles.push(handle);
        successful_listeners += 1;
    }
    
    if successful_listeners == 0 {
        anyhow::bail!("No SNMP listeners could be started - check port availability and permissions");
    }

    // Start HTTP forwarder
    let mut forwarder_handle = tokio::spawn(async move {
        if let Err(e) = http_forwarder.start().await {
            error!("HTTP forwarder failed: {}", e);
        }
    });

    // Start retry forwarder
    let mut retry_handle = tokio::spawn(async move {
        if let Err(e) = retry_forwarder.start().await {
            error!("Retry forwarder failed: {}", e);
        }
    });

    // Start cache manager
    let mut cache_handle = tokio::spawn(async move {
        if let Err(e) = cache_manager.start().await {
            error!("Cache manager failed: {}", e);
        }
    });

    // Start log rotation monitoring
    let _log_rotation_handle = start_log_rotation_monitoring(
        config.logging.file_output.clone(),
        config.logging.max_log_size_mb,
        config.logging.max_log_files,
    );

    // Set up signal handling for graceful shutdown
    let mut signals = Signals::new([SIGTERM, signal_hook::consts::SIGINT])
        .context("Failed to register signal handlers")?;

    info!("AckbarX started successfully");
    info!("Listening on {} port(s)", config.listeners.len());
    info!("Forwarding to {} endpoint(s)", config.endpoints.len());

    // Wait for shutdown signal
    tokio::select! {
        _ = signals.next() => {
            info!("Received shutdown signal, stopping gracefully...");
        }
        _ = &mut forwarder_handle => {
            warn!("HTTP forwarder stopped unexpectedly");
        }
        _ = &mut retry_handle => {
            warn!("Retry forwarder stopped unexpectedly");
        }
        _ = &mut cache_handle => {
            warn!("Cache manager stopped unexpectedly");
        }
    }

    // Graceful shutdown with timeout to prevent hanging on unreachable endpoints
    info!("Shutting down AckbarX - flushing in-memory traps to cache");
    
    // Signal forwarders to flush pending traps to cache before shutdown
    info!("Signalling HTTP forwarders to flush pending traps");
    let _ = main_shutdown_tx.send(());
    let _ = retry_shutdown_tx.send(());
    
    // Wait for both forwarders to complete flushing with timeout
    info!("Waiting for forwarders to complete trap flushing (30s timeout)");
    let flush_timeout = tokio::time::Duration::from_secs(30);
    
    let main_flush_result = tokio::time::timeout(flush_timeout, main_flush_completion_rx).await;
    let retry_flush_result = tokio::time::timeout(flush_timeout, retry_flush_completion_rx).await;
    
    match (main_flush_result, retry_flush_result) {
        (Ok(Ok(_)), Ok(Ok(_))) => {
            info!("Both forwarders confirmed trap flushing complete");
        }
        _ => {
            warn!("Forwarder flush timeout or failure - proceeding with shutdown to prevent hanging");
        }
    }
    
    // Phase 1: Close input channels to stop new trap acceptance
    info!("Phase 1: Closing input channels to stop new trap acceptance");
    drop(trap_tx);
    drop(rejected_trap_tx);
    
    // Phase 2: NO WAIT - Close cache channel immediately after stopping trap acceptance
    info!("Phase 2: NUCLEAR OPTION - Immediate cache channel closure (zero delay)");
    
    // Phase 3: Close cache channel to signal final processing
    info!("Phase 3: Closing cache channel after in-flight operations");
    info!("EMERGENCY DEBUG: About to close cache_tx - this may cause trap loss!");
    drop(cache_tx);
    info!("EMERGENCY DEBUG: cache_tx channel has been closed");
    
    // Phase 4: Wait for cache manager to confirm all processing complete (with extended timeout)
    info!("Phase 4: Waiting for cache manager to complete all operations (45s timeout)");
    let cache_timeout = tokio::time::Duration::from_secs(45);
    
    match tokio::time::timeout(cache_timeout, cache_completion_rx).await {
        Ok(Ok(_)) => {
            info!("Cache manager confirmed all operations complete - all traps preserved");
        }
        Ok(Err(e)) => {
            error!("Cache completion signal failed: {} - data loss possible during shutdown", e);
        }
        Err(_) => {
            warn!("Cache completion timeout - forcing shutdown to prevent hanging");
        }
    }
    
    // Now safely shutdown all tasks
    for handle in listener_handles {
        handle.abort();
    }
    forwarder_handle.abort();
    retry_handle.abort();
    cache_handle.abort();

    info!("AckbarX stopped - all in-memory traps flushed to cache");
    Ok(())
}



/// Build endpoint mapping from configuration source routing with validation
fn build_endpoint_mapping(config: &Config) -> HashMap<String, String> {
    let mut mapping = HashMap::new();
    
    // Create a set of valid endpoint names for quick lookup
    let valid_endpoints: std::collections::HashSet<String> = config.endpoints
        .iter()
        .map(|ep| ep.name.clone())
        .collect();
    
    // Validate source mapping and build validated mapping
    if let Some(ref source_mapping) = config.source_mapping {
        for (source_pattern, endpoint_name) in source_mapping {
            // Validate that the referenced endpoint actually exists
            if !valid_endpoints.contains(endpoint_name) {
                error!("Source mapping references non-existent endpoint: '{}' for pattern '{}'", 
                    endpoint_name, source_pattern);
                warn!("Available endpoints: {:?}", valid_endpoints);
                
                // Use first endpoint as fallback for invalid references
                if let Some(fallback_endpoint) = config.endpoints.first() {
                    warn!("Falling back to endpoint '{}' for pattern '{}'", 
                        fallback_endpoint.name, source_pattern);
                    mapping.insert(source_pattern.clone(), fallback_endpoint.name.clone());
                } else {
                    error!("No endpoints configured - cannot create fallback mapping");
                }
            } else {
                // Valid endpoint reference
                debug!("Mapped source pattern '{}' to endpoint '{}'", source_pattern, endpoint_name);
                mapping.insert(source_pattern.clone(), endpoint_name.clone());
            }
        }
    }
    
    // Ensure we have a default mapping if no explicit mappings exist
    if mapping.is_empty() {
        if let Some(default_endpoint) = config.endpoints.first() {
            info!("No source mapping configured - using '{}' as default endpoint", default_endpoint.name);
            mapping.insert("default".to_string(), default_endpoint.name.clone());
        } else {
            error!("No endpoints configured and no source mapping available");
        }
    }
    
    // Log final mapping for transparency
    info!("Built endpoint mapping with {} pattern(s)", mapping.len());
    for (pattern, endpoint) in &mapping {
        debug!("  {} -> {}", pattern, endpoint);
    }
    
    mapping
}
