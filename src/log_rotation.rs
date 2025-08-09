//! Log Rotation Management for AckbarX
//! 
//! Provides log file size monitoring and rotation management to prevent
//! log files from growing too large and affecting system performance.
//! 
//! Developed by GoCortex.io

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

pub struct LogRotationManager {
    log_file_path: PathBuf,
    max_size_bytes: u64,
    max_files: usize,
    check_interval: Duration,
}

impl LogRotationManager {
    pub fn new(
        log_file_path: PathBuf,
        max_size_mb: u64,
        max_files: usize,
        check_interval_seconds: u64,
    ) -> Self {
        Self {
            log_file_path,
            max_size_bytes: max_size_mb * 1024 * 1024, // Convert MB to bytes
            max_files,
            check_interval: Duration::from_secs(check_interval_seconds),
        }
    }

    /// Start the log rotation monitoring task
    pub async fn start_monitoring(&self) -> Result<()> {
        let mut interval = interval(self.check_interval);
        let log_path = self.log_file_path.clone();
        let max_size = self.max_size_bytes;
        let max_files = self.max_files;

        info!(
            "Started log rotation monitoring for {} (max size: {}MB, max files: {})",
            log_path.display(),
            max_size / (1024 * 1024),
            max_files
        );

        loop {
            interval.tick().await;
            
            if let Err(e) = self.check_and_rotate(&log_path, max_size, max_files).await {
                error!("Log rotation check failed: {}", e);
            }
        }
    }

    /// Check log file size and rotate if necessary
    async fn check_and_rotate(
        &self,
        log_path: &Path,
        max_size: u64,
        max_files: usize,
    ) -> Result<()> {
        // Check if log file exists and its size
        if !log_path.exists() {
            debug!("Log file {} doesn't exist, skipping rotation check", log_path.display());
            return Ok(());
        }

        let metadata = tokio::fs::metadata(log_path)
            .await
            .context("Failed to read log file metadata")?;

        let file_size = metadata.len();
        
        if file_size > max_size {
            info!(
                "Log file {} size ({}MB) exceeds limit ({}MB), rotating",
                log_path.display(),
                file_size / (1024 * 1024),
                max_size / (1024 * 1024)
            );
            
            self.rotate_log_file(log_path, max_files).await?;
        } else {
            debug!(
                "Log file size: {}MB / {}MB",
                file_size / (1024 * 1024),
                max_size / (1024 * 1024)
            );
        }

        Ok(())
    }

    /// Rotate the log file by renaming it with a timestamp
    async fn rotate_log_file(&self, log_path: &Path, max_files: usize) -> Result<()> {
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let log_dir = log_path.parent().unwrap_or(Path::new("."));
        let log_filename = log_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("ackbarx");
        let log_extension = log_path.extension()
            .and_then(|s| s.to_str())
            .unwrap_or("log");

        // Create rotated filename
        let rotated_filename = format!("{}.{}.{}", log_filename, timestamp, log_extension);
        let rotated_path = log_dir.join(rotated_filename);

        // Rename current log file
        tokio::fs::rename(log_path, &rotated_path)
            .await
            .context("Failed to rotate log file")?;

        info!("Rotated log file to {}", rotated_path.display());

        // Clean up old log files if we exceed max_files
        self.cleanup_old_logs(log_dir, log_filename, log_extension, max_files)
            .await?;

        Ok(())
    }

    /// Clean up old rotated log files to maintain the maximum number of files
    async fn cleanup_old_logs(
        &self,
        log_dir: &Path,
        log_filename: &str,
        log_extension: &str,
        max_files: usize,
    ) -> Result<()> {
        let mut log_files = Vec::new();

        // Read directory and find all rotated log files
        let mut entries = tokio::fs::read_dir(log_dir)
            .await
            .context("Failed to read log directory")?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if let Some(filename) = path.file_name().and_then(|s| s.to_str()) {
                // Match pattern: log_filename.YYYYMMDD_HHMMSS.log_extension
                if filename.starts_with(log_filename) 
                    && filename.ends_with(log_extension)
                    && filename.contains('.') {
                    
                    let metadata = entry.metadata().await?;
                    if let Ok(modified) = metadata.modified() {
                        log_files.push((path, modified));
                    }
                }
            }
        }

        // Sort by modification time (oldest first)
        log_files.sort_by_key(|(_, modified)| *modified);

        // Remove excess files
        if log_files.len() > max_files {
            let files_to_remove = log_files.len() - max_files;
            for (path, _) in log_files.iter().take(files_to_remove) {
                match tokio::fs::remove_file(path).await {
                    Ok(_) => info!("Removed old log file: {}", path.display()),
                    Err(e) => warn!("Failed to remove old log file {}: {}", path.display(), e),
                }
            }
        }

        Ok(())
    }
}

/// Create and start log rotation monitoring as a background task
pub fn start_log_rotation_monitoring(
    log_file_path: Option<String>,
    max_size_mb: u64,
    max_files: usize,
) -> Option<tokio::task::JoinHandle<()>> {
    if let Some(log_path) = log_file_path {
        let log_rotation = LogRotationManager::new(
            PathBuf::from(log_path),
            max_size_mb,
            max_files,
            300, // Check every 5 minutes
        );

        Some(tokio::spawn(async move {
            if let Err(e) = log_rotation.start_monitoring().await {
                error!("Log rotation monitoring failed: {}", e);
            }
        }))
    } else {
        None
    }
}