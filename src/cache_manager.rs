//! Local file-based caching manager for offline SNMP trap storage
//! 
//! Stores traps as JSON files in instance-specific folders for offline resilience.
//! Provides automatic retry mechanisms and cache cleanup based on configurable
//! size and age limits.
//! 
//! Developed by GoCortex.io

use crate::config::{CacheConfig, Config};
use crate::snmp_listener::SnmpTrap;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration as TokioDuration};
use tracing::{debug, error, info, warn};

#[derive(Debug, Serialize, Deserialize)]
struct CachedTrap {
    trap: SnmpTrap,
    cached_at: DateTime<Utc>,
    retry_count: u32,
    target_instance: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RejectedTrap {
    pub trap: SnmpTrap,
    pub rejected_at: DateTime<Utc>,
    pub rejection_reason: String,
    pub validation_failure: ValidationFailureType,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ValidationFailureType {
    CommunityStringMismatch { expected: Vec<String>, received: Option<String> },
    UnsupportedSnmpVersion { supported: Vec<String>, received: String },
    UnparseableData { parse_error: String },
    InvalidSourceIp { source_ip: String, error: String },
}

pub struct CacheManager {
    cache_config: CacheConfig,
    full_config: Config,
    storage_path: PathBuf,
    trap_receiver: mpsc::UnboundedReceiver<SnmpTrap>,
    rejected_trap_receiver: mpsc::UnboundedReceiver<RejectedTrap>,
    retry_sender: mpsc::UnboundedSender<SnmpTrap>,
    success_receiver: mpsc::UnboundedReceiver<(String, String)>, // (trap_id, target_instance)
    completion_sender: Option<tokio::sync::oneshot::Sender<()>>, // For shutdown completion notification
}

struct CacheManagerShared {
    cache_config: CacheConfig,
    full_config: Config,
    storage_path: PathBuf,
    retry_sender: mpsc::UnboundedSender<SnmpTrap>,
}

impl CacheManagerShared {
    /// Sanitize endpoint name for safe filesystem usage
    fn sanitize_instance_name(&self, instance_name: &str) -> String {
        // Replace filesystem-unsafe characters with safe alternatives
        let mut sanitized = instance_name
            .chars()
            .map(|c| match c {
                // Invalid Windows/Unix filesystem characters
                '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
                '/' | '\\' => '-',  // Path separators become dashes
                // Control characters (0-31) and DEL (127)
                c if c.is_control() => '_',
                // Unicode whitespace becomes underscore
                c if c.is_whitespace() => '_',
                // Valid characters pass through
                c => c,
            })
            .collect::<String>();

        // Handle reserved Windows names
        if matches!(sanitized.to_uppercase().as_str(), 
            "CON" | "PRN" | "AUX" | "NUL" | 
            "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9" |
            "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9"
        ) {
            sanitized = format!("endpoint_{}", sanitized);
        }

        // Ensure name is not empty and doesn't start/end with dots or spaces
        sanitized = sanitized.trim_matches(|c: char| c == '.' || c.is_whitespace()).to_string();
        
        if sanitized.is_empty() {
            sanitized = "unknown_endpoint".to_string();
        }

        // Limit length to reasonable filesystem limits (most support 255, we use 200 for safety)
        if sanitized.len() > 200 {
            sanitized = format!("{}_{}", &sanitized[..190], 
                self.hash_string(&sanitized));
        }

        sanitized
    }

    /// Generate a short hash for long names to ensure uniqueness
    fn hash_string(&self, input: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        input.hash(&mut hasher);
        format!("{:x}", hasher.finish()).chars().take(8).collect()
    }

    /// Cache a trap to local file storage
    async fn cache_trap(&self, trap: &SnmpTrap, target_instance: &str) -> Result<()> {
        let sanitized_instance = self.sanitize_instance_name(target_instance);
        let instance_dir = self.storage_path.join(&sanitized_instance);
        
        debug!("Caching trap {} to sanitized instance directory: {} (original: {})", 
            trap.id, sanitized_instance, target_instance);
        fs::create_dir_all(&instance_dir)
            .await
            .with_context(|| format!("Failed to create instance directory: {}", instance_dir.display()))?;

        let cached_trap = CachedTrap {
            trap: trap.clone(),
            cached_at: Utc::now(),
            retry_count: 0,
            target_instance: sanitized_instance.clone(),
        };

        let filename = format!("{}_{}.json", trap.id, cached_trap.cached_at.timestamp_millis());
        let file_path = instance_dir.join(filename);

        let json_content = serde_json::to_string_pretty(&cached_trap)
            .context("Failed to serialise cached trap to JSON")?;

        fs::write(&file_path, json_content)
            .await
            .with_context(|| format!("Failed to write trap to file: {}", file_path.display()))?;

        info!("Successfully cached trap {} to {}", trap.id, sanitized_instance);
        Ok(())
    }
    
    /// Cache a rejected trap to the "Lost and Found" directory
    async fn cache_rejected_trap(&self, rejected_trap: &RejectedTrap) -> Result<()> {
        let lost_and_found_dir = self.storage_path.join("lost-and-found");
        
        debug!("Caching rejected trap {} to lost-and-found directory (reason: {})", 
            rejected_trap.trap.id, rejected_trap.rejection_reason);
        fs::create_dir_all(&lost_and_found_dir)
            .await
            .with_context(|| format!("Failed to create lost-and-found directory: {}", lost_and_found_dir.display()))?;

        let filename = format!("{}_{}.json", rejected_trap.trap.id, rejected_trap.rejected_at.timestamp_millis());
        let file_path = lost_and_found_dir.join(filename);

        let json_content = serde_json::to_string_pretty(rejected_trap)
            .context("Failed to serialise rejected trap to JSON")?;

        fs::write(&file_path, json_content)
            .await
            .with_context(|| format!("Failed to write rejected trap to file: {}", file_path.display()))?;

        info!("Successfully cached rejected trap {} to lost-and-found (reason: {})", 
            rejected_trap.trap.id, rejected_trap.rejection_reason);
        Ok(())
    }

    /// Retrieve cached traps for retry from all instances
    async fn get_cached_traps(&self, limit: usize) -> Result<Vec<CachedTrap>> {
        let mut cached_traps = Vec::new();

        // Read all instance directories
        if !self.storage_path.exists() {
            return Ok(cached_traps);
        }

        let mut entries = match fs::read_dir(&self.storage_path).await {
            Ok(entries) => entries,
            Err(e) => {
                debug!("Cannot read cache directory: {}", e);
                return Ok(cached_traps);
            }
        };

        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                let instance_dir = entry.path();
                match self.read_instance_traps(&instance_dir).await {
                    Ok(instance_traps) => cached_traps.extend(instance_traps),
                    Err(e) => debug!("Failed to read instance traps from {:?}: {}", instance_dir, e),
                }
            }
        }

        // Sort by cached_at timestamp and limit results
        cached_traps.sort_by(|a, b| a.cached_at.cmp(&b.cached_at));
        cached_traps.truncate(limit);

        // CRITICAL: Deduplicate by trap UUID to prevent redundant caching from creating duplicate retries
        let original_count = cached_traps.len();
        let mut seen_uuids = std::collections::HashSet::new();
        let deduplicated_traps: Vec<CachedTrap> = cached_traps
            .into_iter()
            .filter(|t| t.retry_count < 10)
            .filter(|cached_trap| {
                if seen_uuids.contains(&cached_trap.trap.id) {
                    debug!("Skipping duplicate trap {} (already loaded from another endpoint directory)", cached_trap.trap.id);
                    false
                } else {
                    seen_uuids.insert(cached_trap.trap.id.clone());
                    true
                }
            })
            .collect();

        if deduplicated_traps.len() < original_count {
            info!("Deduplicated {} cached traps to {} unique traps for retry", 
                original_count, deduplicated_traps.len());
        }

        Ok(deduplicated_traps)
    }

    /// Read traps from a specific instance directory
    async fn read_instance_traps(&self, instance_dir: &Path) -> Result<Vec<CachedTrap>> {
        let mut traps = Vec::new();
        let mut entries = fs::read_dir(instance_dir)
            .await
            .with_context(|| format!("Failed to read instance directory: {}", instance_dir.display()))?;

        while let Some(entry) = entries.next_entry().await? {
            let file_path = entry.path();
            if file_path.extension().and_then(|s| s.to_str()) == Some("json") {
                match self.read_cached_trap(&file_path).await {
                    Ok(cached_trap) => traps.push(cached_trap),
                    Err(e) => warn!("Failed to read cached trap from {}: {}", file_path.display(), e),
                }
            }
        }

        Ok(traps)
    }

    /// Read a single cached trap from file
    async fn read_cached_trap(&self, file_path: &Path) -> Result<CachedTrap> {
        let content = fs::read_to_string(file_path)
            .await
            .with_context(|| format!("Failed to read trap file: {}", file_path.display()))?;

        let cached_trap: CachedTrap = serde_json::from_str(&content)
            .with_context(|| format!("Failed to deserialise trap from: {}", file_path.display()))?;

        Ok(cached_trap)
    }

    /// Update retry count for a trap
    async fn update_retry_count(&self, trap_id: &str, target_instance: &str) -> Result<()> {
        let sanitized_instance = self.sanitize_instance_name(target_instance);
        let instance_dir = self.storage_path.join(&sanitized_instance);
        let mut entries = fs::read_dir(&instance_dir)
            .await
            .with_context(|| format!("Failed to read instance directory: {}", instance_dir.display()))?;

        while let Some(entry) = entries.next_entry().await? {
            let file_path = entry.path();
            if file_path.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with(&format!("{}_", trap_id)))
                .unwrap_or(false)
            {
                if let Ok(mut cached_trap) = self.read_cached_trap(&file_path).await {
                    cached_trap.retry_count += 1;
                    
                    let json_content = serde_json::to_string_pretty(&cached_trap)
                        .context("Failed to serialise updated trap")?;

                    fs::write(&file_path, json_content)
                        .await
                        .with_context(|| format!("Failed to update trap file: {}", file_path.display()))?;

                    debug!("Updated retry count to {} for trap {}", cached_trap.retry_count, trap_id);
                    return Ok(());
                }
            }
        }

        warn!("Failed to find trap {} for retry count update", trap_id);
        Ok(())
    }

    /// Remove old traps from cache
    async fn cleanup_old_traps(&self) -> Result<()> {
        let cutoff = Utc::now() - Duration::hours(self.cache_config.max_age_hours as i64);
        let mut removed_count = 0;

        if !self.storage_path.exists() {
            return Ok(());
        }

        let mut entries = fs::read_dir(&self.storage_path)
            .await
            .context("Failed to read cache storage directory")?;

        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                let instance_dir = entry.path();
                removed_count += self.cleanup_instance_old_traps(&instance_dir, cutoff).await?;
            }
        }

        if removed_count > 0 {
            info!("Cleaned up {} old cached traps", removed_count);
        }

        Ok(())
    }

    /// Clean up old traps from a specific instance directory
    async fn cleanup_instance_old_traps(&self, instance_dir: &Path, cutoff: DateTime<Utc>) -> Result<u32> {
        let mut removed_count = 0;
        let mut entries = fs::read_dir(instance_dir)
            .await
            .with_context(|| format!("Failed to read instance directory: {}", instance_dir.display()))?;

        while let Some(entry) = entries.next_entry().await? {
            let file_path = entry.path();
            if file_path.extension().and_then(|s| s.to_str()) == Some("json") {
                match self.read_cached_trap(&file_path).await {
                    Ok(cached_trap) => {
                        if cached_trap.cached_at < cutoff {
                            if let Err(e) = fs::remove_file(&file_path).await {
                                warn!("Failed to remove old trap file {}: {}", file_path.display(), e);
                            } else {
                                removed_count += 1;
                            }
                        }
                    }
                    Err(_) => {
        // Remove corrupted or unreadable cache files
                        let _ = fs::remove_file(&file_path).await;
                        removed_count += 1;
                    }
                }
            }
        }

        Ok(removed_count)
    }

    /// Enforce cache size limit by removing oldest files until below limit
    async fn enforce_size_limit(&self) -> Result<()> {
        let mut total_size = self.calculate_cache_size().await?;
        let size_limit_bytes = self.cache_config.max_size_mb * 1024 * 1024;

        if total_size <= size_limit_bytes {
            return Ok(()); // Already within limit
        }

        warn!("Cache size ({} MB) exceeds limit ({} MB), removing oldest entries", 
              total_size / (1024 * 1024), self.cache_config.max_size_mb);

        let mut all_traps = self.get_all_cached_traps_with_paths().await?;
        all_traps.sort_by(|a, b| a.1.cached_at.cmp(&b.1.cached_at));

        let mut removed_count = 0;
        let target_size = (size_limit_bytes as f64 * 0.9) as u64; // Target 90% of limit for buffer

        // Remove files one by one until we're below the target size
        for (file_path, _) in all_traps.iter() {
            if total_size <= target_size {
                break; // We've reduced enough
            }

            // Get file size before removing
            let file_size = match fs::metadata(file_path).await {
                Ok(metadata) => metadata.len(),
                Err(_) => 0, // File might have been removed already
            };

            if let Err(e) = fs::remove_file(file_path).await {
                warn!("Failed to remove cache file {}: {}", file_path.display(), e);
            } else {
                removed_count += 1;
                total_size = total_size.saturating_sub(file_size);
                debug!("Removed cache file, new total size: {} MB", total_size / (1024 * 1024));
            }
        }

        info!("Removed {} old entries to enforce size limit (new size: {} MB)", 
              removed_count, total_size / (1024 * 1024));
        
        Ok(())
    }

    /// Calculate total cache size in bytes
    async fn calculate_cache_size(&self) -> Result<u64> {
        let mut total_size = 0u64;

        if !self.storage_path.exists() {
            return Ok(0);
        }

        let mut entries = fs::read_dir(&self.storage_path)
            .await
            .context("Failed to read cache storage directory")?;

        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                total_size += self.calculate_instance_size(&entry.path()).await?;
            }
        }

        Ok(total_size)
    }

    /// Calculate size of a specific instance directory
    async fn calculate_instance_size(&self, instance_dir: &Path) -> Result<u64> {
        let mut size = 0u64;
        let mut entries = fs::read_dir(instance_dir)
            .await
            .with_context(|| format!("Failed to read instance directory: {}", instance_dir.display()))?;

        while let Some(entry) = entries.next_entry().await? {
            if let Ok(metadata) = entry.metadata().await {
                size += metadata.len();
            }
        }

        Ok(size)
    }

    /// Get all cached traps with their file paths for cleanup operations
    async fn get_all_cached_traps_with_paths(&self) -> Result<Vec<(PathBuf, CachedTrap)>> {
        let mut traps_with_paths = Vec::new();

        if !self.storage_path.exists() {
            return Ok(traps_with_paths);
        }

        let mut entries = fs::read_dir(&self.storage_path)
            .await
            .context("Failed to read cache storage directory")?;

        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                let instance_dir = entry.path();
                let instance_traps = self.get_instance_traps_with_paths(&instance_dir).await?;
                traps_with_paths.extend(instance_traps);
            }
        }

        Ok(traps_with_paths)
    }

    /// Get traps with paths from a specific instance directory
    async fn get_instance_traps_with_paths(&self, instance_dir: &Path) -> Result<Vec<(PathBuf, CachedTrap)>> {
        let mut traps_with_paths = Vec::new();
        let mut entries = fs::read_dir(instance_dir)
            .await
            .with_context(|| format!("Failed to read instance directory: {}", instance_dir.display()))?;

        while let Some(entry) = entries.next_entry().await? {
            let file_path = entry.path();
            if file_path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(cached_trap) = self.read_cached_trap(&file_path).await {
                    traps_with_paths.push((file_path, cached_trap));
                }
            }
        }

        Ok(traps_with_paths)
    }

    /// Remove successfully forwarded trap from cache
    async fn remove_trap(&self, trap_id: &str, target_instance: &str) -> Result<()> {
        let sanitized_instance = self.sanitize_instance_name(target_instance);
        let instance_dir = self.storage_path.join(&sanitized_instance);
        
        if !instance_dir.exists() {
            return Ok(()); // Nothing to remove
        }

        // Collect file paths first to avoid race conditions during iteration
        let mut file_paths = Vec::new();
        let mut entries = fs::read_dir(&instance_dir)
            .await
            .with_context(|| format!("Failed to read instance directory: {}", instance_dir.display()))?;

        while let Some(entry) = entries.next_entry().await? {
            let file_path = entry.path();
            if file_path.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with(&format!("{}_", trap_id)))
                .unwrap_or(false)
            {
                file_paths.push(file_path);
            }
        }

        // Remove files outside of directory iteration
        for file_path in file_paths {
            if let Err(e) = fs::remove_file(&file_path).await {
                // File might have been removed by another process, only warn if it still exists
                if fs::try_exists(&file_path).await.unwrap_or(false) {
                    warn!("Failed to remove cached trap file {}: {}", file_path.display(), e);
                }
            } else {
                debug!("Removed trap {} from cache", trap_id);
            }
        }

        Ok(())
    }
}

impl CacheManager {
    /// Create a new file-based cache manager
    pub fn new(
        full_config: Config,
        trap_receiver: mpsc::UnboundedReceiver<SnmpTrap>,
        rejected_trap_receiver: mpsc::UnboundedReceiver<RejectedTrap>,
        retry_sender: mpsc::UnboundedSender<SnmpTrap>,
        success_receiver: mpsc::UnboundedReceiver<(String, String)>,
        completion_sender: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Result<Self> {
        let cache_config = full_config.cache.clone();
        let storage_path = PathBuf::from(&cache_config.storage_path);
        
        // Create storage directory if it doesn't exist
        std::fs::create_dir_all(&storage_path)
            .with_context(|| format!("Failed to create cache storage directory: {}", storage_path.display()))?;

        info!("Initialised file-based cache storage at: {}", storage_path.display());

        Ok(Self {
            cache_config,
            full_config,
            storage_path,
            trap_receiver,
            rejected_trap_receiver,
            retry_sender,
            success_receiver,
            completion_sender,
        })
    }

    /// Start the cache manager
    pub async fn start(mut self) -> Result<()> {
        info!("Cache manager started");

        // Extract the receiver and shared state
        let cache_manager = Arc::new(CacheManagerShared {
            cache_config: self.cache_config.clone(),
            full_config: self.full_config.clone(),
            storage_path: self.storage_path.clone(),
            retry_sender: self.retry_sender.clone(),
        });
        
        let cleanup_manager = Arc::clone(&cache_manager);
        let retry_manager = Arc::clone(&cache_manager);
        let success_manager = Arc::clone(&cache_manager);
        
        // Trap caching task (main processing loop)
        let cache_trap_manager = Arc::clone(&cache_manager);
        let completion_sender = self.completion_sender.take();
        let cache_task = tokio::spawn(async move {
            let mut pending_traps_count = 0;
            
            while let Some(trap) = self.trap_receiver.recv().await {
                pending_traps_count += 1;
                
                // Cache to ALL configured endpoints for redundancy
                let endpoint_names: Vec<String> = cache_trap_manager.full_config.endpoints
                    .iter()
                    .map(|endpoint| endpoint.name.clone())
                    .collect();

                info!("Received trap {} from {} for caching to {} instances: {:?}", 
                    trap.id, trap.source_address, endpoint_names.len(), endpoint_names);
                
                for endpoint_name in &endpoint_names {
                    if let Err(e) = cache_trap_manager.cache_trap(&trap, endpoint_name).await {
                        error!("Failed to cache trap {} to {}: {}", trap.id, endpoint_name, e);
                    }
                }
            }
            
            // CRITICAL: Ensure all file operations complete before signaling shutdown
            info!("Cache trap receiver closed - processed {} traps during shutdown", pending_traps_count);
            info!("Waiting for all file operations to complete...");
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            info!("Cache task shutdown complete - all file operations preserved");
        });

        // Rejected trap caching task (lost and found processing loop)
        let rejected_trap_manager = Arc::clone(&cache_manager);
        let rejected_task = tokio::spawn(async move {
            while let Some(rejected_trap) = self.rejected_trap_receiver.recv().await {
                debug!("Processing rejected trap {} from {} (reason: {})", 
                    rejected_trap.trap.id, rejected_trap.trap.source_address, rejected_trap.rejection_reason);
                if let Err(e) = rejected_trap_manager.cache_rejected_trap(&rejected_trap).await {
                    error!("Failed to cache rejected trap {}: {}", rejected_trap.trap.id, e);
                }
            }
            debug!("Rejected trap receiver closed");
        });

        // Periodic cleanup task
        let cleanup_task = tokio::spawn(async move {
            let mut cleanup_interval = interval(TokioDuration::from_secs(
                cleanup_manager.cache_config.flush_interval_seconds
            ));

            loop {
                cleanup_interval.tick().await;
                
                if let Err(e) = cleanup_manager.cleanup_old_traps().await {
                    error!("Failed to cleanup old traps: {}", e);
                }
                
                if let Err(e) = cleanup_manager.enforce_size_limit().await {
                    error!("Failed to enforce size limit: {}", e);
                }
            }
        });

        // Retry processing task
        let retry_task = tokio::spawn(async move {
            let mut retry_interval = interval(TokioDuration::from_secs(60)); // Retry every minute

            loop {
                retry_interval.tick().await;
                
                // Only attempt retry if cache directory exists
                if retry_manager.storage_path.exists() {
                    match retry_manager.get_cached_traps(100).await {
                        Ok(cached_traps) => {
                            if !cached_traps.is_empty() {
                                info!("Retrying {} cached traps", cached_traps.len());
                                for cached_trap in cached_traps {
                                    // Update retry count before sending
                                    if let Err(e) = retry_manager.update_retry_count(
                                        &cached_trap.trap.id, 
                                        &cached_trap.target_instance
                                    ).await {
                                        warn!("Failed to update retry count for trap {}: {}", cached_trap.trap.id, e);
                                    }

                                    // Send the trap for retry
                                    if let Err(e) = retry_manager.retry_sender.send(cached_trap.trap) {
                                        error!("Failed to send trap for retry: {}", e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            // Only log as debug to avoid spam when no traps are cached
                            debug!("No cached traps to retry: {}", e);
                        },
                    }
                } else {
                    debug!("Cache directory doesn't exist yet, skipping retry check");
                }
            }
        });

        // Success notification handling task
        let success_task = tokio::spawn(async move {
            while let Some((trap_id, target_instance)) = self.success_receiver.recv().await {
                debug!("Received success notification for trap {} to instance {}", trap_id, target_instance);
                if let Err(e) = success_manager.remove_trap(&trap_id, &target_instance).await {
                    warn!("Failed to remove trap {} from cache: {}", trap_id, e);
                } else {
                    info!("Removed successfully forwarded trap {} from cache", trap_id);
                }
            }
            debug!("Success notification receiver closed");
        });

        // Wait for BOTH main and rejected trap processing to complete during shutdown
        let (cache_result, rejected_result) = tokio::join!(cache_task, rejected_task);
        
        let completion_message = match (cache_result, rejected_result) {
            (Ok(_), Ok(_)) => {
                info!("Both cache and rejected trap tasks completed gracefully");
                
                // CRITICAL: Extended wait for file system operations to complete
                info!("Ensuring all file system operations are fully committed...");
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                
                "Cache completion signaled - all file operations committed to disk"
            }
            (cache_result, rejected_result) => {
                if let Err(e) = cache_result {
                    error!("Cache task failed: {}", e);
                }
                if let Err(e) = rejected_result {
                    error!("Rejected trap task failed: {}", e);
                }
                
                // Even on errors, wait for file operations
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                
                "Cache completion signaled - file operations attempted despite task errors"
            }
        };
        
        // Signal completion ONLY after file operations are guaranteed complete
        if let Some(sender) = completion_sender {
            let _ = sender.send(());
            info!("{}", completion_message);
        }
        
        // Abort background tasks since shutdown is complete
        cleanup_task.abort();
        retry_task.abort();
        success_task.abort();
        
        info!("Cache manager shutdown complete - background tasks terminated");
        Ok(())
    }
}