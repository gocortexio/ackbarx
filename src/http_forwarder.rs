//! HTTP Forwarder for sending SNMP traps to endpoints
//! 
//! Handles forwarding of SNMP traps to configured HTTP endpoints with retry logic
//! and XSIAM-compatible payload formatting.
//! 
//! Developed by GoCortex.io

use crate::config::HttpEndpointConfig;
use crate::snmp_listener::SnmpTrap;
use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use base64::prelude::*;

pub struct HttpForwarder {
    client: Client,
    endpoints: Vec<HttpEndpointConfig>,
    trap_receiver: mpsc::UnboundedReceiver<SnmpTrap>,
    cache_sender: mpsc::UnboundedSender<SnmpTrap>,
    success_sender: mpsc::UnboundedSender<(String, String)>, // (trap_id, target_instance)
    forwarder_type: String,
    shutdown_receiver: mpsc::UnboundedReceiver<()>,
    flush_completion_sender: Option<tokio::sync::oneshot::Sender<()>>,
    shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl HttpForwarder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoints: Vec<HttpEndpointConfig>,
        trap_receiver: mpsc::UnboundedReceiver<SnmpTrap>,
        cache_sender: mpsc::UnboundedSender<SnmpTrap>,
        success_sender: mpsc::UnboundedSender<(String, String)>,
        forwarder_type: String,
        shutdown_receiver: mpsc::UnboundedReceiver<()>,
        flush_completion_sender: Option<tokio::sync::oneshot::Sender<()>>,
        shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            endpoints,
            trap_receiver,
            cache_sender,
            success_sender,
            forwarder_type,
            shutdown_receiver,
            flush_completion_sender,
            shutdown_flag,
        }
    }

    /// Start the HTTP forwarder
    pub async fn start(mut self) -> Result<()> {
        info!("HTTP forwarder ({}) started with {} endpoints", self.forwarder_type, self.endpoints.len());

        let mut pending_traps = Vec::new();
        let mut current_trap: Option<SnmpTrap> = None;
        
        loop {
            tokio::select! {
                // Process incoming traps
                trap_option = self.trap_receiver.recv() => {
                    if let Some(trap) = trap_option {
                        debug!("Processing trap {} for forwarding", trap.id);
                        current_trap = Some(trap.clone());

                        // Try to forward to all configured endpoints
                        let mut forwarded_successfully = false;

                        for endpoint in &self.endpoints {
                            // ULTIMATE FIX: Check shutdown before each endpoint attempt
                            if self.shutdown_flag.load(std::sync::atomic::Ordering::Relaxed) {
                                warn!("ULTIMATE: Shutdown detected before forwarding trap {} to {} - caching immediately", trap.id, endpoint.name);
                                break;
                            }
                            
                            match self.forward_trap(&trap, endpoint).await {
                                Ok(()) => {
                                    info!("Successfully forwarded trap {} to {} ({})", trap.id, endpoint.name, endpoint.url);
                                    forwarded_successfully = true;
                                    
                                    // Notify cache manager to remove the trap if it was cached
                                    if let Err(e) = self.success_sender.send((trap.id.clone(), endpoint.name.clone())) {
                                        warn!("Failed to notify cache manager of successful forward: {}", e);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to forward trap {} to {} ({}): {}", trap.id, endpoint.name, endpoint.url, e);
                                }
                            }
                        }

                        // Cache once per trap if forwarding failed to all endpoints
                        if !forwarded_successfully && current_trap.is_some() {
                            let trap_id = trap.id.clone();
                            info!("Forwarding failed for trap {} to all {} endpoints, caching once for retry", trap_id, self.endpoints.len());
                            
                            // EMERGENCY DEBUG: Check cache channel state before sending
                            if self.cache_sender.is_closed() {
                                error!("CRITICAL: Cache channel is CLOSED when trying to send trap {}", trap_id);
                            } else {
                                debug!("Cache channel is OPEN, sending trap {} (single cache per trap)", trap_id);
                            }
                            
                            if let Err(e) = self.cache_sender.send(trap) {
                                error!("Failed to cache trap {}: {}", trap_id, e);
                            } else {
                                debug!("Successfully sent trap {} to cache - single cache entry created", trap_id);
                            }
                        } else if forwarded_successfully {
                            debug!("Trap {} forwarded successfully, no caching needed", trap.id);
                        }
                        
                        current_trap = None;
                    } else {
                        // Channel closed, normal shutdown
                        debug!("Trap receiver channel closed for {} forwarder", self.forwarder_type);
                        break;
                    }
                }
                
                // Handle shutdown signal
                shutdown_signal = self.shutdown_receiver.recv() => {
                    if shutdown_signal.is_some() {
                        info!("ULTIMATE SHUTDOWN: {} forwarder setting shutdown flag and aborting ALL operations", self.forwarder_type);
                        
                        // ULTIMATE FIX: Set global shutdown flag to stop ALL HTTP attempts immediately
                        self.shutdown_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                        
                        // Cache any trap currently being processed immediately
                        if let Some(trap) = current_trap.take() {
                            let trap_id = trap.id.clone();
                            info!("ULTIMATE: Caching current trap {} during shutdown", trap_id);
                            if let Err(e) = self.cache_sender.send(trap) {
                                error!("CRITICAL: Failed to cache current trap {}: {}", trap_id, e);
                            } else {
                                info!("ULTIMATE: Successfully cached current trap {} during shutdown", trap_id);
                            }
                        }
                        
                        // Collect any remaining traps from the channel
                        while let Ok(trap) = self.trap_receiver.try_recv() {
                            pending_traps.push(trap);
                        }
                        
                        // Cache all pending traps immediately
                        for trap in pending_traps.drain(..) {
                            let trap_id = trap.id.clone();
                            if let Err(e) = self.cache_sender.send(trap.clone()) {
                                error!("Failed to cache pending trap {} during shutdown: {}", trap_id, e);
                            } else {
                                info!("Cached pending trap {} during graceful shutdown", trap_id);
                            }
                        }
                        
                        // Signal completion of flush operation
                        if let Some(completion_sender) = self.flush_completion_sender.take() {
                            let _ = completion_sender.send(());
                            info!("{} forwarder flush completion signaled", self.forwarder_type);
                        }
                        
                        info!("{} forwarder shutdown complete - operations preserved", self.forwarder_type);
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Forward a single trap to an HTTP endpoint
    async fn forward_trap(&self, trap: &SnmpTrap, endpoint: &HttpEndpointConfig) -> Result<()> {
        let payload = self.format_trap_payload(trap, endpoint)?;
        let mut last_error = None;

        for attempt in 1..=endpoint.max_retries {
            // ULTIMATE FIX: Check shutdown flag before every single HTTP attempt
            if self.shutdown_flag.load(std::sync::atomic::Ordering::Relaxed) {
                warn!("ULTIMATE: Shutdown detected before HTTP attempt {} for trap {} to {} - aborting", attempt, trap.id, endpoint.name);
                return Err(anyhow::anyhow!("HTTP forwarding aborted due to shutdown"));
            }
            
            debug!("Forwarding attempt {} for trap {} to {}", attempt, trap.id, endpoint.name);

            let result = self.send_http_request(&payload, endpoint).await;

            match result {
                Ok(()) => {
                    debug!("Successfully sent trap {} to {} on attempt {}", trap.id, endpoint.name, attempt);
                    return Ok(());
                }
                Err(e) => {
                    last_error = Some(e);
                    warn!("Attempt {} failed for trap {} to {}: {}", attempt, trap.id, endpoint.name, last_error.as_ref().unwrap());

                    // ULTIMATE FIX: Check shutdown before delay
                    if attempt < endpoint.max_retries {
                        if self.shutdown_flag.load(std::sync::atomic::Ordering::Relaxed) {
                            warn!("ULTIMATE: Shutdown detected before retry delay for trap {} - aborting remaining attempts", trap.id);
                            return Err(anyhow::anyhow!("HTTP forwarding aborted during retry"));
                        }
                        
                        let delay = Duration::from_secs(endpoint.retry_backoff_seconds * attempt as u64);
                        sleep(delay).await;
                        
                        // Check again after delay
                        if self.shutdown_flag.load(std::sync::atomic::Ordering::Relaxed) {
                            warn!("ULTIMATE: Shutdown detected after retry delay for trap {} - aborting", trap.id);
                            return Err(anyhow::anyhow!("HTTP forwarding aborted after retry delay"));
                        }
                    }
                }
            }
        }

        // All attempts failed
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Unknown error")))
    }

    /// Send HTTP request to endpoint
    async fn send_http_request(&self, payload: &str, endpoint: &HttpEndpointConfig) -> Result<()> {
        let mut request = self.client
            .post(&endpoint.url)
            .timeout(Duration::from_secs(endpoint.timeout_seconds))
            .body(payload.to_string());

        // Add custom headers
        for (key, value) in &endpoint.headers {
            request = request.header(key, value);
        }

        let response = request.send().await
            .context("Failed to send HTTP request")?;

        let status = response.status();
        
        if response.status().is_success() {
            info!("HTTP request to {} successful: {} ({})", endpoint.name, status.as_u16(), status.canonical_reason().unwrap_or("OK"));
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_else(|_| "No response body".to_string());
            let status_code = status.as_u16();
            
            // Provide specific error messages for common HTTP status codes
            let error_detail = match status_code {
                401 => "Authentication failed - Invalid API key or credentials",
                403 => "Access forbidden - Insufficient permissions",
                404 => "Endpoint not found - Check URL configuration",
                429 => "Rate limit exceeded - Too many requests",
                500..=599 => "Server error - XSIAM/XDR service unavailable",
                _ => "Request failed",
            };
            
            error!("HTTP request to {} failed: {} {} - {}", endpoint.name, status_code, status.canonical_reason().unwrap_or(""), error_detail);
            if !body.is_empty() && body != "No response body" {
                error!("Response body: {}", body);
            }
            
            anyhow::bail!("HTTP request failed with status {}: {}", status, error_detail)
        }
    }

    /// Format SNMP trap as XSIAM-compatible payload
    fn format_trap_payload(&self, trap: &SnmpTrap, endpoint: &HttpEndpointConfig) -> Result<String> {
        // Format as newline-delimited JSON for XSIAM
        let event = json!({
            "timestamp": trap.timestamp.timestamp_millis(),
            "event_type": "snmp_trap",
            "source_ip": trap.source_address,
            "snmp_version": trap.version,
            "snmp_community": trap.community,
            "enterprise_oid": trap.enterprise_oid,
            "trap_type": trap.trap_type,
            "specific_type": trap.specific_type,
            "timestamp_ticks": trap.timestamp_ticks,
            "variables": trap.variable_bindings.iter().map(|var| {
                json!({
                    "oid": var.oid,
                    "type": var.value_type,
                    "value": var.value
                })
            }).collect::<Vec<_>>(),
            "raw_data": BASE64_STANDARD.encode(&trap.raw_data),
            "trap_id": trap.id,
            "forwarder": "ackbarx",
            "endpoint": endpoint.name,
            "processed_at": chrono::Utc::now().to_rfc3339()
        });

        // Convert to compact JSON string
        Ok(serde_json::to_string(&event)?)
    }
}

/// HTTP endpoint health checker
pub struct EndpointHealthChecker {
    client: Client,
    endpoints: Vec<HttpEndpointConfig>,
}

impl EndpointHealthChecker {
    pub fn new(endpoints: Vec<HttpEndpointConfig>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, endpoints }
    }

    /// Check health of all endpoints
    pub async fn check_all(&self) -> HashMap<String, bool> {
        let mut results = HashMap::new();

        for endpoint in &self.endpoints {
            let healthy = self.check_endpoint(endpoint).await;
            results.insert(endpoint.name.clone(), healthy);
        }

        results
    }

    /// Check health of a single endpoint
    async fn check_endpoint(&self, endpoint: &HttpEndpointConfig) -> bool {
        // Basic health check using HTTP GET request to health endpoint
        // Construct health check URL from base URL
        let base_url = endpoint.url
            .trim_end_matches("/logs/v1/event")
            .trim_end_matches("/")
            .to_string();
        let health_url = format!("{}/health", base_url);
        
        match self.client.get(&health_url).send().await {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    }
}


