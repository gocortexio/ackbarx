//! Configuration management for AckbarX
//! 
//! Developed by GoCortex.io

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::net::IpAddr;
use anyhow::{Context, Result, anyhow};
use ipnet::IpNet;
use tracing::{warn, debug};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub listeners: Vec<SnmpListenerConfig>,
    pub endpoints: Vec<HttpEndpointConfig>,
    pub cache: CacheConfig,
    pub logging: LoggingConfig,
    pub source_mapping: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpListenerConfig {
    pub port: u16,
    pub bind_address: String,
    pub community_strings: Vec<String>,
    pub snmp_version: Vec<SnmpVersion>,
    pub max_packet_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SnmpVersion {
    V1,
    V2c,
    V3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpEndpointConfig {
    pub name: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub timeout_seconds: u64,
    pub max_retries: u32,
    pub retry_backoff_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub enabled: bool,
    pub max_size_mb: u64,
    pub max_age_hours: u64,
    pub storage_path: String,
    pub flush_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub console_output: bool,
    pub file_output: Option<String>,
    #[serde(default = "default_max_log_size_mb")]
    pub max_log_size_mb: u64,
    #[serde(default = "default_max_log_files")]
    pub max_log_files: usize,
    #[serde(default = "default_rotation_strategy")]
    pub rotation_strategy: String,
}

fn default_max_log_size_mb() -> u64 { 50 }
fn default_max_log_files() -> usize { 10 }
fn default_rotation_strategy() -> String { "size".to_string() }

impl Default for Config {
    fn default() -> Self {
        Self {
            listeners: vec![SnmpListenerConfig {
                port: 162,
                bind_address: "0.0.0.0".to_string(),
                community_strings: vec!["public".to_string()],
                snmp_version: vec![SnmpVersion::V1, SnmpVersion::V2c],
                max_packet_size: 8192,
            }],
            endpoints: vec![
                HttpEndpointConfig {
                    name: "primary_xsiam".to_string(),
                    url: "https://api-your-tenant.xdr.au.paloaltonetworks.com/logs/v1/event".to_string(),
                    headers: {
                        let mut headers = HashMap::new();
                        headers.insert("Content-Type".to_string(), "text/plain".to_string());
                        headers.insert("Authorization".to_string(), "YOUR_API_KEY_HERE".to_string());
                        headers
                    },
                    timeout_seconds: 30,
                    max_retries: 3,
                    retry_backoff_seconds: 5,
                },
                HttpEndpointConfig {
                    name: "backup_xsiam".to_string(),
                    url: "https://api-backup.xdr.au.paloaltonetworks.com/logs/v1/event".to_string(),
                    headers: {
                        let mut headers = HashMap::new();
                        headers.insert("Content-Type".to_string(), "text/plain".to_string());
                        headers.insert("Authorization".to_string(), "YOUR_BACKUP_API_KEY_HERE".to_string());
                        headers
                    },
                    timeout_seconds: 45,
                    max_retries: 5,
                    retry_backoff_seconds: 10,
                },
            ],
            cache: CacheConfig {
                enabled: true,
                max_size_mb: 500,
                max_age_hours: 48,
                storage_path: "./cache".to_string(),
                flush_interval_seconds: 300,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                console_output: true,
                file_output: Some("./ackbarx.log".to_string()),
                max_log_size_mb: default_max_log_size_mb(),
                max_log_files: default_max_log_files(),
                rotation_strategy: default_rotation_strategy(),
            },
            source_mapping: {
                let mut mapping = HashMap::new();
                mapping.insert("192.168.1.0/24".to_string(), "primary_xsiam".to_string());
                mapping.insert("10.0.0.0/8".to_string(), "backup_xsiam".to_string());
                mapping.insert("172.16.0.1".to_string(), "primary_xsiam".to_string());
                mapping.insert("*".to_string(), "primary_xsiam".to_string());
                Some(mapping)
            },
        }
    }
}

impl Config {
    /// Create a simple default configuration for basic setups
    pub fn simple() -> Self {
        Self {
            listeners: vec![SnmpListenerConfig {
                port: 162,
                bind_address: "0.0.0.0".to_string(),
                community_strings: vec!["public".to_string()],
                snmp_version: vec![SnmpVersion::V1, SnmpVersion::V2c],
                max_packet_size: 8192,
            }],
            endpoints: vec![
                HttpEndpointConfig {
                    name: "xsiam".to_string(),
                    url: "https://api-your-tenant.xdr.au.paloaltonetworks.com/logs/v1/event".to_string(),
                    headers: {
                        let mut headers = HashMap::new();
                        headers.insert("Content-Type".to_string(), "text/plain".to_string());
                        headers.insert("Authorization".to_string(), "YOUR_API_KEY_HERE".to_string());
                        headers
                    },
                    timeout_seconds: 30,
                    max_retries: 3,
                    retry_backoff_seconds: 5,
                },
            ],
            cache: CacheConfig {
                enabled: true,
                max_size_mb: 100,
                max_age_hours: 24,
                storage_path: "./cache".to_string(),
                flush_interval_seconds: 300,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                console_output: true,
                file_output: Some("./ackbarx.log".to_string()),
                max_log_size_mb: default_max_log_size_mb(),
                max_log_files: default_max_log_files(),
                rotation_strategy: default_rotation_strategy(),
            },
            source_mapping: {
                let mut mapping = HashMap::new();
                mapping.insert("*".to_string(), "xsiam".to_string());
                Some(mapping)
            },
        }
    }
    /// Load configuration from a JSON file
    pub async fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = tokio::fs::read_to_string(path.as_ref())
            .await
            .context("Failed to read configuration file")?;
        
        let config: Config = serde_json::from_str(&content)
            .context("Failed to parse configuration JSON")?;
        
        Ok(config)
    }
    
    /// Save configuration to a JSON file
    pub async fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)
            .context("Failed to serialise configuration")?;
        
        tokio::fs::write(path.as_ref(), content)
            .await
            .context("Failed to write configuration file")?;
        
        Ok(())
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Basic existence validation
        if self.listeners.is_empty() {
            anyhow::bail!("At least one SNMP listener must be configured");
        }
        
        if self.endpoints.is_empty() {
            anyhow::bail!("At least one HTTP endpoint must be configured");
        }

        // 1. Port conflict validation
        self.validate_port_conflicts()?;

        // 2. Listener validation
        for listener in &self.listeners {
            if listener.port == 0 {
                anyhow::bail!("Invalid port number: {}", listener.port);
            }
            if listener.community_strings.is_empty() {
                anyhow::bail!("At least one community string must be configured");
            }
            
            // Validate bind address
            if listener.bind_address != "0.0.0.0" && listener.bind_address.parse::<IpAddr>().is_err() {
                anyhow::bail!("Invalid bind address: {}", listener.bind_address);
            }
        }

        // 3. Endpoint validation
        for endpoint in &self.endpoints {
            if endpoint.name.is_empty() {
                anyhow::bail!("Endpoint name cannot be empty");
            }
            if endpoint.url.is_empty() {
                anyhow::bail!("Endpoint URL cannot be empty");
            }
            if !endpoint.url.starts_with("http://") && !endpoint.url.starts_with("https://") {
                anyhow::bail!("Invalid endpoint URL: {}", endpoint.url);
            }
        }

        // 4. Source mapping validation
        if let Some(ref source_mapping) = self.source_mapping {
            self.validate_source_mapping(source_mapping)?;
        }

        Ok(())
    }

    /// Validate that no two listeners use the same port and bind address combination
    fn validate_port_conflicts(&self) -> Result<()> {
        let mut used_addresses = HashSet::new();

        for listener in &self.listeners {
            let address_key = format!("{}:{}", listener.bind_address, listener.port);
            
            if used_addresses.contains(&address_key) {
                anyhow::bail!("Port conflict: Multiple listeners configured for {}:{}", 
                    listener.bind_address, listener.port);
            }
            
            used_addresses.insert(address_key);
        }

        Ok(())
    }

    /// Validate source mapping IP addresses and endpoint name references
    fn validate_source_mapping(&self, source_mapping: &HashMap<String, String>) -> Result<()> {
        // Collect all valid endpoint names
        let valid_endpoint_names: HashSet<String> = self.endpoints
            .iter()
            .map(|e| e.name.clone())
            .collect();

        for (source_pattern, endpoint_name) in source_mapping {
            // 1. Validate that endpoint name exists
            if !valid_endpoint_names.contains(endpoint_name) {
                anyhow::bail!("Source mapping references non-existent endpoint: '{}' -> '{}'", 
                    source_pattern, endpoint_name);
            }

            // 2. Validate IP address pattern
            self.validate_ip_pattern(source_pattern)
                .with_context(|| format!("Invalid source pattern: '{}'", source_pattern))?;
        }

        Ok(())
    }

    /// Validate IP address pattern (supports CIDR notation, wildcards, and individual IPs)
    fn validate_ip_pattern(&self, pattern: &str) -> Result<()> {
        // Handle wildcard patterns
        if pattern == "*" || pattern == "0.0.0.0/0" || pattern == "::/0" {
            return Ok(()); // Valid catch-all patterns
        }

        // Handle wildcard IP patterns like "192.168.1.*"
        if pattern.contains('*') {
            return self.validate_wildcard_pattern(pattern);
        }

        // Handle CIDR notation
        if pattern.contains('/') {
            return pattern.parse::<IpNet>()
                .map(|_| ())
                .with_context(|| format!("Invalid CIDR notation: {}", pattern));
        }

        // Handle individual IP address
        pattern.parse::<IpAddr>()
            .map(|_| ())
            .with_context(|| format!("Invalid IP address: {}", pattern))
    }

    /// Validate wildcard patterns like "192.168.1.*" or "2001:db8::*"
    fn validate_wildcard_pattern(&self, pattern: &str) -> Result<()> {
        let parts: Vec<&str> = pattern.split('*').collect();
        
        if parts.len() != 2 {
            return Err(anyhow!("Invalid wildcard pattern - only one '*' allowed per pattern"));
        }

        let prefix = parts[0];
        let suffix = parts[1];

        // Suffix should be empty or start with a valid separator
        if !suffix.is_empty() && !suffix.starts_with('.') && !suffix.starts_with(':') {
            return Err(anyhow!("Invalid wildcard pattern - invalid suffix"));
        }

        // IPv4 wildcard validation
        if prefix.contains('.') {
            if prefix.is_empty() {
                return Ok(()); // Pattern like "*" is valid
            }
            
            // Ensure prefix ends with '.' for IPv4
            if !prefix.ends_with('.') {
                return Err(anyhow!("IPv4 wildcard pattern must end with '.' before '*'"));
            }
            
            // Validate prefix is valid IPv4 partial address
            let trimmed_prefix = prefix.trim_end_matches('.');
            if !trimmed_prefix.is_empty() {
                let parts: Vec<&str> = trimmed_prefix.split('.').collect();
                if parts.len() > 3 {
                    return Err(anyhow!("Invalid IPv4 wildcard prefix"));
                }
                
                for part in parts {
                    let octet: u16 = part.parse()
                        .with_context(|| format!("Invalid IPv4 octet: {}", part))?;
                    if octet > 255 {
                        return Err(anyhow!("IPv4 octet out of range: {}", octet));
                    }
                }
            }
        }
        // IPv6 wildcard validation
        else if prefix.contains(':') {
            // Basic IPv6 wildcard validation
            if !prefix.ends_with(':') && !prefix.is_empty() {
                return Err(anyhow!("IPv6 wildcard pattern should end with ':' before '*'"));
            }
        }
        else if !prefix.is_empty() {
            return Err(anyhow!("Wildcard pattern prefix must be valid IP address format"));
        }

        Ok(())
    }

    /// Match a source IP address against configured patterns (CIDR, wildcards, exact matches)
    pub fn match_source_ip(&self, source_ip: &str) -> Option<String> {
        let source_mapping = match &self.source_mapping {
            Some(mapping) => mapping,
            None => return self.endpoints.first().map(|e| e.name.clone()),
        };

        // Validate and parse the source IP with comprehensive error handling
        let source_addr = match self.parse_source_ip_safely(source_ip) {
            Some(addr) => addr,
            None => {
                warn!("Invalid source IP address format: '{}' - falling back to catch-all pattern", source_ip);
                // Try to match catch-all patterns even with invalid IP
                return self.find_catch_all_endpoint(source_mapping);
            }
        };

        // Try to match against each pattern in order with enhanced validation
        for (pattern, endpoint_name) in source_mapping {
            match self.ip_matches_pattern_safely(&source_addr, pattern) {
                Ok(true) => {
                    debug!("Source IP {} matched pattern '{}' -> endpoint '{}'", source_ip, pattern, endpoint_name);
                    return Some(endpoint_name.clone());
                }
                Ok(false) => continue,
                Err(e) => {
                    warn!("Invalid pattern '{}' in source mapping: {} - skipping", pattern, e);
                    continue;
                }
            }
        }

        // Fall back to default endpoint if no match
        let fallback = self.endpoints.first().map(|e| e.name.clone());
        debug!("No pattern matched source IP {} - using fallback endpoint: {:?}", source_ip, fallback);
        fallback
    }

    /// Safely parse source IP with comprehensive validation
    fn parse_source_ip_safely(&self, source_ip: &str) -> Option<IpAddr> {
        // Handle empty/whitespace-only input
        let trimmed = source_ip.trim();
        if trimmed.is_empty() {
            return None;
        }

        // Validate string length (IPv6 can be up to 39 chars, IPv4 up to 15)
        if trimmed.len() > 45 {
            return None;
        }

        // Check for obviously invalid patterns
        if trimmed.starts_with('.') || trimmed.ends_with('.') || 
           trimmed.starts_with(':') || trimmed.contains("..") ||
           trimmed.contains(":::") {
            return None;
        }

        // Attempt to parse as IP address
        trimmed.parse::<IpAddr>().ok()
    }

    /// Find catch-all endpoint for invalid IP addresses
    fn find_catch_all_endpoint(&self, source_mapping: &std::collections::HashMap<String, String>) -> Option<String> {
        // Look for catch-all patterns in order of preference
        let catch_all_patterns = ["*", "0.0.0.0/0", "::/0"];
        
        for pattern in &catch_all_patterns {
            if let Some(endpoint_name) = source_mapping.get(*pattern) {
                debug!("Using catch-all pattern '{}' for invalid IP -> endpoint '{}'", pattern, endpoint_name);
                return Some(endpoint_name.clone());
            }
        }
        
        // Final fallback to first configured endpoint
        self.endpoints.first().map(|e| e.name.clone())
    }

    /// Check if an IP address matches a given pattern with comprehensive error handling
    fn ip_matches_pattern_safely(&self, ip_addr: &IpAddr, pattern: &str) -> Result<bool> {
        // Validate pattern format first
        let trimmed_pattern = pattern.trim();
        if trimmed_pattern.is_empty() {
            return Err(anyhow!("Empty pattern"));
        }

        // Catch-all patterns
        if trimmed_pattern == "*" || trimmed_pattern == "0.0.0.0/0" || trimmed_pattern == "::/0" {
            return Ok(true);
        }

        // Exact IP match with validation
        if let Ok(pattern_addr) = trimmed_pattern.parse::<IpAddr>() {
            return Ok(ip_addr == &pattern_addr);
        }

        // CIDR notation match with enhanced validation
        if trimmed_pattern.contains('/') {
            return self.validate_and_match_cidr(ip_addr, trimmed_pattern);
        }

        // Wildcard pattern match with validation
        if trimmed_pattern.contains('*') {
            return self.validate_and_match_wildcard(ip_addr, trimmed_pattern);
        }

        Err(anyhow!("Unrecognized pattern format: {}", trimmed_pattern))
    }

    /// Validate and match CIDR patterns
    fn validate_and_match_cidr(&self, ip_addr: &IpAddr, pattern: &str) -> Result<bool> {
        // Split CIDR notation
        let parts: Vec<&str> = pattern.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid CIDR format - must have exactly one '/'"));
        }

        let (network_part, prefix_part) = (parts[0], parts[1]);

        // Validate network address
        let network_addr = network_part.parse::<IpAddr>()
            .with_context(|| format!("Invalid network address in CIDR: {}", network_part))?;

        // Validate prefix length
        let prefix_len: u8 = prefix_part.parse()
            .with_context(|| format!("Invalid prefix length: {}", prefix_part))?;

        // Check prefix length bounds based on IP version
        let max_prefix = match network_addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix_len > max_prefix {
            return Err(anyhow!("Prefix length {} exceeds maximum {} for {:?}", 
                prefix_len, max_prefix, network_addr));
        }

        // Ensure IP versions match
        match (ip_addr, &network_addr) {
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => {
                return Ok(false); // Different IP versions never match
            }
            _ => {}
        }

        // Parse as IpNet for matching
        match pattern.parse::<IpNet>() {
            Ok(network) => Ok(network.contains(ip_addr)),
            Err(e) => Err(anyhow!("Failed to parse CIDR network: {}", e)),
        }
    }

    /// Validate and match wildcard patterns
    fn validate_and_match_wildcard(&self, ip_addr: &IpAddr, pattern: &str) -> Result<bool> {
        // Pre-validate the wildcard pattern
        self.validate_wildcard_pattern(pattern)?;

        // Handle IPv4 wildcard matching
        if let IpAddr::V4(ipv4) = ip_addr {
            if pattern.contains('.') {
                return self.match_ipv4_wildcard(ipv4, pattern);
            }
        }

        // Handle IPv6 wildcard matching
        if let IpAddr::V6(ipv6) = ip_addr {
            if pattern.contains(':') {
                return self.match_ipv6_wildcard(ipv6, pattern);
            }
        }

        // Pattern and IP version mismatch
        Ok(false)
    }

    /// Match IPv4 address against wildcard pattern
    fn match_ipv4_wildcard(&self, ipv4: &std::net::Ipv4Addr, pattern: &str) -> Result<bool> {
        let ip_str = ipv4.to_string();
        
        if pattern == "*" {
            return Ok(true);
        }

        if !pattern.contains('*') {
            return Err(anyhow!("Not a wildcard pattern"));
        }

        // Split pattern at the wildcard
        let parts: Vec<&str> = pattern.splitn(2, '*').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid wildcard pattern format"));
        }

        let (prefix, suffix) = (parts[0], parts[1]);

        // Match prefix and suffix
        if !prefix.is_empty() && !ip_str.starts_with(prefix) {
            return Ok(false);
        }

        if !suffix.is_empty() && !ip_str.ends_with(suffix) {
            return Ok(false);
        }

        Ok(true)
    }

    /// Match IPv6 address against wildcard pattern
    fn match_ipv6_wildcard(&self, ipv6: &std::net::Ipv6Addr, pattern: &str) -> Result<bool> {
        let ip_str = ipv6.to_string();
        
        if pattern == "*" {
            return Ok(true);
        }

        if !pattern.contains('*') {
            return Err(anyhow!("Not a wildcard pattern"));
        }

        // Basic IPv6 prefix matching (simplified for now)
        let parts: Vec<&str> = pattern.splitn(2, '*').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid IPv6 wildcard pattern format"));
        }

        let prefix = parts[0];
        
        if !prefix.is_empty() && !ip_str.starts_with(prefix) {
            return Ok(false);
        }

        Ok(true)
    }

}


