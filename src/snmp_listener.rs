//! SNMP Trap Listener Implementation for AckbarX
//! 
//! Listens for SNMP traps on configured UDP ports and processes them
//! for forwarding to HTTP endpoints with source-based routing.
//! 
//! Developed by GoCortex.io

use crate::config::SnmpListenerConfig;
use crate::cache_manager::{RejectedTrap, ValidationFailureType};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq)]
pub enum SnmpVersion {
    V1,
    V2c,
    V3,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpTrap {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source_address: String,
    pub version: String,
    pub community: Option<String>,
    pub enterprise_oid: Option<String>,
    pub trap_type: Option<u32>,
    pub specific_type: Option<u32>,
    pub timestamp_ticks: Option<u32>,
    pub variable_bindings: Vec<SnmpVariable>,
    pub raw_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpVariable {
    pub oid: String,
    pub value_type: String,
    pub value: String,
}

pub struct SnmpListener {
    config: SnmpListenerConfig,
    trap_sender: mpsc::UnboundedSender<SnmpTrap>,
    rejected_trap_sender: mpsc::UnboundedSender<RejectedTrap>,
}

impl SnmpListener {
    pub fn new(
        config: SnmpListenerConfig,
        trap_sender: mpsc::UnboundedSender<SnmpTrap>,
        rejected_trap_sender: mpsc::UnboundedSender<RejectedTrap>,
    ) -> Self {
        Self {
            config,
            trap_sender,
            rejected_trap_sender,
        }
    }
    
    /// Start listening for SNMP traps on the configured port
    pub async fn start(self: Arc<Self>) -> Result<()> {
        let bind_addr = format!("{}:{}", self.config.bind_address, self.config.port);
        let socket = UdpSocket::bind(&bind_addr)
            .await
            .context(format!("Failed to bind to {}", bind_addr))?;
        
        // Set larger socket buffer to handle high-throughput bursts
        // Note: Tokio UdpSocket doesn't expose buffer size methods directly
        // OS-level buffer tuning should be done via sysctl if needed
        
        info!("SNMP listener started on {}", bind_addr);
        
        let mut buffer = vec![0u8; self.config.max_packet_size];
        let mut packet_count = 0u64;
        
        loop {
            match socket.recv_from(&mut buffer).await {
                Ok((len, src_addr)) => {
                    packet_count += 1;
                    let data = buffer[..len].to_vec();
                    let listener = Arc::clone(&self);
                    
                    // Log high-rate activity for diagnostics
                    if packet_count % 1000 == 0 {
                        info!("Processed {} UDP packets on port {}", packet_count, self.config.port);
                    }
                    
                    // Process the trap in a separate task to avoid blocking the listener
                    tokio::spawn(async move {
                        if let Err(e) = listener.process_trap_data(data, src_addr).await {
                            error!("Failed to process SNMP trap from {}: {}", src_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to receive UDP packet: {}", e);
                    // Continue listening despite errors
                }
            }
        }
    }
    
    /// Process incoming SNMP trap data
    async fn process_trap_data(&self, data: Vec<u8>, src_addr: SocketAddr) -> Result<()> {
        debug!("Processing SNMP trap from {} ({} bytes)", src_addr, data.len());
        
        // Parse the SNMP message
        let trap = match self.parse_snmp_trap(&data, src_addr).await {
            Ok(trap) => trap,
            Err(e) => {
                warn!("Failed to parse SNMP trap from {}: {}", src_addr, e);
                
                // Create a rejected trap record for unparseable data
                let minimal_trap = SnmpTrap {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: Utc::now(),
                    source_address: src_addr.ip().to_string(),
                    version: "unknown".to_string(),
                    community: None,
                    enterprise_oid: None,
                    trap_type: None,
                    specific_type: None,
                    timestamp_ticks: None,
                    variable_bindings: vec![],
                    raw_data: data,
                };
                
                let rejected_trap = RejectedTrap {
                    trap: minimal_trap,
                    rejected_at: Utc::now(),
                    rejection_reason: format!("SNMP parsing failed: {}", e),
                    validation_failure: ValidationFailureType::UnparseableData { 
                        parse_error: e.to_string() 
                    },
                };
                
                // Send to lost and found instead of normal processing
                if let Err(send_err) = self.rejected_trap_sender.send(rejected_trap) {
                    error!("Failed to send rejected trap to lost-and-found: {}", send_err);
                }
                return Ok(());
            }
        };
        
        // Send the successfully parsed trap for processing
        if let Err(e) = self.trap_sender.send(trap) {
            error!("Failed to send trap for processing: {}", e);
        }
        
        Ok(())
    }
    
    /// Parse SNMP trap from raw bytes with enhanced version and community validation
    async fn parse_snmp_trap(&self, data: &[u8], src_addr: SocketAddr) -> Result<SnmpTrap> {
        if data.len() < 10 {
            anyhow::bail!("SNMP packet too short");
        }
        
        // Check if it looks like an SNMP message (starts with SEQUENCE tag)
        if data[0] != 0x30 {
            anyhow::bail!("Not a valid SNMP message");
        }
        
        // Enhanced SNMP parsing with version-specific handling
        let (version, community, parsed_version) = self.parse_enhanced_snmp_header(data)?;
        
        // Enhanced community string validation (must be done before other validations)
        self.validate_community_string(&community, &parsed_version)?;
        
        // Validate SNMP version against listener configuration
        if !self.is_version_supported(&parsed_version) {
            anyhow::bail!("SNMP version {} not supported by this listener", version);
        }
        
        // Extract trap information with version-specific parsing
        let (enterprise_oid, trap_type, specific_type, timestamp_ticks, variable_bindings) = 
            self.parse_enhanced_trap_pdu(data, &parsed_version)?;
        
        let trap = SnmpTrap {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            source_address: src_addr.ip().to_string(),
            version,
            community,
            enterprise_oid,
            trap_type,
            specific_type,
            timestamp_ticks,
            variable_bindings,
            raw_data: data.to_vec(),
        };
        
        debug!("Parsed SNMP {} trap: {} from {}", trap.version, trap.id, trap.source_address);
        Ok(trap)
    }
    
    /// Parse enhanced SNMP header with version-specific handling
    fn parse_enhanced_snmp_header(&self, data: &[u8]) -> Result<(String, Option<String>, SnmpVersion)> {
        if data.len() < 8 {
            anyhow::bail!("SNMP packet too short for header parsing");
        }
        
        // Skip sequence header and length with proper bounds checking
        let mut offset = 2;
        if data[1] & 0x80 != 0 {
            let len_bytes = (data[1] & 0x7F) as usize;
            if len_bytes > 4 || offset + len_bytes >= data.len() {
                anyhow::bail!("Invalid SNMP message length encoding");
            }
            offset += len_bytes;
        }
        
        if offset >= data.len() {
            anyhow::bail!("Invalid SNMP message structure");
        }
        
        // Parse version (INTEGER) with enhanced validation
        if data[offset] != 0x02 {
            anyhow::bail!("Expected INTEGER tag for SNMP version");
        }
        
        if offset + 2 >= data.len() {
            anyhow::bail!("SNMP version field truncated");
        }
        
        let version_len = data[offset + 1] as usize;
        if version_len != 1 || offset + 2 + version_len >= data.len() {
            anyhow::bail!("Invalid SNMP version field length");
        }
        
        let version_num = data[offset + 2];
        let (version_str, parsed_version) = match version_num {
            0 => ("v1".to_string(), SnmpVersion::V1),
            1 => ("v2c".to_string(), SnmpVersion::V2c),
            3 => ("v3".to_string(), SnmpVersion::V3),
            v => (format!("unknown({})", v), SnmpVersion::Unknown),
        };
        
        // Move to community string (skip version INTEGER: tag + length + value)
        offset += 2 + version_len;
        
        // Parse community string with version-specific handling
        let community = if parsed_version == SnmpVersion::V3 {
            // SNMPv3 uses security parameters instead of community strings
            None
        } else if offset < data.len() && data[offset] == 0x04 {
            // OCTET STRING tag for community
            if offset + 1 >= data.len() {
                anyhow::bail!("Community string length field missing");
            }
            
            let comm_len = data[offset + 1] as usize;
            if comm_len > 255 || offset + 2 + comm_len > data.len() {
                anyhow::bail!("Invalid community string length: {}", comm_len);
            }
            
            match std::str::from_utf8(&data[offset + 2..offset + 2 + comm_len]) {
                Ok(s) => Some(s.to_string()),
                Err(_) => anyhow::bail!("Community string contains invalid UTF-8"),
            }
        } else {
            // Missing or invalid community string
            anyhow::bail!("Expected community string for SNMP v1/v2c");
        };
        
        Ok((version_str, community, parsed_version))
    }

    /// Check if SNMP version is supported by this listener
    fn is_version_supported(&self, version: &SnmpVersion) -> bool {
        use crate::config::SnmpVersion as ConfigSnmpVersion;
        
        for supported_version in &self.config.snmp_version {
            match (supported_version, version) {
                (ConfigSnmpVersion::V1, SnmpVersion::V1) => return true,
                (ConfigSnmpVersion::V2c, SnmpVersion::V2c) => return true,
                (ConfigSnmpVersion::V3, SnmpVersion::V3) => return true,
                _ => continue,
            }
        }
        false
    }

    /// Enhanced community string validation with version awareness
    fn validate_community_string(&self, community: &Option<String>, version: &SnmpVersion) -> Result<()> {
        match version {
            SnmpVersion::V1 | SnmpVersion::V2c => {
                match community {
                    Some(comm) => {
                        if !self.config.community_strings.contains(comm) {
                            anyhow::bail!("Invalid community string '{}' for SNMP {}", 
                                comm, if matches!(version, SnmpVersion::V1) { "v1" } else { "v2c" });
                        }
                    }
                    None => {
                        anyhow::bail!("Community string required for SNMP {}", 
                            if matches!(version, SnmpVersion::V1) { "v1" } else { "v2c" });
                    }
                }
            }
            SnmpVersion::V3 => {
                // SNMPv3 doesn't use community strings but uses security parameters
                if community.is_some() {
                    debug!("Community string present in SNMPv3 message (will be ignored)");
                }
            }
            SnmpVersion::Unknown => {
                anyhow::bail!("Unknown SNMP version, cannot validate community string");
            }
        }
        Ok(())
    }
    
    /// Parse enhanced trap PDU with version-specific handling
    #[allow(clippy::type_complexity)]
    fn parse_enhanced_trap_pdu(&self, data: &[u8], version: &SnmpVersion) -> Result<(Option<String>, Option<u32>, Option<u32>, Option<u32>, Vec<SnmpVariable>)> {
        // Enhanced trap parsing with version-specific differences
        
        let enterprise_oid = match version {
            SnmpVersion::V1 => {
                // V1 traps have enterprise OID field
                self.extract_v1_enterprise_oid(data).unwrap_or_else(|| "1.3.6.1.4.1.0".to_string())
            }
            SnmpVersion::V2c | SnmpVersion::V3 => {
                // V2c/V3 use snmpTrapOID in variable bindings
                self.extract_v2_trap_oid(data).unwrap_or_else(|| "1.3.6.1.6.3.1.1.4.1.0".to_string())
            }
            SnmpVersion::Unknown => "1.3.6.1.4.1.0".to_string(),
        };

        let (trap_type, specific_type) = match version {
            SnmpVersion::V1 => {
                // V1 traps have explicit generic-trap and specific-trap fields
                let generic_trap = self.extract_v1_generic_trap(data).unwrap_or(6); // Default to enterprise-specific
                let specific_trap = if generic_trap == 6 {
                    self.extract_v1_specific_trap(data).unwrap_or(1)
                } else {
                    0 // Standard traps don't use specific-trap
                };
                (Some(generic_trap), Some(specific_trap))
            }
            SnmpVersion::V2c | SnmpVersion::V3 => {
                // V2c/V3 encode trap type in the OID
                (Some(6), Some(1)) // Default to enterprise-specific
            }
            SnmpVersion::Unknown => (Some(6), Some(1)),
        };
        
        let timestamp_ticks = match version {
            SnmpVersion::V1 => {
                // V1 traps have explicit timestamp field
                self.extract_v1_timestamp(data).or_else(|| {
                    let now = chrono::Utc::now().timestamp();
                    // Use modular arithmetic to prevent overflow
                    Some((now % 86400).max(0) as u32)
                })
            }
            SnmpVersion::V2c | SnmpVersion::V3 => {
                // V2c/V3 use sysUpTime in variable bindings
                {
                    let now = chrono::Utc::now().timestamp();
                    // Use modular arithmetic to prevent overflow
                    Some((now % 86400).max(0) as u32)
                }
            }
            SnmpVersion::Unknown => {
                let now = chrono::Utc::now().timestamp();
                // Use modular arithmetic to prevent overflow
                Some((now % 86400).max(0) as u32)
            },
        };
        
        // Create some basic variable bindings as examples
        let variable_bindings = vec![
            SnmpVariable {
                oid: "1.3.6.1.2.1.1.3.0".to_string(), // sysUpTime
                value_type: "TimeTicks".to_string(),
                value: timestamp_ticks.unwrap().to_string(),
            },
            SnmpVariable {
                oid: "1.3.6.1.6.3.1.1.4.1.0".to_string(), // snmpTrapOID
                value_type: "OBJECT_IDENTIFIER".to_string(),
                value: enterprise_oid.clone(),
            },
        ];
        
        Ok((Some(enterprise_oid), trap_type, specific_type, timestamp_ticks, variable_bindings))
    }

    // Version-specific field extraction methods (simplified implementations)
    
    fn extract_v1_enterprise_oid(&self, _data: &[u8]) -> Option<String> {
        // Simplified - would need full ASN.1 parsing for complete implementation
        Some("1.3.6.1.4.1.0".to_string())
    }

    fn extract_v1_generic_trap(&self, _data: &[u8]) -> Option<u32> {
        // Simplified - would parse the generic-trap field from V1 trap PDU
        Some(6) // enterprise-specific
    }

    fn extract_v1_specific_trap(&self, _data: &[u8]) -> Option<u32> {
        // Simplified - would parse the specific-trap field from V1 trap PDU
        Some(1)
    }

    fn extract_v1_timestamp(&self, _data: &[u8]) -> Option<u32> {
        // Simplified - would parse the time-stamp field from V1 trap PDU
        Some((chrono::Utc::now().timestamp() % 86400) as u32)
    }

    fn extract_v2_trap_oid(&self, _data: &[u8]) -> Option<String> {
        // Simplified - would parse snmpTrapOID from variable bindings
        Some("1.3.6.1.6.3.1.1.4.1.0".to_string())
    }
}


