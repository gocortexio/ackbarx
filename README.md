# AckbarX - Enterprise SNMP Trap Forwarder

AckbarX is a robust Rust-based SNMP Trap Forwarder developed by GoCortex.io to bridge traditional SNMP monitoring infrastructure with modern HTTP-based log ingestion systems, specifically targeting Cortex XSIAM/XDR platforms.

## Key Features

- **Multi-protocol SNMP Support** - Handles SNMPv1, v2c, and v3 traps with version-specific parsing
- **HTTP Endpoint Forwarding** - Forwards traps to Cortex XSIAM and other REST APIs with authentication
- **Source-based Routing** - Routes traps to different endpoints based on IP patterns (CIDR, wildcards, exact matches)
- **Redundant File-based Caching** - Offline resilience with caching to ALL endpoint directories for full redundancy
- **Atomic Graceful Shutdown** - Zero data loss during shutdown with atomic coordination preventing HTTP retry delays
- **Lost and Found System** - Preserves all rejected traps for forensic analysis and debugging
- **Advanced Log Rotation** - Automatic log management with size limits and file cleanup
- **Dual Configuration Generation** - Simple and complex configuration templates for different deployment scenarios
- **Production Ready** - Comprehensive error handling, enhanced diagnostics, and enterprise-grade reliability

## Quick Start

### Simple Setup (Single Endpoint, Basic Configuration)
1. **Generate Simple Config**: `./ackbarx --generate-simple-config`
2. **Edit API Keys**: Update `config.json` with your XSIAM endpoint and authentication
3. **Start Service**: `./ackbarx --config config.json`

### Enterprise Setup (Multiple Endpoints, Advanced Routing)
1. **Generate Complex Config**: `./ackbarx --generate-config`
2. **Configure Endpoints**: Update `config.json` with your primary/backup XSIAM instances
3. **Set Source Routing**: Configure IP-based routing patterns
4. **Start Service**: `./ackbarx --config config.json`

### Automatic Configuration Creation
If no `config.json` exists, AckbarX automatically creates a simple configuration and starts:
```bash
./ackbarx  # Auto-generates simple config.json if missing
```

## Configuration Options

### Simple vs Complex Configuration

| Feature | Simple Config (`--generate-simple-config`) | Complex Config (`--generate-config`) |
|---------|---------------------------------------------|---------------------------------------|
| **SNMP Listeners** | 1 (port 162) | 2 (ports 162, 1162) |
| **HTTP Endpoints** | 1 (xsiam) | 2 (primary_xsiam, backup_xsiam) |
| **SNMP Versions** | V1, V2c only | V1, V2c, V3 |
| **Source Routing** | Catch-all (*) | Advanced CIDR/IP matching |
| **Cache Settings** | 100MB/24h | 500MB/48h |
| **Best For** | Quick start, single tenant | Production, high availability |

## SNMP Configuration

### SNMPv1 Listener
```json
{
  "port": 162,
  "bind_address": "0.0.0.0",
  "community_strings": ["public", "private"],
  "snmp_version": ["V1"],
  "max_packet_size": 8192
}
```
**Purpose**: Receives legacy SNMPv1 traps with simple community string authentication.

### SNMPv2c Listener
```json
{
  "port": 1162,
  "bind_address": "0.0.0.0",
  "community_strings": ["monitoring", "network"],
  "snmp_version": ["V2c"],
  "max_packet_size": 16384
}
```
**Purpose**: Handles SNMPv2c traps with improved error handling and data types.

### SNMPv3 Listener
```json
{
  "port": 2162,
  "bind_address": "0.0.0.0",
  "community_strings": [],
  "snmp_version": ["V3"],
  "max_packet_size": 32768
}
```
**Purpose**: Processes secure SNMPv3 traps with user-based authentication and encryption (community strings not used).

### Multi-Version Listener
```json
{
  "port": 162,
  "bind_address": "0.0.0.0",
  "community_strings": ["public", "monitoring"],
  "snmp_version": ["V1", "V2c", "V3"],
  "max_packet_size": 16384
}
```
**Purpose**: Accepts all SNMP versions on a single port for mixed environments.

## HTTP Endpoint Configuration

### Primary XSIAM Endpoint
```json
{
  "name": "primary_xsiam",
  "url": "https://api-your-tenant.xdr.au.paloaltonetworks.com/logs/v1/event",
  "headers": {
    "Content-Type": "text/plain",
    "Authorization": "YOUR_API_KEY_HERE"
  },
  "timeout_seconds": 30,
  "max_retries": 3,
  "retry_backoff_seconds": 5
}
```
**Purpose**: Primary destination for SNMP trap forwarding with XSIAM authentication.

### Backup Endpoint
```json
{
  "name": "backup_xsiam",
  "url": "https://api-backup.xdr.au.paloaltonetworks.com/logs/v1/event",
  "headers": {
    "Content-Type": "text/plain",
    "Authorization": "YOUR_BACKUP_API_KEY_HERE"
  },
  "timeout_seconds": 45,
  "max_retries": 5,
  "retry_backoff_seconds": 10
}
```
**Purpose**: Secondary endpoint for redundancy with extended retry parameters.

## Source-Based Routing

Routes SNMP traps to specific endpoints based on source IP address:

```json
{
  "source_mapping": {
    "192.168.1.0/24": "primary_xsiam",
    "10.0.0.0/8": "backup_xsiam",
    "172.16.0.1": "primary_xsiam",
    "192.168.100.*": "primary_xsiam",
    "*": "primary_xsiam"
  }
}
```

- **CIDR Blocks**: `192.168.1.0/24` matches subnet ranges
- **Wildcards**: `192.168.100.*` matches patterns  
- **Exact IPs**: `172.16.0.1` matches specific devices
- **Catch-all**: `*` handles all unmatched sources

## Cache and Storage

```json
{
  "cache": {
    "enabled": true,
    "max_size_mb": 500,
    "max_age_hours": 48,
    "storage_path": "./cache",
    "flush_interval_seconds": 300
  }
}
```

**Purpose**: Provides offline resilience by caching failed forwards for automatic retry when endpoints recover.

## Logging Configuration

```json
{
  "logging": {
    "level": "info",
    "console_output": true,
    "file_output": "./ackbarx.log",
    "max_log_size_mb": 50,
    "max_log_files": 10,
    "rotation_strategy": "size"
  }
}
```

- **Levels**: `error`, `warn`, `info`, `debug`, `trace`
- **Rotation**: Automatic log rotation when files exceed size limits
- **Cleanup**: Maintains specified number of historical log files

## Building from Source

```bash
cargo build --release
./target/release/ackbarx --help
```

## Installation

### Recommended Installation (Production)
```bash
# Create application directory
sudo mkdir -p /opt/ackbarx
cd /opt/ackbarx

# Copy binary and set permissions
sudo cp /path/to/target/release/ackbarx ./
sudo chmod +x ackbarx

# Create symlink for system-wide access
sudo ln -sf /opt/ackbarx/ackbarx /usr/local/bin/ackbarx

# Generate initial configuration
sudo /opt/ackbarx/ackbarx --generate-simple-config
```

**Why `/opt/ackbarx`?**
- AckbarX creates cache directories (`./cache/`)
- Generates log files (`./ackbarx.log`)
- Stores configuration (`./config.json`)
- Needs a dedicated working directory, not just the binary path

## Command Line Options

```bash
ackbarx [OPTIONS]

Options:
  -c, --config <FILE>           Configuration file path [default: config.json]
  -d, --daemon                  Run as daemon (suppress console output)
      --generate-config         Generate complex configuration file (enterprise setup)
      --generate-simple-config  Generate simple configuration file (basic setup)
  -h, --help                    Print help information
  -V, --version                 Print version information
```

### Configuration Generation Examples

```bash
# Create simple config (single endpoint, SNMPv1/v2c)
./ackbarx --generate-simple-config

# Create complex config (dual endpoints, all SNMP versions)
./ackbarx --generate-config

# Create config with custom filename
./ackbarx --generate-simple-config -c production.json
```

## Production Deployment

### Standard Deployment
1. **Generate Config**: Use `--generate-config` for enterprise or `--generate-simple-config` for basic setup
2. **Configure Endpoints**: Add your XSIAM tenant URLs and API keys
3. **Test Connectivity**: Verify endpoint authentication and network access
4. **Start Service**: Run with appropriate user permissions for UDP port binding
5. **Monitor Logs**: Check log files for successful trap reception and forwarding

### High Availability Deployment
1. **Use Complex Config**: `./ackbarx --generate-config`
2. **Configure Redundant Endpoints**: Set both primary and backup XSIAM instances
3. **Enable Source Routing**: Configure IP-based routing for different network segments
4. **Verify Cache Redundancy**: Ensure both endpoint cache directories are populated
5. **Test Graceful Shutdown**: Verify zero data loss during service restarts



## Troubleshooting

### Cache Directory Structure
```
./cache/
├── primary_xsiam/    ← All failed traps cached here
├── backup_xsiam/     ← Identical copies for redundancy
└── lost_and_found/   ← Rejected traps for analysis
```

### Common Issues
- **Port Binding Failures**: Ensure appropriate permissions for UDP port 162
- **HTTP Endpoint Errors**: Verify XSIAM API keys and network connectivity
- **Cache Directory Permissions**: Ensure write access to cache storage path
- **Missing Traps**: Check both endpoint cache directories for redundant copies

---

**Developed by GoCortex.io**
**Version 0.5.0 - August 2025**