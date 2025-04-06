use std::net::{IpAddr, SocketAddr};
use serde::{Deserialize, Serialize};
use thiserror::Error;



/// Error types for client mapping operations
#[derive(Error, Debug)]
pub enum ClientError {
    
    #[error("Client IP not found in mapping table")]
    ClientNotFound,
    
    #[error("Client mapping has expired")]
    MappingExpired,
    
    #[error("Group not found: {0}")]
    GroupNotFound(String),
    
    #[error("Invalid MAC address format: {0}")]
    InvalidMacAddress(String),
    
    #[error("Invalid client identifier: {0}")]
    InvalidIdentifier(String),
}

/// Result type for client operations
pub type ClientResult<T> = Result<T, ClientError>;

/// Client identification methods
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientIdentifier {
    /// Identify by IP address
    IpAddress(IpAddr),
    
    /// Identify by MAC address
    MacAddress(String),
    
    /// Identify by hostname
    Hostname(String),
    
    /// Identify by custom identifier (e.g., client certificate CN)
    CustomId(String),
    
    /// Identify by IP subnet (CIDR notation)
    Subnet(String, u8), // (Network address, prefix length)
}

impl ClientIdentifier {
    /// Parse a client identifier from string representation
    pub fn from_string(s: &str) -> Result<Self, ClientError> {
        // Try as IP address first
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(ClientIdentifier::IpAddress(ip));
        }
        
        // Check for MAC address format (XX:XX:XX:XX:XX:XX)
        let mac_regex = regex::Regex::new(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$").unwrap();
        if mac_regex.is_match(s) {
            return Ok(ClientIdentifier::MacAddress(s.to_uppercase()));
        }
        
        // Check for subnet format (192.168.1.0/24)
        let subnet_regex = regex::Regex::new(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$").unwrap();
        if let Some(caps) = subnet_regex.captures(s) {
            if let (Ok(ip), Ok(prefix)) = (caps[1].parse::<IpAddr>(), caps[2].parse::<u8>()) {
                if (ip.is_ipv4() && prefix <= 32) || (ip.is_ipv6() && prefix <= 128) {
                    return Ok(ClientIdentifier::Subnet(caps[1].to_string(), prefix));
                }
            }
        }
        
        // If it looks like a hostname (contains letters and no special chars other than -)
        let hostname_regex = regex::Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$").unwrap();
        if hostname_regex.is_match(s) {
            return Ok(ClientIdentifier::Hostname(s.to_lowercase()));
        }
        
        // Otherwise, treat as custom identifier
        Ok(ClientIdentifier::CustomId(s.to_string()))
    }
    
    /// Check if this identifier matches a given IP address
    pub fn matches_ip(&self, ip: &IpAddr) -> bool {
        match self {
            ClientIdentifier::IpAddress(self_ip) => self_ip == ip,
            ClientIdentifier::Subnet(network, prefix) => {
                // Check if IP is in subnet
                match (ip, network.parse::<IpAddr>()) {
                    (IpAddr::V4(ip_v4), Ok(IpAddr::V4(network_v4))) => {
                        let ip_bits = u32::from_be_bytes(ip_v4.octets());
                        let network_bits = u32::from_be_bytes(network_v4.octets());
                        let mask = if *prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                        (ip_bits & mask) == (network_bits & mask)
                    },
                    (IpAddr::V6(ip_v6), Ok(IpAddr::V6(network_v6))) => {
                        let ip_bits = u128::from_be_bytes(ip_v6.octets());
                        let network_bits = u128::from_be_bytes(network_v6.octets());
                        let mask = if *prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
                        (ip_bits & mask) == (network_bits & mask)
                    },
                    _ => false,
                }
            },
            _ => false, // Other types need additional information to match IP
        }
    }
}

/// Database-stored client mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMapping {
    /// Client identifier (IP, MAC, etc.)
    pub identifier: ClientIdentifier,
    
    /// User group ID this client belongs to
    pub group_id: String,
    
    /// Optional friendly name for this client
    pub friendly_name: Option<String>,
    
    /// When this mapping expires (unix timestamp)
    pub expires: u64,
    
    /// Additional metadata as JSON
    pub metadata: serde_json::Value,
}

/// Runtime client information derived from request
#[derive(Debug, Clone)]
pub struct ClientInfo {
    /// IP address of the client
    pub ip_addr: IpAddr,
    
    /// Port the client is connecting from
    pub port: u16,
    
    /// MAC address if available
    pub mac_address: Option<String>,
    
    /// Hostname if available
    pub hostname: Option<String>,
    
    /// User group the client belongs to
    pub group_id: Option<String>,
    
    /// Friendly name for the client
    pub friendly_name: Option<String>,
}

impl ClientInfo {
    /// Create a new ClientInfo from a socket address
    pub fn from_addr(addr: SocketAddr) -> Self {
        Self {
            ip_addr: addr.ip(),
            port: addr.port(),
            mac_address: None,
            hostname: None,
            group_id: None,
            friendly_name: None,
        }
    }
    
    /// Create a new ClientInfo with all fields
    #[allow(dead_code)]
    pub fn new(
        ip_addr: IpAddr,
        port: u16,
        mac_address: Option<String>,
        hostname: Option<String>,
        group_id: Option<String>,
        friendly_name: Option<String>,
    ) -> Self {
        Self {
            ip_addr,
            port,
            mac_address,
            hostname,
            group_id,
            friendly_name,
        }
    }
}