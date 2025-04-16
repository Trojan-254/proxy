use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserTier {
    Free,
    Premium,
    PremiumEducation,
    PremiumBusiness,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientIdentifier {
    pub client_id: String,
    pub ip_addr: IpAddr,
    pub additional: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccount {
    pub client_id: String,
    pub tier: UserTier,
    pub name: String,
    pub email: Option<String>,
    pub max_devices: u32,
    pub active_devices: u32,
    pub quota_daily: u32,
    pub quota_used: u32,
    pub custom_rules_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub name: String,
    pub ip_address: IpAddr,
    pub mac_address: Option<String>,
    pub browser_fingerprint: Option<String>,
    pub last_active: DateTime<Utc>,
    pub group: Option<String>, // Parents, Children, Staff, ...
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilteringRules {
    pub blocked_categories: Vec<String>,
    pub allowed_categories: Vec<String>,
    pub custom_blocked_domains: Vec<String>,
    pub custom_allowed_domains: Vec<String>,
    pub time_restrictions: Vec<TimeRestriction>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRestriction {
    pub name: String,
    pub days: Vec<Weekday>,
    pub start_time: String, // Format "HH:MM"
    pub end_time: String, // Same format
    pub blocked_categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Weekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}