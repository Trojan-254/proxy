/// This is the main filter engine that processes the input data and applies the filter rules.
/// written by Samwuel Simiyu.
/// This module is responsible for managing the filter rules, applying them to the input data,
/// and generating the output data.
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};
use chrono::{Datelike, Local, Timelike};
use serde::{Deserialize, Serialize};
use std::thread;

// Predefined categories for filtering
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Category {
    Adult,
    Gambling,
    SocialMedia,
    Gaming,
    Malware,
    Phishing,
    Advertising,
    #[serde(untagged)]
    Custom(String),
}

impl Category {
    pub fn as_str(&self) -> &str {
        match self {
            Category::Adult => "adult",
            Category::Gambling => "gambling",
            Category::SocialMedia => "social_media",
            Category::Gaming => "gaming",
            Category::Malware => "malware",
            Category::Phishing => "phishing",
            Category::Advertising => "advertising",
            Category::Custom(name) => name,
        }
    }
}


/// Time restriction for filtering rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRestriction {
    /// Days the restriction applies (0 = Sunday, 6 = Saturday)
    pub days: Vec<u8>,
    /// Start time in seconds since midnigth
    pub start_time: u32,
    /// End time in seconds since midnight
    pub end_time: u32,
}

/// Filter rule action
#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Block,
}

/// Filter rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule ID
    pub id: u32,
    
    /// User-friendly description
    pub description: String,
    
    /// Whether the rule is enabled
    pub enabled: bool,
    
    /// Rule priority (lower number = higher priority)
    pub priority: u16,
    
    /// Action to take when rule matches
    pub action: RuleAction,
    
    /// Categories this rule applies to
    pub categories: HashSet<Category>,
    
    /// Exact domain matches
    pub exact_domains: HashSet<String>,
    
    /// Domain patterns (with wildcards)
    pub domain_patterns: Vec<String>,
    
    /// Time restrictions
    pub time_restrictions: Vec<TimeRestriction>,
}

/// Filter profile containing a set of enabled categories to filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterProfile {
    /// Profile name
    pub name: String,
    /// Profile description
    #[serde(default)]
    pub description: String,
    /// Is this the active profile
    #[serde(default)]
    pub is_active: bool,
    /// Categories to filter
    pub blocked_categories: HashSet<Category>,
    /// custom rules to this profile
    pub rules: Vec<Rule>,
}

/// Result of a filter operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterResult {
    /// whether domain is blocked
    pub is_allowed: bool,
    /// Reason for decision
    pub reason: String,
    /// Category the domain belongs to if any
    pub category: Option<Category>,
    /// Rule id that determined this outcome
    pub rule_id: Option<u32>,
}

/// Domain categorization cache entry
struct CategorizeDomain {
    category: Category,
    expiry: SystemTime,
}

/// User preferences
#[derive(Debug, Clone, Serialize, Deserialize, Copy)]
pub struct UserPreferences {
    /// Cache ttl in seconds
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,
    /// enable logging for filter decisions
    #[serde(default)]
    pub enable_logging: bool,
    /// Show notifications for blocked domains
    #[serde(default)]
    pub show_block_notifications: bool,
    /// Auto refresh interval in seconds
    #[serde(default)]
    pub auto_refresh_interval: u64,
}

fn default_cache_ttl() -> u64 {
    3600 // 1 hour
}

impl Default for UserPreferences {
    fn default() -> Self {
        Self {
            cache_ttl: default_cache_ttl(),
            enable_logging: false,
            show_block_notifications: true,
            auto_refresh_interval: 0,
        }
    }
}

/// Complete configuration from JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfiguration {
    /// Available profiles
    pub profiles: Vec<FilterProfile>,
    /// user defined domain categories
    #[serde(default)]
    pub custom_domains: Vec<DomainCategory>,
    /// user defined pattern categories
    #[serde(default)]
    pub custom_patterns: Vec<PatternCategory>,
    /// user preferences
    #[serde(default)]
    pub user_preferences: UserPreferences,
}


/// Domain category mappping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainCategory {
    pub domain: String,
    pub category: Category,
}


/// Pattern to category mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternCategory {
    pub pattern: String,
    pub category: Category,
}

/// Filter engine that processes the input data and applies the filter rules
pub struct EnhancedFilterEngine {
    /// Domain category mappings
    domain_categories: HashMap<String, Category>,
    /// domain pattern category
    pattern_categories: Vec<(String, Category)>,
    /// Available profiles
    profiles: Vec<FilterProfile>,
    /// Active profile
    active_profile: FilterProfile,
    /// Cache of categorized domains patterns
    category_cache: Arc<RwLock<HashMap<String, CategorizeDomain>>>,
    /// Cache TTL in seconds
    cache_ttl: Duration,
    /// User preferences
    preferences: UserPreferences,
    /// Configuration file path
    config_file_path: Option<String>,
    /// Last modified time of the configuration file
    last_modified: Instant,
}

impl EnhancedFilterEngine {
    /// Create a new filter engine from json config 
    pub fn from_json<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        // Load the configuration
        let config = Self::load_config(&path)?;

        // Find the active profile
        let active_profile = config.profiles.iter()
            .find(|p| p.is_active)
            .or_else(|| config.profiles.first())
            .cloned()
            .unwrap_or_else(|| Self::create_default_profile());

        // Initialize engine
        let mut engine = Self {
            domain_categories: HashMap::new(),
            pattern_categories: Vec::new(),
            profiles: config.profiles.clone(),
            active_profile,
            category_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(config.user_preferences.cache_ttl),
            preferences: config.user_preferences,
            config_file_path: Some(path.as_ref().to_string_lossy().to_string()),
            last_modified: Instant::now(),
        };


        // Load domain categories
        for domain_cat in &config.custom_domains {
            engine.add_domain(&domain_cat.domain, domain_cat.category.clone());
        }

        // Load pattern categories
        for pattern_cat in &config.custom_patterns {
            engine.add_pattern(&pattern_cat.pattern, pattern_cat.category.clone());
        }
        
        // Start auto-refresh thread if enabled
        if engine.preferences.auto_refresh_interval > 0 {
            engine.start_auto_refresh();
        }
        
        Ok(engine)
    }

    /// Load configuration from JSON file
    /// This function will read the JSON file and parse it into a FilterConfiguration struct
    fn load_config<P: AsRef<Path>>(path: P) -> Result<FilterConfiguration, Box<dyn std::error::Error>> {
        // check if file exists
        if !path.as_ref().exists() {
            // create default config
            return Ok(Self::create_default_config());
        }

        // Open file
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);

        // Read entire file
        let mut contents = String::new();
        reader.read_to_string(&mut contents)?;

        // Parse JSON
        let config: FilterConfiguration = serde_json::from_str(&contents)?;
        Ok(config)
    }

    /// Create a default configuration
    fn create_default_config() -> FilterConfiguration {
        FilterConfiguration {
            profiles: vec![Self::create_default_profile()],
            custom_domains: vec![
                DomainCategory { domain: "facebook.com".to_string(), category: Category::SocialMedia },
                DomainCategory { domain: "twitter.com".to_string(), category: Category::SocialMedia },
                DomainCategory { domain: "instagram.com".to_string(), category: Category::SocialMedia },
                DomainCategory { domain: "tiktok.com".to_string(), category: Category::SocialMedia },
                DomainCategory { domain: "pornhub.com".to_string(), category: Category::Adult },
                DomainCategory { domain: "xvideos.com".to_string(), category: Category::Adult },
            ],
            custom_patterns: vec![
                PatternCategory { pattern: "*porn*".to_string(), category: Category::Adult },
                PatternCategory { pattern: "*adult*".to_string(), category: Category::Adult },
                PatternCategory { pattern: "*bet*".to_string(), category: Category::Gambling },
                PatternCategory { pattern: "*casino*".to_string(), category: Category::Gambling },
                PatternCategory { pattern: "*.malware.*".to_string(), category: Category::Malware },
                PatternCategory { pattern: "*phish*".to_string(), category: Category::Phishing },
            ],
            user_preferences: UserPreferences::default(),
        }
    }
    
    /// Create a default profile
    fn create_default_profile() -> FilterProfile {
        // Create default family profile
        let mut blocked_categories = HashSet::new();
        blocked_categories.insert(Category::Adult);
        blocked_categories.insert(Category::Gambling);
        blocked_categories.insert(Category::Malware);
        blocked_categories.insert(Category::Phishing);
        
        // School hours restriction for social media
        let school_restriction = TimeRestriction {
            days: vec![1, 2, 3, 4, 5], // Monday to Friday
            start_time: 8 * 3600, // 8:00 AM
            end_time: 15 * 3600, // 3:00 PM
        };
        
        let social_rule = Rule {
            id: 1,
            description: "Block social media during school hours".to_string(),
            enabled: true,
            priority: 10,
            action: RuleAction::Block,
            categories: {
                let mut set = HashSet::new();
                set.insert(Category::SocialMedia);
                set
            },
            exact_domains: HashSet::new(),
            domain_patterns: Vec::new(),
            time_restrictions: vec![school_restriction],
        };
        
        FilterProfile {
            name: "Family".to_string(),
            description: "Default family profile with parental controls".to_string(),
            is_active: true,
            blocked_categories,
            rules: vec![social_rule],
        }
    }
    
    /// Add a domain with its category
    pub fn add_domain(&mut self, domain: &str, category: Category) {
        self.domain_categories.insert(domain.to_lowercase(), category);
    }
    
    /// Add a domain pattern with its category
    pub fn add_pattern(&mut self, pattern: &str, category: Category) {
        self.pattern_categories.push((pattern.to_lowercase(), category));
    }
    
    /// Set the active profile by name
    pub fn set_active_profile(&mut self, profile_name: &str) -> Result<(), String> {
        for profile in &self.profiles {
            if profile.name == profile_name {
                // Set this profile as active
                let mut profile = profile.clone();
                profile.is_active = true;
                
                // Update active profile
                self.active_profile = profile;
                
                // Update other profiles' active status
                for p in &mut self.profiles {
                    p.is_active = p.name == profile_name;
                }
                
                // Save changes if path exists
                if let Some(ref path) = self.config_file_path {
                    self.save_config(path).map_err(|e| e.to_string())?;
                }
                
                return Ok(());
            }
        }
        
        Err(format!("Profile not found: {}", profile_name))
    }
    
    /// Check if a domain should be filtered
    pub fn check_domain(&self, domain: &str) -> FilterResult {
        let domain = domain.to_lowercase();
        
        // 1. Check if any rule explicitly mentions this domain
        if let Some(result) = self.check_domain_against_rules(&domain) {
            // Log if enabled
            if self.preferences.enable_logging {
                println!("FILTER: {} - {} (Rule #{})", 
                    domain, 
                    if result.is_allowed { "ALLOWED" } else { "BLOCKED" },
                    result.rule_id.unwrap_or(0));
            }
            return result;
        }
        
        // 2. Check if domain is in our predefined category list
        let category = self.get_domain_category(&domain);
        
        // 3. If we have a category and it's in the blocked categories list
        if let Some(cat) = &category {
            if self.active_profile.blocked_categories.contains(cat) {
                let result = FilterResult {
                    is_allowed: false,
                    reason: format!("Domain blocked: {} is categorized as {}", domain, cat.as_str()),
                    category: Some(cat.clone()),
                    rule_id: None,
                };
                
                // Log if enabled
                if self.preferences.enable_logging {
                    println!("FILTER: {} - BLOCKED (Category: {})", domain, cat.as_str());
                }
                
                return result;
            }
        }
        
        // 4. Default allow if no blocks found
        let result = FilterResult {
            is_allowed: true,
            reason: "Domain allowed: no matching blocks".to_string(),
            category,
            rule_id: None,
        };
        
        // Log if enabled
        if self.preferences.enable_logging {
            println!("FILTER: {} - ALLOWED (Default)", domain);
        }
        
        result
    }
    
    /// Check if the domain matches any custom rules
    fn check_domain_against_rules(&self, domain: &str) -> Option<FilterResult> {
        // Current time for time-based restrictions
        let now = Local::now();
        let day_of_week = now.weekday().num_days_from_sunday() as u8;
        let seconds_since_midnight = 
            (now.hour() as u32 * 3600) + (now.minute() as u32 * 60) + now.second();
        
        // Get category first for category-based rules
        let domain_category = self.get_domain_category(domain);
        
        // Sort rules by priority for consistent application
        let mut sorted_rules = self.active_profile.rules.clone();
        sorted_rules.sort_by_key(|r| r.priority);
        
        // Check each rule in priority order
        for rule in sorted_rules {
            // Skip disabled rules
            if !rule.enabled {
                continue;
            }
            
            // Check time restrictions
            if !rule.time_restrictions.is_empty() {
                let mut time_allowed = false;
                
                for restriction in &rule.time_restrictions {
                    // Check day
                    if !restriction.days.contains(&day_of_week) {
                        continue;
                    }
                    
                    // Check time
                    if seconds_since_midnight >= restriction.start_time && 
                       seconds_since_midnight <= restriction.end_time {
                        time_allowed = true;
                        break;
                    }
                }
                
                if !time_allowed {
                    continue; // Skip this rule if time restrictions not met
                }
            }
            
            // Check exact domain match
            if rule.exact_domains.contains(domain) {
                return Some(FilterResult {
                    is_allowed: rule.action == RuleAction::Allow,
                    reason: rule.description.clone(),
                    category: domain_category.clone(),
                    rule_id: Some(rule.id),
                });
            }
            
            // Check domain patterns
            for pattern in &rule.domain_patterns {
                if Self::domain_matches_pattern(domain, pattern) {
                    return Some(FilterResult {
                        is_allowed: rule.action == RuleAction::Allow,
                        reason: rule.description.clone(),
                        category: domain_category.clone(),
                        rule_id: Some(rule.id),
                    });
                }
            }
            
            // Check category match
            if let Some(ref category) = domain_category {
                if rule.categories.contains(category) {
                    return Some(FilterResult {
                        is_allowed: rule.action == RuleAction::Allow,
                        reason: rule.description.clone(),
                        category: Some(category.clone()),
                        rule_id: Some(rule.id),
                    });
                }
            }
        }
        
        None // No matching rule
    }
    
    /// Get the category for a domain
    fn get_domain_category(&self, domain: &str) -> Option<Category> {
        // First check exact domain matches for best performance
        if let Some(category) = self.domain_categories.get(domain) {
            return Some(category.clone());
        }
        
        // Check cache for pattern matches
        {
            let cache = self.category_cache.read().unwrap();
            if let Some(cached) = cache.get(domain) {
                if cached.expiry > SystemTime::now() {
                    return Some(cached.category.clone());
                }
            }
        }
        
        // Check against patterns (slower operation)
        for (pattern, category) in &self.pattern_categories {
            if Self::domain_matches_pattern(domain, pattern) {
                // Add to cache
                {
                    let mut cache = self.category_cache.write().unwrap();
                    cache.insert(
                        domain.to_string(),
                        CategorizeDomain {
                            category: category.clone(),
                            expiry: SystemTime::now() + self.cache_ttl,
                        },
                    );
                }
                return Some(category.clone());
            }
        }
        
        // No category found
        None
    }
    
    /// Check if a domain matches a pattern (with optimizations)
    fn domain_matches_pattern(domain: &str, pattern: &str) -> bool {
        // Fast path: exact match
        if pattern == domain {
            return true;
        }
        
        // Fast path: simple suffix match for *.example.com pattern
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..]; // Get ".example.com"
            if domain.ends_with(suffix) {
                let prefix_len = domain.len() - suffix.len();
                // Must have at least one character before the suffix
                return prefix_len > 0;
            }
            return false;
        }
        
        // Convert domain and pattern to lowercase for case-insensitive matching
        let domain_lower = domain;
        let pattern_lower = pattern;
        
        // Handle different wildcard positions
        if pattern_lower.starts_with("*.") {
            // *.example.com pattern - match any subdomain
            let suffix = &pattern_lower[2..]; // Remove the "*."
            domain_lower.ends_with(suffix) && domain_lower.len() > suffix.len() &&
                domain_lower.chars().nth(domain_lower.len() - suffix.len() - 1) == Some('.')
        } else if pattern_lower.ends_with(".*") {
            // domain.* pattern - match any TLD
            let prefix = &pattern_lower[..pattern_lower.len() - 2]; // Remove the ".*"
            domain_lower.starts_with(prefix) && domain_lower.len() > prefix.len() &&
                domain_lower.chars().nth(prefix.len()) == Some('.')
        } else if pattern_lower.starts_with('*') && pattern_lower.ends_with('*') && pattern_lower.len() > 2 {
            // *contains* pattern - match if domain contains the middle part
            let middle = &pattern_lower[1..pattern_lower.len() - 1];
            domain_lower.contains(middle)
        } else if pattern_lower.starts_with('*') {
            // *suffix pattern - match if domain ends with the suffix
            let suffix = &pattern_lower[1..];
            domain_lower.ends_with(suffix)
        } else if pattern_lower.ends_with('*') {
            // prefix* pattern - match if domain starts with the prefix
            let prefix = &pattern_lower[..pattern_lower.len() - 1];
            domain_lower.starts_with(prefix)
        } else {
            // Exact match (no wildcards)
            domain_lower == pattern_lower
        }
    }
    
    /// Bulk check multiple domains (optimized for performance)
    pub fn bulk_check_domains(&self, domains: &[String]) -> HashMap<String, FilterResult> {
        let mut results = HashMap::with_capacity(domains.len());
        
        for domain in domains {
            results.insert(domain.clone(), self.check_domain(domain));
        }
        
        results
    }
    
    /// Clean up expired cache entries
    pub fn cleanup_cache(&self) {
        let mut cache = self.category_cache.write().unwrap();
        let now = SystemTime::now();
        
        cache.retain(|_, entry| entry.expiry > now);
    }
    
    /// Save the current configuration to file
    pub fn save_config<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let config = self.build_current_config();
        
        // Serialize to JSON
        let json = serde_json::to_string_pretty(&config)?;
        
        // Write to file
        std::fs::write(path, json)?;
        
        Ok(())
    }
    
    /// Build current configuration
    fn build_current_config(&self) -> FilterConfiguration {
        // Convert domain categories
        let custom_domains: Vec<DomainCategory> = self.domain_categories
            .iter()
            .map(|(domain, category)| DomainCategory {
                domain: domain.clone(),
                category: category.clone(),
            })
            .collect();
        
        // Convert pattern categories
        let custom_patterns: Vec<PatternCategory> = self.pattern_categories
            .iter()
            .map(|(pattern, category)| PatternCategory {
                pattern: pattern.clone(),
                category: category.clone(),
            })
            .collect();
        
        FilterConfiguration {
            profiles: self.profiles.clone(),
            custom_domains,
            custom_patterns,
            user_preferences: self.preferences.clone(),
        }
    }
    
    /// Add a new profile
    pub fn add_profile(&mut self, profile: FilterProfile) -> Result<(), String> {
        // Check for duplicate name
        if self.profiles.iter().any(|p| p.name == profile.name) {
            return Err(format!("Profile with name '{}' already exists", profile.name));
        }
        
        // Add to profiles
        self.profiles.push(profile);
        
        // Save if path exists
        if let Some(ref path) = self.config_file_path {
            self.save_config(path).map_err(|e| e.to_string())?;
        }
        
        Ok(())
    }
    
    /// Update a profile
    pub fn update_profile(&mut self, profile: FilterProfile) -> Result<(), String> {
        // Find profile index
        let index = self.profiles.iter().position(|p| p.name == profile.name)
            .ok_or_else(|| format!("Profile not found: {}", profile.name))?;
        
        // Update profile
        self.profiles[index] = profile.clone();
        
        // If this is active profile, update it too
        if profile.is_active {
            self.active_profile = profile;
        }
        
        // Save if path exists
        if let Some(ref path) = self.config_file_path {
            self.save_config(path).map_err(|e| e.to_string())?;
        }
        
        Ok(())
    }
    
    /// Delete a profile
    pub fn delete_profile(&mut self, profile_name: &str) -> Result<(), String> {
        // Cannot delete active profile
        if self.active_profile.name == profile_name {
            return Err("Cannot delete active profile".to_string());
        }
        
        // Find profile index
        let index = self.profiles.iter().position(|p| p.name == profile_name)
            .ok_or_else(|| format!("Profile not found: {}", profile_name))?;
        
        // Remove profile
        self.profiles.remove(index);
        
        // Save if path exists
        if let Some(ref path) = self.config_file_path {
            self.save_config(path).map_err(|e| e.to_string())?;
        }
        
        Ok(())
    }
    
    /// Update user preferences
    pub fn update_preferences(&mut self, preferences: UserPreferences) -> Result<(), String> {
        // Update preferences
        self.preferences = preferences;
        self.cache_ttl = Duration::from_secs(self.preferences.cache_ttl);
        
        // Handle auto-refresh changes
        if self.preferences.auto_refresh_interval > 0 {
            self.start_auto_refresh();
        }
        
        // Save if path exists
        if let Some(ref path) = self.config_file_path {
            self.save_config(path).map_err(|e| e.to_string())?;
        }
        
        Ok(())
    }
    
    /// Add a new custom domain category
    pub fn add_custom_domain(&mut self, domain: &str, category: Category) -> Result<(), String> {
        // Add domain
        self.add_domain(domain, category.clone());
        
        // Save if path exists
        if let Some(ref path) = self.config_file_path {
            self.save_config(path).map_err(|e| e.to_string())?;
        }
        
        Ok(())
    }
    
    /// Add a new custom pattern category
    pub fn add_custom_pattern(&mut self, pattern: &str, category: Category) -> Result<(), String> {
        // Add pattern
        self.add_pattern(pattern, category.clone());
        
        // Save if path exists
        if let Some(ref path) = self.config_file_path {
            self.save_config(path).map_err(|e| e.to_string())?;
        }
        
        Ok(())
    }
    
    /// Get all available profiles
    pub fn get_profiles(&self) -> Vec<FilterProfile> {
        self.profiles.clone()
    }
    
    /// Get active profile
    pub fn get_active_profile(&self) -> FilterProfile {
        self.active_profile.clone()
    }
    
    /// Add a rule to active profile
    pub fn add_rule(&mut self, rule: Rule) -> Result<(), String> {
        // Check for duplicate ID
        if self.active_profile.rules.iter().any(|r| r.id == rule.id) {
            return Err(format!("Rule with ID {} already exists", rule.id));
        }
        
        // Add rule to active profile
        self.active_profile.rules.push(rule.clone());
        
        // Update profiles list
        for profile in &mut self.profiles {
            if profile.name == self.active_profile.name {
                profile.rules.push(rule);
                break;
            }
        }
        
        // Save if path exists
        if let Some(ref path) = self.config_file_path {
            self.save_config(path).map_err(|e| e.to_string())?;
        }
        
        Ok(())
    }
    
    /// Start auto-refresh thread
    fn start_auto_refresh(&self) {
        if self.preferences.auto_refresh_interval == 0 {
            return;
        }
        
        // Clone what we need for the thread
        let interval = self.preferences.auto_refresh_interval;
        let config_path = self.config_file_path.clone();
        let cache = Arc::clone(&self.category_cache);
        
        // Start background thread
        thread::spawn(move || {
            loop {
                // Sleep for the interval
                thread::sleep(Duration::from_secs(interval));
                
                // Clean up cache
                let mut cache_guard = cache.write().unwrap();
                let now = SystemTime::now();
                cache_guard.retain(|_, entry| entry.expiry > now);
                drop(cache_guard);
                
                // Reload config if path exists
                if let Some(ref path) = config_path {
                    match EnhancedFilterEngine::load_config(path) {
                        Ok(_) => {
                            println!("Auto-refreshed configuration from {}", path);
                        },
                        Err(e) => {
                            eprintln!("Error auto-refreshing configuration: {}", e);
                        }
                    }
                }
            }
        });
    }

    /// Reaload config from file
    pub fn reload_config(&mut self) -> Result<(), String> {
        if let Some(ref path) = self.config_file_path.clone() {
            // Load config
            let config = Self::load_config(path).map_err(|e| e.to_string())?;
            
            // Find active profile
            let active_profile = config.profiles.iter()
                .find(|p| p.is_active)
                .or_else(|| config.profiles.first())
                .cloned()
                .unwrap_or_else(|| Self::create_default_profile());
            
            // Clear existing domains and patterns
            self.domain_categories.clear();
            self.pattern_categories.clear();
            
            // Update fields
            self.profiles = config.profiles.clone();
            self.active_profile = active_profile;
            self.preferences = config.user_preferences;
            self.cache_ttl = Duration::from_secs(config.user_preferences.cache_ttl);
            
            // Load domain categories
            for domain_cat in &config.custom_domains {
                self.add_domain(&domain_cat.domain, domain_cat.category.clone());
            }
            
            // Load pattern categories
            for pattern_cat in &config.custom_patterns {
                self.add_pattern(&pattern_cat.pattern, pattern_cat.category.clone());
            }
            
            // Update last reload time
            self.last_modified = Instant::now();
            
            Ok(())
        } else {
            Err("No configuration file path specified".to_string())
        }
    }
    
    /// Get statistics about the filter engine
    pub fn get_stats(&self) -> HashMap<String, String> {
        let mut stats = HashMap::new();
        
        stats.insert("domain_categories_count".to_string(), self.domain_categories.len().to_string());
        stats.insert("pattern_categories_count".to_string(), self.pattern_categories.len().to_string());
        stats.insert("profiles_count".to_string(), self.profiles.len().to_string());
        stats.insert("active_profile".to_string(), self.active_profile.name.clone());
        stats.insert("rules_count".to_string(), self.active_profile.rules.len().to_string());
        
        // Get cache stats
        let cache = self.category_cache.read().unwrap();
        stats.insert("cache_entries".to_string(), cache.len().to_string());
        stats.insert("cache_ttl_seconds".to_string(), self.cache_ttl.as_secs().to_string());
        
        // Last reload time
        let elapsed = self.last_modified.elapsed().as_secs();
        stats.insert("last_reload_seconds_ago".to_string(), elapsed.to_string());
        
        stats
    }
    
    /// Clear the domain category cache
    pub fn clear_cache(&self) -> usize {
        let mut cache = self.category_cache.write().unwrap();
        let count = cache.len();
        cache.clear();
        count
    }
}

/// Simple filter engine implementation

pub struct SimpleFilterEngine {
    filter_config: Arc<RwLock<Option<FilterConfiguration>>>,
    refresh_interval: u64,
}

impl SimpleFilterEngine {
    pub fn new(filter_config: Option<FilterConfiguration>, refresh_interval: u64) -> Self {
        Self {
            filter_config: Arc::new(RwLock::new(filter_config)),
            refresh_interval,
        }
    }
    
    pub fn from_json_file(path: &str, _refresh_interval: u64) -> Option<FilterConfiguration> {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                match serde_json::from_str::<FilterConfiguration>(&content) {
                    Ok(config) => Some(config),
                    Err(e) => {
                        eprintln!("Error parsing filter config JSON: {}", e);
                        None
                    }
                }
            },
            Err(e) => {
                eprintln!("Error reading filter config file: {}", e);
                None
            }
        }
    }
    
    pub fn check_domain(&self, domain: &str) -> FilterResult {
        // Get a read lock on the configuration
        if let Ok(config_guard) = self.filter_config.read() {
            if let Some(ref config) = *config_guard {
                // Find active profile
                let active_profile = config.profiles.iter()
                    .find(|p| p.is_active)
                    .or_else(|| config.profiles.first());
                
                if let Some(profile) = active_profile {
                    // Check if domain is in any blocked category
                    for domain_cat in &config.custom_domains {
                        if domain_cat.domain.eq_ignore_ascii_case(domain) {
                            if profile.blocked_categories.contains(&domain_cat.category) {
                                return FilterResult {
                                    is_allowed: false,
                                    reason: format!("Domain '{}' is in blocked category '{}'", 
                                                  domain, domain_cat.category.as_str()),
                                    category: Some(domain_cat.category.clone()),
                                    rule_id: None,
                                };
                            }
                        }
                    }
                    
                    // Check patterns
                    for pattern_cat in &config.custom_patterns {
                        if Self::domain_matches_pattern(domain, &pattern_cat.pattern) {
                            if profile.blocked_categories.contains(&pattern_cat.category) {
                                return FilterResult {
                                    is_allowed: false,
                                    reason: format!("Domain '{}' matches pattern '{}' in blocked category '{}'", 
                                                  domain, pattern_cat.pattern, pattern_cat.category.as_str()),
                                    category: Some(pattern_cat.category.clone()),
                                    rule_id: None,
                                };
                            }
                        }
                    }
                    
                    // Check rules
                    for rule in &profile.rules {
                        if !rule.enabled {
                            continue;
                        }
                        
                        // Check exact domains
                        if rule.exact_domains.contains(domain) {
                            return FilterResult {
                                is_allowed: rule.action == RuleAction::Allow,
                                reason: rule.description.clone(),
                                category: None,
                                rule_id: Some(rule.id),
                            };
                        }
                        
                        // Check patterns
                        for pattern in &rule.domain_patterns {
                            if Self::domain_matches_pattern(domain, pattern) {
                                return FilterResult {
                                    is_allowed: rule.action == RuleAction::Allow,
                                    reason: rule.description.clone(),
                                    category: None,
                                    rule_id: Some(rule.id),
                                };
                            }
                        }
                    }
                }
            }
        }
        
        // Default: allow
        FilterResult {
            is_allowed: true,
            reason: "No matching filter rules".to_string(),
            category: None,
            rule_id: None,
        }
    }
    
    fn domain_matches_pattern(domain: &str, pattern: &str) -> bool {
        let domain = domain.to_lowercase();
        let pattern = pattern.to_lowercase();
        
        if pattern.starts_with('*') && pattern.ends_with('*') {
            let substring = &pattern[1..pattern.len()-1];
            domain.contains(substring)
        } else if pattern.starts_with('*') {
            let suffix = &pattern[1..];
            domain.ends_with(suffix)
        } else if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len()-1];
            domain.starts_with(prefix)
        } else if pattern.starts_with("*.") {
            let suffix = &pattern[1..];
            domain.ends_with(suffix) && domain.split('.').count() > pattern.split('.').count() - 1
        } else {
            domain == pattern
        }
    }
}