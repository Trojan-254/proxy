use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};
use std::sync::RwLock;
use chrono::Datelike;
use chrono::Timelike;

/// Predefined categories for domain filtering
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Category {
    Adult,
    Gambling,
    SocialMedia,
    Gaming,
    Malware,
    Phishing,
    Advertising,
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
#[derive(Debug, Clone)]
pub struct TimeRestriction {
    /// Days the restriction applies (0 = Sunday, 6 = Saturday)
    pub days: Vec<u8>,
    
    /// Start time in seconds since midnight
    pub start_time: u32,
    
    /// End time in seconds since midnight
    pub end_time: u32,
}

/// Filter rule action
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Block,
}

/// Filter rule definition
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct FilterProfile {
    /// Profile name
    pub name: String,
    
    /// Categories to block
    pub blocked_categories: HashSet<Category>,
    
    /// Custom rules for this profile
    pub rules: Vec<Rule>,
}

/// Result of a filtering check
#[derive(Debug, Clone)]
pub struct FilterResult {
    /// Whether the domain is allowed
    pub is_allowed: bool,
    
    /// Reason for the decision
    pub reason: String,
    
    /// Category the domain belongs to (if any)
    pub category: Option<Category>,
    
    /// Rule ID that determined this outcome (if any)
    pub rule_id: Option<u32>,
}

/// Domain categorization cache entry
struct CategorizedDomain {
    category: Category,
    expiry: SystemTime,
}

/// Simple standalone filter engine
pub struct SimpleFilterEngine {
    /// Domain category mappings
    domain_categories: HashMap<String, Category>,
    
    /// Domain pattern categories
    pattern_categories: Vec<(String, Category)>,
    
    /// Active filter profile
    profile: FilterProfile,
    
    /// Cache of categorized domains for patterns
    category_cache: RwLock<HashMap<String, CategorizedDomain>>,
    
    /// Cache TTL in seconds
    cache_ttl: Duration,
}

impl SimpleFilterEngine {
    /// Create a new simple filter engine with predefined categories
    pub fn new(profile: FilterProfile, cache_ttl_seconds: u64) -> Self {
        // Initialize with empty mappings
        let mut engine = Self {
            domain_categories: HashMap::new(),
            pattern_categories: Vec::new(),
            profile,
            category_cache: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(cache_ttl_seconds),
        };
        
        // Add predefined domains and categories
        engine.add_predefined_domains();
        
        engine
    }
    
    /// Add predefined domains and categories
    fn add_predefined_domains(&mut self) {
        // Adult content sites
        self.add_domain("pornhub.com", Category::Adult);
        self.add_domain("xvideos.com", Category::Adult);
        self.add_domain("xnxx.com", Category::Adult);
        self.add_pattern("*porn*", Category::Adult);
        self.add_pattern("*adult*", Category::Adult);
        self.add_pattern("*xxx*", Category::Adult);
        
        // Gambling sites
        self.add_domain("bet365.com", Category::Gambling);
        self.add_domain("pokerstars.com", Category::Gambling);
        self.add_domain("draftkings.com", Category::Gambling);
        self.add_pattern("*bet*", Category::Gambling);
        self.add_pattern("*casino*", Category::Gambling);
        self.add_pattern("*poker*", Category::Gambling);
        
        // Social media
        self.add_domain("facebook.com", Category::SocialMedia);
        self.add_domain("instagram.com", Category::SocialMedia);
        self.add_domain("twitter.com", Category::SocialMedia);
        self.add_domain("tiktok.com", Category::SocialMedia);
        
        // Gaming
        self.add_domain("roblox.com", Category::Gaming);
        self.add_domain("minecraft.net", Category::Gaming);
        self.add_domain("epicgames.com", Category::Gaming);
        
        // Malware domains
        self.add_pattern("*.malware.*", Category::Malware);
        self.add_pattern("*phish*", Category::Phishing);
        
        // Advertising
        self.add_pattern("*ad.*", Category::Advertising);
        self.add_pattern("*ads.*", Category::Advertising);
        self.add_pattern("*adserver*", Category::Advertising);
        
        // Note: In a production system, you would likely load these from a file
        // or allow the user to provide their own categorized domain lists
    }
    
    /// Add a domain with its category
    pub fn add_domain(&mut self, domain: &str, category: Category) {
        self.domain_categories.insert(domain.to_lowercase(), category);
    }
    
    /// Add a domain pattern with its category
    pub fn add_pattern(&mut self, pattern: &str, category: Category) {
        self.pattern_categories.push((pattern.to_lowercase(), category));
    }
    
    /// Set the active filter profile
    pub fn set_profile(&mut self, profile: FilterProfile) {
        self.profile = profile;
    }
    
    /// Check if a domain should be filtered
    pub fn check_domain(&self, domain: &str) -> FilterResult {
        let domain = domain.to_lowercase();
        
        // 1. Check if any rule explicitly mentions this domain
        if let Some(result) = self.check_domain_against_rules(&domain) {
            return result;
        }
        
        // 2. Check if domain is in our predefined category list
        let category = self.get_domain_category(&domain);
        
        // 3. If we have a category and it's in the blocked categories list
        if let Some(cat) = &category {
            if self.profile.blocked_categories.contains(cat) {
                return FilterResult {
                    is_allowed: false,
                    reason: format!("Domain blocked: {} is categorized as {}", domain, cat.as_str()),
                    category: Some(cat.clone()),
                    rule_id: None,
                };
            }
        }
        
        // 4. Default allow if no blocks found
        FilterResult {
            is_allowed: true,
            reason: "Domain allowed: no matching blocks".to_string(),
            category,
            rule_id: None,
        }
    }
    
    /// Get the category for a domain
    fn get_domain_category(&self, domain: &str) -> Option<Category> {
        // First check exact domain matches
        if let Some(category) = self.domain_categories.get(domain) {
            return Some(category.clone());
        }
        
        // Check cache first
        {
            let cache = self.category_cache.read().unwrap();
            if let Some(cached) = cache.get(domain) {
                if cached.expiry > SystemTime::now() {
                    return Some(cached.category.clone());
                }
            }
        }
        
        // Check against patterns
        for (pattern, category) in &self.pattern_categories {
            if Self::domain_matches_pattern(domain, pattern) {
                // Add to cache
                {
                    let mut cache = self.category_cache.write().unwrap();
                    cache.insert(
                        domain.to_string(),
                        CategorizedDomain {
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
    
    /// Check if the domain matches any custom rules
    fn check_domain_against_rules(&self, domain: &str) -> Option<FilterResult> {
        // Current time for time-based restrictions
        let now = chrono::Local::now();
        let day_of_week = now.weekday().num_days_from_sunday() as u8;
        let seconds_since_midnight = 
            (now.hour() as u32 * 3600) + (now.minute() as u32 * 60) + now.second();
        
        // Get category first for category-based rules
        let domain_category = self.get_domain_category(domain);
        
        // Check each rule in priority order
        for rule in self.profile.rules.iter() {
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
    
    /// Check if a domain matches a pattern
    /// Same implementation as in your original code
    fn domain_matches_pattern(domain: &str, pattern: &str) -> bool {
        // Convert domain and pattern to lowercase for case-insensitive matching
        let domain_lower = domain.to_lowercase();
        let pattern_lower = pattern.to_lowercase();
        
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
    
    /// Create a default profile with common blocks for families
    pub fn create_family_profile() -> FilterProfile {
        let mut blocked_categories = HashSet::new();
        blocked_categories.insert(Category::Adult);
        blocked_categories.insert(Category::Gambling);
        blocked_categories.insert(Category::Malware);
        blocked_categories.insert(Category::Phishing);
        
        // Create some default rules
        let mut rules = Vec::new();
        
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
        
        rules.push(social_rule);
        
        FilterProfile {
            name: "Family".to_string(),
            blocked_categories,
            rules,
        }
    }
    
    /// Clean up expired cache entries
    pub fn cleanup_cache(&self) {
        let mut cache = self.category_cache.write().unwrap();
        let now = SystemTime::now();
        
        cache.retain(|_, entry| entry.expiry > now);
    }
    
    /// Bulk check multiple domains
    pub fn bulk_check_domains(&self, domains: &[String]) -> HashMap<String, FilterResult> {
        let mut results = HashMap::new();
        
        for domain in domains {
            results.insert(domain.clone(), self.check_domain(domain));
        }
        
        results
    }
}