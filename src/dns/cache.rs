use std::collections::HashMap;
use std::time::Instant;
use std::sync::Arc;
use thiserror::Error;
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;

use crate::utils::metrics_channel::{self, increment_counter};
use crate::{error, info, debug};


/// Error that may occur during caching operations
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("Entry expired")]
    EntryExpired,

    #[error("Entry not found")]
    EntryNotFound,

    #[error("Invalid cache key")]
    InvalidKey,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Memory limit exceeded")]
    MemoryLimitExceeded,

}

/// Result type for cache operations
type CacheResult<T> = Result<T, CacheError>;

/// Structure to hold a cached DNS Response with metadata
#[derive(Clone, Debug)]
struct CacheEntry {
    response: Message,
    created_at: Instant,
    ttl: u32,
    size_bytes: usize,
    access_count: u32,
}

impl CacheEntry {
    /// Create a new cache entry
    fn new(response: Message, ttl: u32) -> Self {
        // Approximate size calculations:
        // - fixed overhead for the struct
        // - Serialized size for the DNS message
        // This is approximate but good enough for cache management
        let size_bytes = match response.to_vec() {
            Ok(bytes) => bytes.len() + std::mem::size_of::<Self>(),
            Err(_) => 1024, // I choose a default assumption here if serialization will fail
        };

        Self {
            response,
            created_at: Instant::now(),
            ttl,
            size_bytes,
            access_count: 0,
        }
    }

    /// Check if an entry has expired
    fn is_expired(&self) -> bool {
        let age = Instant::now().duration_since(self.created_at).as_secs() as u32;
        age >= self.ttl
    }

    /// Record an access to the entry
    fn record_access(&mut self) {
        self.access_count += 1;
    }

    /// Get the effective TTL remaining (0 if it is expired)
    fn remaining_ttl(&self) -> u32{
        let age = Instant::now().duration_since(self.created_at).as_secs() as u32;
        if age >= self.ttl {
            0
        } else {
            self.ttl - age
        }
    }

    /// Update DNS Response TTls based on remaining cache TTl
    fn update_response_ttl(&self) -> Message {
        let mut updated_response = self.response.clone();
        let remaining = self.remaining_ttl();

        // Update TTL in all record sections
        for record in updated_response.answers_mut() {
            // Never set ttl higher than the original one
            let current_ttl = record.ttl();
            if current_ttl > remaining {
                record.set_ttl(remaining);
            }
        }

        for record in updated_response.name_servers_mut() {
            let current_ttl = record.ttl();
            if current_ttl > remaining {
                record.set_ttl(remaining);
            }
        }

        for record in updated_response.additionals_mut() {
            let current_ttl = record.ttl();
            if current_ttl > remaining {
                record.set_ttl(remaining);
            }
        }
        updated_response
    }
}

/// Cache Key for combining domain name and record type
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
struct CacheKey {
    domain: String,
    record_type: RecordType,
}

impl CacheKey {
    fn new(domain: &str, record_type: RecordType) -> Self {
        // Normalize doomain name by ensuring it's lowecase and has trailing dot .
        let normalized = if domain.ends_with('.') {
            domain.to_lowercase()
        } else {
            format!("{}.", domain.to_lowercase())
        };

        Self {
            domain: normalized,
            record_type,
        }
    }
}


/// Configuration for a DNS Cache
#[derive(Clone, Debug)]
pub struct DnsCacheConfig {
    /// Maximum number of entries to keep in cache
    pub max_entries: usize,
    
    /// Maximum memory usage in bytes (approximate)
    pub max_memory_bytes: usize,
    
    /// Minimum TTL to use (overrides smaller TTLs)
    pub min_ttl: u32,
    
    /// Maximum TTL to use (overrides larger TTLs)
    pub max_ttl: u32,
    
    /// How often to run cleanup in seconds
    pub cleanup_interval_secs: u64,
    
    /// Enable negative caching (NXDOMAIN, etc.)
    pub enable_negative_caching: bool,
    
    /// TTL for negative responses
    pub negative_ttl: u32,
    
    /// Whether to prefetch entries nearing expiration
    pub enable_prefetch: bool,
    
    /// Prefetch when TTL reaches this percentage of original
    pub prefetch_threshold_percent: u8,

}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 1000000,
            max_memory_bytes: 50 * 1024 * 1024, // 50 MB
            min_ttl: 60,      // 1 minute
            max_ttl: 86400,   // 24 hours
            cleanup_interval_secs: 3000, // 5 minutes
            enable_negative_caching: true,
            negative_ttl: 3000, // 5 minutes
            enable_prefetch: true,
            prefetch_threshold_percent: 100,
        }
    }
}


/// Dns response cache implementation
pub struct DnsCache {
    /// The actual cache storage - domain + type -> entry mapping
    entries: HashMap<CacheKey, CacheEntry>,

    /// Configuration for this cache entires
    config: DnsCacheConfig,

    /// approximate current memory usage
    memory_usage: usize,

    /// Number of cache hits since inception
    hit_count: u64,

    /// Number of cache misses since inception
    miss_count: u64,

    /// Number of entries eviction due to memory or count limits
    eviction_count: u64,

    /// Creatiion time of this cache instant
    created_at: Instant,

    /// Last cleanup time
    last_cleanup: Instant,

    /// Callback for prefetching entries( This will be set by the DnsProxy)
    prefetch_callback: Option<Arc<dyn Fn(String, RecordType) + Send + Sync>>,
}

impl DnsCache {
    /// creates a new DNS Cache with default configuration
    pub fn new() -> Self {
        Self::with_config(DnsCacheConfig::default())
    }

    /// Creates a new DNS Cache whith custom configuration
    pub fn with_config(config: DnsCacheConfig) -> Self {
        Self {
            entries: HashMap::with_capacity(config.max_entries / 2),
            config,
            memory_usage: 0,
            hit_count: 0,
            miss_count: 0,
            eviction_count: 0,
            created_at: Instant::now(),
            last_cleanup: Instant::now(),
            prefetch_callback: None,
        }
    }

    /// Set a callback function for prefetching cache entries
    pub fn set_prefetch_callback<F>(&mut self, callback: F)
    where 
        F: Fn(String, RecordType) + Send + Sync + 'static,
    {
        self.prefetch_callback = Some(Arc::new(callback))
    }

    /// Get an entry from cache
    pub fn get(&self, domain: &str, record_type: RecordType) -> Option<Message> {
        // get the time
        let request_timer = metrics_channel::start_timer("dns.cache.lookup.duration");

        let key = CacheKey::new(domain, record_type);

        match self.entries.get(&key) {
            Some(entry) if !entry.is_expired() => {
                // clone entry for modification
                let mut entry_clone = entry.clone();
                entry_clone.record_access();

                // Check if we could trigger a prefetch
                if self.config.enable_prefetch && self.prefetch_callback.is_some() {
                    let original_ttl = entry.ttl;
                    let remaining_ttl = entry.remaining_ttl();
                    let threshold = (original_ttl as f64 * (self.config.prefetch_threshold_percent as f64 / 100.0)) as u32;

                    if remaining_ttl <= threshold {
                        // The entry is close to expiration, trigger a prefetch
                        if let Some(ref callback) = self.prefetch_callback {
                            let domain_clone = domain.to_string();
                            let callback_clone = Arc::clone(callback);

                            // Spawn a new task to refresh this entry
                            tokio::spawn(async move {
                                callback_clone(domain_clone, record_type);
                            });

                            // logging
                            debug!("Triggered prefetch for {}, type {:?}", domain, record_type);
                            // println!("Triggered prefetch for {}, type {:?}", domain, record_type);
                        }
                    }
                }

                // Get response with updated ttls
                let response = entry_clone.update_response_ttl();
                drop(request_timer);

                // Update metrics
                // implementation goes here
                increment_counter("dns.cache.hits");

                Some(response)
            },
            Some(_) => {
                // Entry exists but expired
                increment_counter("dns.cache.expired");
                None
            },
            None => {
                // Entry doesn't exist
                increment_counter("dns.cache.misses");
                None
            }
        }
    }


    /// Insert a new entry into the cache
    pub fn insert(&mut self, domain: &str, record_type: RecordType, response: Message, ttl: u32) -> CacheResult<()> {
        // Skip caching for non cacheable responses
        if !Self::is_cacheable(&response) {
            return Ok(());
        }

        // Adjust the TTl based on config
        let adjusted_ttl = ttl.clamp(self.config.min_ttl, self.config.max_ttl);

        // create cache
        let key = CacheKey::new(domain, record_type);

        // Create cache entry
        let entry = CacheEntry::new(response, adjusted_ttl);

        // check if we need to make new(more) room for in the cache
        self.ensure_capacity(entry.size_bytes)?;

        // update memory usage
        self.memory_usage += entry.size_bytes;

        // Store the entry
        self.entries.insert(key, entry);
        info!("Cache inserterd for {} with type {:?}", domain, record_type);

        // update metrics
        increment_counter("dns.cache.insert");

        Ok(())
    }

     /// Remove an entry from the cache
     pub fn remove(&mut self, domain: &str, record_type: RecordType) -> CacheResult<()> {
        let key = CacheKey::new(domain, record_type);
        
        if let Some(entry) = self.entries.remove(&key) {
            // Update memory usage
            self.memory_usage = self.memory_usage.saturating_sub(entry.size_bytes);
            // Update eviction count
            self.eviction_count += 1;
            // Update metrics
            increment_counter("dns.cache.removed");
            Ok(())
        } else {
            Err(CacheError::EntryNotFound)
        }
    }
    
    /// Clear the entire cache
    pub fn clear(&mut self) {
        self.entries.clear();
        self.memory_usage = 0;
        // info!("DNS cache cleared");
        info!("DNS Cache cleared");
    }

    /// Get cache statistics
    pub fn stats(&self) -> HashMap<String, u64> {
        let mut stats = HashMap::new();
        
        stats.insert("entries".into(), self.entries.len() as u64);
        stats.insert("memory_bytes".into(), self.memory_usage as u64);
        stats.insert("hits".into(), self.hit_count);
        stats.insert("misses".into(), self.miss_count);
        stats.insert("evictions".into(), self.eviction_count);
        stats.insert("uptime_seconds".into(), self.created_at.elapsed().as_secs());
        
        // Calculate hit ratio
        let total_requests = self.hit_count + self.miss_count;
        let hit_ratio = if total_requests > 0 {
            (self.hit_count as f64 / total_requests as f64 * 100.0) as u64
        } else {
            0
        };
        stats.insert("hit.ratio.percentage".into(), hit_ratio);
        
        stats
    }

    /// Check if a response is cacheable
    fn is_cacheable(response: &Message) -> bool {
        use hickory_proto::op::ResponseCode;
        
        // Basic cacheability checks
        match response.response_code() {
            // Always cache positive responses
            ResponseCode::NoError => {
                // But only if they have answers (unless specifically allowing empty responses)
                !response.answers().is_empty()
            },
            
            // Cache negative responses if enabled
            ResponseCode::NXDomain => true,
            
            // Don't cache error responses
            _ => false,
        }
    }

    /// Make room in the cache if needed
    fn ensure_capacity(&mut self, required_size: usize) -> CacheResult<()> {
        // Check if adding this would exceed memory limit
        if self.memory_usage + required_size > self.config.max_memory_bytes {
            // Need to evict entries
            self.evict_entries(required_size)
        } else if self.entries.len() >= self.config.max_entries {
            // Need to evict just one entry to make room
            self.evict_entries(0)
        } else {
            // No eviction needed
            Ok(())
        }
    }

    /// Evict cache entries to make room
    fn evict_entries(&mut self, required_size: usize) -> CacheResult<()> {
        // First, remove expired entries
        self.remove_expired();
        
        // If that wasn't enough, evict based on LRU or another policy
        if self.memory_usage + required_size > self.config.max_memory_bytes || 
           self.entries.len() >= self.config.max_entries {
            
            // Collect entries with their keys for evaluation
            let mut entries: Vec<_> = self.entries
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            
            // Sort by access count (least accessed first) and then by age (oldest first)
            entries.sort_by(|a, b| {
                a.1.access_count.cmp(&b.1.access_count)
                    .then_with(|| b.1.created_at.cmp(&a.1.created_at))
            });
            
            // Determine how many entries to remove
            let _bytes_to_free = required_size;
            let mut freed_bytes = 0;
            let mut evicted = 0;
            
            for (key, entry) in entries {
                // Stop if we've freed enough space
                if (self.memory_usage - freed_bytes + required_size <= self.config.max_memory_bytes) &&
                   (self.entries.len() - evicted < self.config.max_entries) {
                    break;
                }
                
                // Remove this entry
                if self.entries.remove(&key).is_some() {
                    freed_bytes += entry.size_bytes;
                    evicted += 1;
                    self.eviction_count += 1;
                }
            }
            
            // Update memory usage
            self.memory_usage -= freed_bytes;
            
            // debug!("Evicted {} cache entries, freed {} bytes", evicted, freed_bytes);
            info!("Evicted {} cache entries, freed {} bytes", evicted, freed_bytes);
            //metrics
            increment_counter("dns.cache.evictions");
        }
        
        Ok(())
    }

    /// Remove all expired entries from the cache
    fn remove_expired(&mut self) {
        let mut removed = 0;
        let mut freed_bytes = 0;
        
        // Collect keys of expired entries
        let expired_keys: Vec<_> = self.entries
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();
        
        // Remove the expired entries
        for key in expired_keys {
            if let Some(entry) = self.entries.remove(&key) {
                freed_bytes += entry.size_bytes;
                removed += 1;
            }
        }
        
        // Update memory usage
        self.memory_usage -= freed_bytes;
        
        if removed > 0 {
            // debug!("Removed {} expired cache entries, freed {} bytes", removed, freed_bytes);
            info!("Removed {} expired cache entries, freed {} bytes", removed, freed_bytes);
        }
    }

    /// Clean up the cache (remove expired entries and enforce limits)
    pub fn cleanup(&mut self) {
        // Time the cleanup operation
        let start = Instant::now();
        
        // Remove expired entries
        self.remove_expired();
        
        // Enforce memory and size limits if needed
        if self.memory_usage > self.config.max_memory_bytes || 
           self.entries.len() > self.config.max_entries {
            if let Err(e) = self.evict_entries(0) {
                error!("Error during cache cleanup: {}", e);
            }
        }
        
        // Update last cleanup time
        self.last_cleanup = Instant::now();
        
        // debug!("Cache cleanup completed in {:?}", start.elapsed());
        info!("Cache cleanup completed in {:?}", start.elapsed());
    }
    
    /// Get the number of entries in the cache
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    
    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

