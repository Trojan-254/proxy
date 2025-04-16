/// This is the main client identification module,
/// Written by Samwuel Simiyu on the !4th of April 2025 instead of reading for bachelor of educations arts(English Literature )exams 
/// which start tommorow
/// This module is responsible for identifying clients based on their IP addresses
/// and storing the information in a Redis database.
/// It uses a Redis connection pool for efficient access to the database.
mod db;
mod models;
mod redis_cache;

use crate::{error, info, warn, debug};
use crate::client_id::db::DbPool;
use crate::client_id::models::{ClientIdentifier, UserAccount, UserTier};
use crate::client_id::redis_cache::RedisPool;


use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use hickory_proto::op::Message;




const CACHE_EXPIRY_SECONDS: u64 = 3600; // 1 hour
const LOOKUP_TIMEOUT_MS: u64 = 50; // 50 milliseconds


/// Client identification error types
#[derive(Debug, thiserror::Error)]
pub enum ClientIdError {
    #[error("Redis error: {0}")]
    RedisError (#[from] redis::RedisError),

    #[error("Database error: {0}")]
    DbError(#[from] sqlx::Error),

    #[error("Client identificattion timeout")]
    Timeout,

    #[error("Client not found")]
    NotFound,

    #[error("Invalid client data")]
    InvalidData,
}

// Result type for client identification operations
pub type Result<T> = std::result::Result<T, ClientIdError>;

// Main client identification service
pub struct ClientIdentificationService {
    redis: RedisPool,
    db: DbPool,
    // in memory cache for ultra fast lookups of frequent clients
    local_cache: Arc<RwLock<lru::LruCache<IpAddr, ClientIdentifier>>>,
}

impl ClientIdentificationService {
    pub async fn new(
        redis_url: &str,
        database_url: &str,
    ) -> Result<Self> {
        let redis = RedisPool::new(redis_url).await?;
        let db = DbPool::new(database_url).await?;

        // Initialize in memory cache(Size based on expected concurrent clients)
        let local_cache = Arc::new(RwLock::new(
            lru::LruCache::new(std::num::NonZeroUsize::new(10_000).unwrap())
        ));

        Ok(Self {
            redis,
            db,
            local_cache,
        })
    }

    /// Identify client from DNS query and return their account information
    pub async fn identify_client(&self, dns_query: &Message, client_ip: IpAddr) -> Result<UserAccount> {
        let start = Instant::now();
        
        // Try to get client from local cache first (fastest path)
        if let Some(identifier) = self.local_cache.write().await.get(&client_ip) {
            debug!("Client found in local cache: {}", client_ip);
            
            // Verify the cached identifier in Redis
            match self.redis.get_user_account(&identifier.client_id).await {
                Ok(account) => {
                    let elapsed = start.elapsed().as_millis();
                    if elapsed > LOOKUP_TIMEOUT_MS as u128 {
                        warn!("Client identification slow ({}ms): {}", elapsed, client_ip);
                    }
                    return Ok(account);
                }
                Err(_) => {
                    // Cache miss or error, will fall through to Redis lookup
                    debug!("Client in local cache but not in Redis: {}", client_ip);
                }
            }
        }
        
        // Extract additional identifying information from the DNS query if available
        // This could include EDNS0 client subnet, query patterns, etc.
        let additional_identifiers = self.extract_additional_identifiers(dns_query);
        
        // Try to identify the client via Redis
        match self.redis.get_client_by_ip(client_ip).await {
            Ok(client_id) => {
                // Client found in Redis, get their account information
                match self.redis.get_user_account(&client_id).await {
                    Ok(account) => {
                        // Update local cache
                        self.local_cache.write().await.put(
                            client_ip,
                            ClientIdentifier {
                                client_id: client_id.clone(),
                                ip_addr: client_ip,
                                additional: additional_identifiers.clone(),
                            },
                        );
                        
                        let elapsed = start.elapsed().as_millis();
                        if elapsed > LOOKUP_TIMEOUT_MS as u128 {
                            warn!("Client identification slow ({}ms): {}", elapsed, client_ip);
                        }
                        
                        // Asynchronously update last seen timestamp
                        let redis_clone = self.redis.clone();
                        let client_id_clone = client_id.clone();
                        tokio::spawn(async move {
                            if let Err(e) = redis_clone.update_client_last_seen(&client_id_clone).await {
                                error!("Failed to update last seen timestamp: {}", e);
                            }
                        });
                        
                        return Ok(account);
                    }
                    Err(ClientIdError::NotFound) => {
                        // Client ID exists but account data missing - try database
                        debug!("Client ID found in Redis but account missing, checking database");
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(ClientIdError::NotFound) => {
                // Client not found in Redis - try database lookup
                debug!("Client not found in Redis, checking database: {}", client_ip);
            }
            Err(e) => return Err(e),
        }
        
        // Check if we're approaching timeout
        if start.elapsed().as_millis() > (LOOKUP_TIMEOUT_MS as u128 * 3/4) {
            // Emergency fallback - treat as unauthenticated/free tier
            warn!("Client identification approaching timeout, using fallback: {}", client_ip);
            return self.create_fallback_account(client_ip).await;
        }
        
        // If we get here, we need to check the database
        match self.db.get_client_by_ip(client_ip).await {
            Ok((client_id, account)) => {
                // Found in database, cache in Redis for future lookups
                self.cache_client_data(client_ip, &client_id, &account, additional_identifiers).await?;
                
                let elapsed = start.elapsed().as_millis();
                if elapsed > LOOKUP_TIMEOUT_MS as u128 {
                    warn!("Client identification slow ({}ms): {}", elapsed, client_ip);
                }
                
                return Ok(account);
            }
            Err(ClientIdError::NotFound) => {
                // Not found in database either - create anonymous/free account
                info!("New client detected: {}", client_ip);
                return self.create_anonymous_account(client_ip).await;
            }
            Err(e) => return Err(e),
        }
    }

    /// Extract additional identifying information from DNS query
    fn extract_additional_identifiers(&self, _dns_query: &Message) -> Vec<String> {
        let identifiers = Vec::new();

        // Extract EDNS client subnet if present
        // This would typically be in the OPT record in the additional section
        // For now placeholder, to be expanded...

        identifiers
    }

    /// Cache client in redis for fast lookups
    async fn cache_client_data(
        &self,
        client_ip: IpAddr,
        client_id: &str,
        account: &UserAccount,
        additional_identifiers: Vec<String>
    ) -> Result<()> {
        // Cache the client identifiers
        self.redis.set_client_ip_mapping(client_ip, client_id).await?;

        // Cache the account data
        self.redis.set_user_account(client_id, account).await?;

        // Update the local cache
        self.local_cache.write().await.put(
            client_ip,
            ClientIdentifier {
                client_id: client_id.to_string(),
                ip_addr: client_ip,
                additional: additional_identifiers,
            },
        );

        Ok(())
    }

    /// Create an anonymous user for new clients
    async fn create_anonymous_account(&self, client_ip: IpAddr) -> Result<UserAccount> {
        // Generate a unique client id for this ip
        let client_id = format!("anon_{}", uuid::Uuid::new_v4());

        // Create a new anoymous account(free-tier)
        let account = UserAccount {
            client_id: client_id.clone(),
            tier: UserTier::Free,
            name: "Anonymous User".to_string(),
            email: None,
            max_devices: 3,
            active_devices: 1, 
            quota_daily: 5000,
            quota_used: 0,
            custom_rules_enabled: false,
        };

        // store in redis
        self.redis.set_client_ip_mapping(client_ip, &client_id).await?;
        self.redis.set_user_account(&client_id, &account).await?;

        // Store in database asynchronously (don't block dns resolution)
        let db_clone = self.db.clone();
        let account_clone = account.clone();
        tokio::spawn(async move {
            if let Err(e) = db_clone.create_anonymous_account(client_ip, &account_clone).await {
                error!("Failed to store anonymous account in database: {}", e);
            }
        });

        // update local cache
        self.local_cache.write().await.put(
            client_ip,
            ClientIdentifier {
                client_id: client_id.clone(),
                ip_addr: client_ip,
                additional: Vec::new(),
            },
        );

        Ok(account)
    } 

    /// Create fallback account when identification times out
    async fn create_fallback_account(&self, client_ip: IpAddr) -> Result<UserAccount> {
        // Similar to anonymous account but with restricted access
        // This ensures we don't block DNS resolution even under high load or database issues
        Ok(UserAccount {
            client_id: format!("fallback_{}", client_ip),
            tier: UserTier::Free,
            name: "Temporary User".to_string(),
            email: None,
            max_devices: 1,
            active_devices: 1,
            quota_daily: 1000, // Restricted quota
            quota_used: 0,
            custom_rules_enabled: false,
        })
    }

    /// Register a new device for an existing account
    pub async fn register_device(
        &self,
        client_id: &str,
        device_id: &str,
        device_info: &models::DeviceInfo
    ) -> Result<()> {
        // store device in redis
        self.redis.set_device_info(client_id, device_id, device_info).await?;

        // store in database asynchronously
        let db_clone = self.db.clone();
        let client_id = client_id.to_string();
        let device_id = device_id.to_string();
        let device_info = device_info.clone();
        tokio::spawn(async move {
            if let Err(e) = db_clone.register_device(&client_id, &device_id, &device_info).await {
                error!("Failed to register device in database: {}", e);
            }
        });

        Ok(())
    }

    /// Update the last active timestamp for a device
    pub async fn update_device_activity(&self, client_id: &str, device_id: &str) -> Result<()> {
        // Update in Redis (low priority, don't block main operations)
        let redis_clone = self.redis.clone();
        let client_id = client_id.to_string();
        let device_id = device_id.to_string();
        tokio::spawn(async move {
            if let Err(e) = redis_clone.update_device_last_active(&client_id, &device_id).await {
                error!("Failed to update device activity: {}", e);
            }
        });
        
        Ok(())
    }
}