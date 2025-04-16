use crate::client_id::models::{DeviceInfo, UserAccount};
use crate::client_id::ClientIdError;
use crate::client_id::Result;
use redis::{aio::MultiplexedConnection, AsyncCommands, Client};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;


const DEFAULT_CACHE_EXPIRY: usize = 3600; // 1 hour

#[derive(Clone)]
pub struct RedisPool {
    client: Client,
    // Use Arc<Mutex<>> to allow sharing connection pool between threads safely
    pool: Arc<Mutex<Vec<MultiplexedConnection>>>,
}

impl RedisPool {
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client = redis::Client::open(redis_url)
            .map_err(ClientIdError::RedisError)?;
        
        // Pre-initialize some connections
        let mut connections = Vec::with_capacity(20);
        for _ in 0..20 {
            let conn = client.get_multiplexed_async_connection().await
                .map_err(ClientIdError::RedisError)?;
            connections.push(conn);
        }
        
        Ok(Self {
            client,
            pool: Arc::new(Mutex::new(connections)),
        })
    }
    
    // Helper method to get a connection from the pool
    async fn get_conn(&self) -> Result<MultiplexedConnection> {
        let mut pool = self.pool.lock().await;
        if let Some(conn) = pool.pop() {
            return Ok(conn);
        }
        
        // If no connections available, create a new one
        let conn = self.client.get_multiplexed_async_connection().await
            .map_err(ClientIdError::RedisError)?;
        Ok(conn)
    }
    
    // Helper method to return a connection to the pool
    async fn return_conn(&self, conn: MultiplexedConnection) {
        let mut pool = self.pool.lock().await;
        pool.push(conn);
    }
    
    pub async fn get_client_by_ip(&self, ip: IpAddr) -> Result<String> {
        let key = format!("ip:{}:client", ip);
        let mut conn = self.get_conn().await?;
        
        let result: Option<String> = conn.get(&key).await
            .map_err(ClientIdError::RedisError)?;
        
        self.return_conn(conn).await;
        
        result.ok_or(ClientIdError::NotFound)
    }
    
    pub async fn set_client_ip_mapping(&self, ip: IpAddr, client_id: &str) -> Result<()> {
        let key = format!("ip:{}:client", ip);
        let mut conn = self.get_conn().await?;
        
        // Store the mapping with expiration
        let _: () = conn.set_ex(&key, client_id, DEFAULT_CACHE_EXPIRY as u64).await
            .map_err(ClientIdError::RedisError)?;
        
        self.return_conn(conn).await;
        
        Ok(())
    }
    
    pub async fn get_user_account(&self, client_id: &str) -> Result<UserAccount> {
        let key = format!("client:{}:account", client_id);
        let mut conn = self.get_conn().await?;
        
        let json: Option<String> = conn.get(&key).await
            .map_err(ClientIdError::RedisError)?;
        
        self.return_conn(conn).await;
        
        match json {
            Some(json_str) => {
                serde_json::from_str(&json_str)
                    .map_err(|_| ClientIdError::InvalidData)
            }
            None => Err(ClientIdError::NotFound),
        }
    }
    
    pub async fn set_user_account(&self, client_id: &str, account: &UserAccount) -> Result<()> {
        let key = format!("client:{}:account", client_id);
        let mut conn = self.get_conn().await?;
        
        let json = serde_json::to_string(account)
            .map_err(|_| ClientIdError::InvalidData)?;
        
        let _: () = conn.set_ex(&key, &json, DEFAULT_CACHE_EXPIRY as u64).await
            .map_err(ClientIdError::RedisError)?;
        
        // Also set the tier for quick lookups
        let tier_key = format!("client:{}:tier", client_id);
        let tier = format!("{:?}", account.tier);
        let _: ()= conn.set_ex(&tier_key, &tier, DEFAULT_CACHE_EXPIRY as u64).await
            .map_err(ClientIdError::RedisError)?;
        
        self.return_conn(conn).await;
        
        Ok(())
    }
    
    pub async fn update_client_last_seen(&self, client_id: &str) -> Result<()> {
        let key = format!("client:{}:last_seen", client_id);
        let mut conn = self.get_conn().await?;
        
        let now = chrono::Utc::now().timestamp();
        let _: () = conn.set_ex(&key, now.to_string(), DEFAULT_CACHE_EXPIRY as u64).await
            .map_err(ClientIdError::RedisError)?;
        
        self.return_conn(conn).await;
        
        Ok(())
    }
    
    pub async fn set_device_info(&self, client_id: &str, device_id: &str, device_info: &DeviceInfo) -> Result<()> {
        let key = format!("client:{}:device:{}", client_id, device_id);
        let mut conn = self.get_conn().await?;
        
        let json = serde_json::to_string(device_info)
            .map_err(|_| ClientIdError::InvalidData)?;
        
        let _: () = conn.set_ex(&key, &json, DEFAULT_CACHE_EXPIRY as u64).await
            .map_err(ClientIdError::RedisError)?;
        
        // Also maintain a list of devices for this client
        let devices_key = format!("client:{}:devices", client_id);
        conn.sadd(&devices_key, device_id).await
            .map_err(ClientIdError::RedisError)?;
        conn.expire(&devices_key, DEFAULT_CACHE_EXPIRY as i64).await
            .map_err(ClientIdError::RedisError)?;
        
        self.return_conn(conn).await;
        
        Ok(())
    }
    
    pub async fn update_device_last_active(&self, client_id: &str, device_id: &str) -> Result<()> {
        let key = format!("client:{}:device:{}:last_active", client_id, device_id);
        let mut conn = self.get_conn().await?;
        
        let now = chrono::Utc::now().timestamp();
        let _: () = conn.set_ex(&key, now.to_string(), DEFAULT_CACHE_EXPIRY as u64).await
            .map_err(ClientIdError::RedisError)?;
        
        self.return_conn(conn).await;
        
        Ok(())
    }
    
    pub async fn increment_usage_count(&self, client_id: &str) -> Result<u32> {
        let today = chrono::Utc::now().date_naive().format("%Y-%m-%d").to_string();
        let key = format!("client:{}:usage:{}", client_id, today);
        let mut conn = self.get_conn().await?;
        
        let count: u32 = conn.incr(&key, 1).await
            .map_err(ClientIdError::RedisError)?;
        
        // Set expiry for 48 hours (to ensure we capture full day's usage)
        let _: bool = conn.expire(&key, 60 * 60 * 48).await
            .map_err(ClientIdError::RedisError)?;
        
        self.return_conn(conn).await;
        
        Ok(count)
    }
}