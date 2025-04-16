use crate::client_id::models::{DeviceInfo, UserAccount, UserTier};
use crate::client_id::ClientIdError;
use crate::client_id::Result;
use sqlx::types::time::OffsetDateTime;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;


// Pooling
#[derive(Clone)]
pub struct DbPool {
    pool: Arc<Pool<Postgres>>,
}

impl DbPool {
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await
            .map_err(ClientIdError::DbError)?;

        // validate connection
        sqlx::query("SELECT 1")
            .execute(&pool)
            .await
            .map_err(ClientIdError::DbError)?;

        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    pub async fn get_client_by_ip(&self, ip: IpAddr) -> Result<(String, UserAccount)> {
        // Query to find client by ip address
        // this would typically involve a join btn clients and their current ip mappings
        let ip_str = ip.to_string();

        // Query for client ID by Ip
        let client_id = sqlx::query!(
            r#"
            SELECT client_id
            FROM client_ip_mappings
            WHERE ip_address = $1 AND active = true
            "#,
            ip_str
        ).fetch_optional(&*self.pool)
        .await
        .map_err(ClientIdError::DbError)?
        .ok_or(ClientIdError::NotFound)?
        .client_id;

        // Query for account details
        let record = sqlx::query!(
            r#"
            SELECT 
                c.client_id,
                c.name,
                c.email,
                c.tier,
                c.max_devices,
                c.active_devices,
                c.quota_daily,
                c.quota_used,
                c.custom_rules_enabled
            FROM clients c
            WHERE c.client_id = $1
            "#,
            client_id
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(ClientIdError::DbError)?
        .ok_or(ClientIdError::NotFound)?;
        
        // Convert database record to UserAccount
        let tier = match record.tier.as_str() {
            "free" => UserTier::Free,
            "premium" => UserTier::Premium,
            "premium_education" => UserTier::PremiumEducation,
            "premium_business" => UserTier::PremiumBusiness,
            _ => UserTier::Free, // Default to free if unknown
        };
        
        let account = UserAccount {
            client_id: record.client_id,
            tier,
            name: record.name,
            email: record.email,
            max_devices: record.max_devices as u32,
            active_devices: record.active_devices as u32,
            quota_daily: record.quota_daily as u32,
            quota_used: record.quota_used as u32,
            custom_rules_enabled: record.custom_rules_enabled,
        };
        
        Ok((client_id, account))
    }

    pub async fn create_anonymous_account(&self, ip: IpAddr, account: &UserAccount) -> Result<()> {
        let ip_str = ip.to_string();
        let tier_str = format!("{:?}", account.tier).to_lowercase();
        
        // Use a transaction for atomic operations
        let mut tx = self.pool.begin().await.map_err(ClientIdError::DbError)?;
        
        // Insert client
        sqlx::query!(
            r#"
            INSERT INTO clients 
            (client_id, name, email, tier, max_devices, active_devices, quota_daily, quota_used, custom_rules_enabled)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (client_id) DO NOTHING
            "#,
            account.client_id,
            account.name,
            account.email,
            tier_str,
            account.max_devices as i32,
            account.active_devices as i32,
            account.quota_daily as i32,
            account.quota_used as i32,
            account.custom_rules_enabled
        )
        .execute(&mut *tx)
        .await
        .map_err(ClientIdError::DbError)?;
        
        // Map IP to client
        sqlx::query!(
            r#"
            INSERT INTO client_ip_mappings 
            (client_id, ip_address, active, created_at)
            VALUES ($1, $2, true, NOW())
            ON CONFLICT (ip_address) DO UPDATE
            SET client_id = $1, active = true, updated_at = NOW()
            "#,
            account.client_id,
            ip_str
        )
        .execute(&mut *tx)
        .await
        .map_err(ClientIdError::DbError)?;
        
        tx.commit().await.map_err(ClientIdError::DbError)?;
        
        Ok(())
    }
    
    pub async fn register_device(&self, client_id: &str, device_id: &str, device_info: &DeviceInfo) -> Result<()> {
        let ip_str = device_info.ip_address.to_string();
        let mac = device_info.mac_address.clone().unwrap_or_default();
        let fingerprint = device_info.browser_fingerprint.clone().unwrap_or_default();
        let group = device_info.group.clone().unwrap_or_default();
        let _last_active_offset = OffsetDateTime::from_unix_timestamp(
            device_info.last_active.timestamp()
        ).unwrap();
        
        sqlx::query!(
            r#"
            INSERT INTO devices 
            (client_id, device_id, name, ip_address, mac_address, browser_fingerprint, last_active, device_group)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (client_id, device_id) DO UPDATE
            SET name = $3, ip_address = $4, mac_address = $5, browser_fingerprint = $6, 
                last_active = $7, device_group = $8, updated_at = NOW()
            "#,
            client_id,
            device_id,
            device_info.name,
            ip_str,
            mac,
            fingerprint,
            device_info.last_active,
            group
        )
        .execute(&*self.pool)
        .await
        .map_err(ClientIdError::DbError)?;
        
        // Also update the active_devices count for the client
        sqlx::query!(
            r#"
            UPDATE clients
            SET active_devices = (
                SELECT COUNT(*) FROM devices 
                WHERE client_id = $1 AND last_active > NOW() - INTERVAL '30 days'
            )
            WHERE client_id = $1
            "#,
            client_id
        )
        .execute(&*self.pool)
        .await
        .map_err(ClientIdError::DbError)?;
        
        Ok(())
    }
}