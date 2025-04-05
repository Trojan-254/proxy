/// Module that handles all database operations
/// 
/// This module contains functions to interact with the database.
/// It includes functions to create, read, update, and delete records.
/// It also includes functions to initialize the database and create tables.
/// 
use async_trait::async_trait;
use thiserror::Error;
use tokio_postgres::{Client, Error as PgError};
use std::{fmt::Result, sync::Arc, time::SystemTime};
use tokio_postgres::NoTls;

use crate::filter::rules::{
    Rule,
    RuleAction,
    TimeRestriction
};

/// Database operation errors
#[derive(Error, Debug)]
pub enum DbError {
    #[error("Database connection error: {0}")]
    ConnectionError(String),

    #[error("Failed to execute query: {0}")]
    QueryError(#[from] PgError),

    #[error("Failed to parse row: {0}")]
    RowParseError(String),

    #[error("Failed to create table: {0}")]
    CreateTableError(String),

    #[error("Failed to insert record: {0}")]
    InsertRecordError(String),

    #[error("Failed to update record: {0}")]
    UpdateRecordError(String),

    #[error("Failed to delete record: {0}")]
    DeleteRecordError(String),

    #[error("No data found: {0}")]
    NotFound(String),
    
    #[error("Data conversion error: {0}")]
    ConversionError(String),
}

/// Result type for database operations
pub type DbResult<T> = Result<T, DbError>;

/// Database operations trait
#[async_trait]
pub trait DbOperations: Send + Sync {
    /// Get all rules from the database
    async fn get_all_rules(&self) -> DbResult<Vec<Rule>>;
    
    /// Get a specific rule by ID
    async fn get_rule(&self, rule_id: u32) -> DbResult<Rule>;
    
    /// Check if a rule exists
    async fn rule_exists(&self, rule_id: u32) -> DbResult<bool>;
    
    /// Add a new rule to the database
    async fn add_rule(&self, rule: &Rule) -> DbResult<u32>;
    
    /// Update an existing rule
    async fn update_rule(&self, rule: &Rule) -> DbResult<()>;
    
    /// Delete a rule
    async fn delete_rule(&self, rule_id: u32) -> DbResult<()>;
    
    /// Get all categories
    async fn get_all_categories(&self) -> DbResult<Vec<String>>;
    
    /// Get domains in a specific category
    async fn get_domains_in_category(&self, category: &str) -> DbResult<Vec<String>>;
    
    /// Add a domain to a category
    async fn add_domain_to_category(&self, domain: &str, category: &str) -> DbResult<()>;
    
    /// Remove a domain from a category
    async fn remove_domain_from_category(&self, domain: &str, category: &str) -> DbResult<()>;
    
    /// Get the category for a specific domain
    async fn get_domain_category(&self, domain: &str) -> DbResult<Option<String>>;
    
    /// Add a client mapping
    async fn add_client_mapping(&self, ip: &str, mac: Option<&str>, hostname: Option<&str>, group_id: &str) -> DbResult<()>;
    
    /// Get group ID for a client
    async fn get_client_group(&self, ip: &str, mac: Option<&str>, hostname: Option<&str>) -> DbResult<String>;
    
    /// Log a DNS query
    async fn log_query(&self, domain: &str, client_ip: &str, client_mac: Option<&str>, 
                     client_group: &str, allowed: bool, category: Option<&str>, 
                     rule_id: Option<u32>) -> DbResult<()>;
}

/// Database operations implementation
pub struct PostgresDb {
    client: Arc<Client>,
}

impl PostgresDb {
    /// Create a new PostgreSQL database connection
    pub async fn new(connection_string: &str) -> DbResult<Self> {
        let (client, connection) = tokio_postgres::connect(connection_string, tokio_postgres::NoTls)
            .await
            .map_err(|e| DbError::ConnectionError(e.to_string()))?;
            
        // Spawn the connection handler
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Database connection error: {}", e);
            }
        });
        
        Ok(Self {
            client: Arc::new(client),
        })
    }
    
    /// Convert database row to Rule
    async fn row_to_rule(&self, id: i32) -> DbResult<Rule> {
        // Get the base rule info
        let row = self.client.query_one(
            "SELECT id, group_id, priority, action, enabled, description 
             FROM rules WHERE id = $1",
            &[&id],
        ).await?;
        
        let rule_id = row.get::<_, i32>("id") as u32;
        let group_id = row.get::<_, String>("group_id");
        let priority = row.get::<_, i32>("priority") as u32;
        let action_str = row.get::<_, String>("action");
        let action = if action_str == "ALLOW" { RuleAction::Allow } else { RuleAction::Block };
        let enabled = row.get::<_, bool>("enabled");
        let description = row.get::<_, String>("description");
        let created_at = row.get::<_, i32>("created_at") as u64;
        let updated_at = row.get::<_, i32>("updated_at") as u64;
        // Get exact domains
        let domains_rows = self.client.query(
            "SELECT domain FROM rule_domains WHERE rule_id = $1",
            &[&id],
        ).await?;
        
        let exact_domains = domains_rows.iter()
            .map(|row| row.get::<_, String>("domain"))
            .collect();
            
        // Get domain patterns
        let patterns_rows = self.client.query(
            "SELECT pattern FROM rule_patterns WHERE rule_id = $1",
            &[&id],
        ).await?;
        
        let domain_patterns = patterns_rows.iter()
            .map(|row| row.get::<_, String>("pattern"))
            .collect();
            
        // Get categories
        let categories_rows = self.client.query(
            "SELECT category_name FROM rule_categories WHERE rule_id = $1",
            &[&id],
        ).await?;
        
        let categories = categories_rows.iter()
            .map(|row| row.get::<_, String>("category_name"))
            .collect();
            
        // Get time restrictions
        let time_rows = self.client.query(
            "SELECT days, start_time, end_time 
             FROM time_restrictions WHERE rule_id = $1",
            &[&id],
        ).await?;
        
        let time_restrictions = time_rows.iter()
            .map(|row| {
                let days_str = row.get::<_, String>("days");
                let days = days_str.chars()
                    .map(|c| c.to_digit(10).unwrap_or(0) as u8)
                    .collect();
                    
                TimeRestriction {
                    id: row.get::<_, i32>("id") as u32,
                    created_at: row.get::<_, i32>("created_at") as u64,
                    days,
                    start_time: row.get::<_, i32>("start_time") as u64,
                    end_time: row.get::<_, i32>("end_time") as u64,
                }
            })
            .collect();
            
        Ok(Rule {
            id: rule_id,
            group_id,
            priority,
            action,
            enabled,
            description,
            exact_domains,
            domain_patterns,
            categories,
            time_restrictions,
            created_at,
            updated_at,
        })
    }
}