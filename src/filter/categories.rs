use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::db::operations::{DbError, DbOperations};
use crate::utils::logging::{debug, error, info, warn};

/// Error types for category operations
#[derive(Error, Debug)]
pub enum CategoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] DbError),
    
    #[error("Category not found: {0}")]
    CategoryNotFound(String),
    
    #[error("Category already exists: {0}")]
    CategoryAlreadyExists(String),
}

/// Result type for category operations
pub type CategoryResult<T> = Result<T, CategoryError>;

/// Category definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Category {
    /// Category name (unique identifier)
    pub name: String,
    
    /// Category description
    pub description: String,
    
    /// Whether this is a built-in category
    pub built_in: bool,
    
    /// When the category was created
    pub created_at: SystemTime,
    
    /// When the category was last updated
    pub updated_at: SystemTime,
}

/// Domain category mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainCategory {
    /// Domain pattern
    pub domain: String,
    
    /// Category name
    pub category_name: String,
    
    /// When the mapping was created
    pub created_at: SystemTime,
}

/// Manager for categories and domain categorization
pub struct CategoryManager {
    /// Database access
    db: Arc<dyn DbOperations>,
    
    /// Cache of categories
    categories_cache: HashMap<String, Category>,
    
    /// Cache of domain to category mappings
    /// Maps domain -> category name
    domain_categories_cache: HashMap<String, String>,
    
    /// When categories were last refreshed
    categories_last_refresh: SystemTime,
    
    /// When domain categories were last refreshed
    domain_categories_last_refresh: SystemTime,
    
    /// How long to cache categories before refreshing
    cache_ttl: Duration,
}

impl CategoryManager {
    /// Create a new category manager
    pub async fn new(
        db: Arc<dyn DbOperations>,
        cache_ttl: Duration,
    ) -> CategoryResult<Self> {
        let mut manager = Self {
            db,
            categories_cache: HashMap::new(),
            domain_categories_cache: HashMap::new(),
            categories_last_refresh: SystemTime::now(),
            domain_categories_last_refresh: SystemTime::now(),
            cache_ttl,
        };
        
        // Initial load of data
        manager.refresh_categories().await?;
        manager.refresh_domain_categories().await?;
        
        Ok(manager)
    }
    
    /// Refresh categories from database
    pub async fn refresh_categories(&mut self) -> CategoryResult<()> {
        debug!("Refreshing categories from database");
        
        let categories = self.db.get_all_categories().await?;
        
        // Update cache
        self.categories_cache.clear();
        for category in categories {
            self.categories_cache.insert(category.name.clone(), category);
        }
        
        self.categories_last_refresh = SystemTime::now();
        
        info!("Categories refreshed, {} categories loaded", self.categories_cache.len());
        
        Ok(())
    }
    
    /// Refresh domain category mappings from database
    pub async fn refresh_domain_categories(&mut self) -> CategoryResult<()> {
        debug!("Refreshing domain category mappings from database");
        
        let mappings = self.db.get_all_domain_categories().await?;
        
        // Update cache
        self.domain_categories_cache.clear();
        for mapping in mappings {
            // Store with lowercase domain for case-insensitive lookups
            self.domain_categories_cache.insert(
                mapping.domain.to_lowercase(),
                mapping.category_name,
            );
        }
        
        self.domain_categories_last_refresh = SystemTime::now();
        
        info!("Domain categories refreshed, {} mappings loaded", self.domain_categories_cache.len());
        
        Ok(())
    }
    
    /// Check if caches need refreshing
    async fn ensure_caches_fresh(&mut self) -> CategoryResult<()> {
        let now = SystemTime::now();
        
        let categories_elapsed = now
            .duration_since(self.categories_last_refresh)
            .unwrap_or(Duration::from_secs(0));
            
        let domain_categories_elapsed = now
            .duration_since(self.domain_categories_last_refresh)
            .unwrap_or(Duration::from_secs(0));
            
        if categories_elapsed > self.cache_ttl {
            self.refresh_categories().await?;
        }
        
        if domain_categories_elapsed > self.cache_ttl {
            self.refresh_domain_categories().await?;
        }
        
        Ok(())
    }
    
    /// Get the category of a domain
    pub async fn get_domain_category(&self, domain: &str) -> Option<String> {
        let domain_lower = domain.to_lowercase();
        
        // Direct lookup first for exact matches
        if let Some(category) = self.domain_categories_cache.get(&domain_lower) {
            return Some(category.clone());
        }
        
        // If no exact match, check for domain patterns
        // Start with most specific parts - e.g., full domain, then parent domains
        let parts: Vec<&str> = domain_lower.split('.').collect();
        let parts_len = parts.len();
        
        // Check for subdomain matches (*.example.com)
        if parts_len >= 2 {
            for i in 1..parts_len {
                let parent_domain = format!("*.{}", parts[parts_len - i..].join("."));
                if let Some(category) = self.domain_categories_cache.get(&parent_domain) {
                    return Some(category.clone());
                }
            }
        }
        
        // Check for TLD wildcards (example.*)
        if parts_len >= 2 {
            let base_domain = format!("{}.*", parts[..parts_len - 1].join("."));
            if let Some(category) = self.domain_categories_cache.get(&base_domain) {
                return Some(category.clone());
            }
        }
        
        // Check for contains patterns (*example*)
        for (pattern, category) in &self.domain_categories_cache {
            if pattern.starts_with('*') && pattern.ends_with('*') && pattern.len() > 2 {
                let middle = &pattern[1..pattern.len() - 1];
                if domain_lower.contains(middle) {
                    return Some(category.clone());
                }
            }
        }
        
        None
    }
    
    /// Get all categories
    pub async fn get_all_categories(&mut self) -> CategoryResult<Vec<Category>> {
        self.ensure_caches_fresh().await?;
        Ok(self.categories_cache.values().cloned().collect())
    }
    
    /// Get a specific category
    pub async fn get_category(&mut self, name: &str) -> CategoryResult<Category> {
        self.ensure_caches_fresh().await?;
        
        match self.categories_cache.get(name) {
            Some(category) => Ok(category.clone()),
            None => Err(CategoryError::CategoryNotFound(name.to_string())),
        }
    }
    
    /// Add a new category
    pub async fn add_category(&mut self, category: Category) -> CategoryResult<()> {
        // Check if category already exists
        if self.categories_cache.contains_key(&category.name) {
            return Err(CategoryError::CategoryAlreadyExists(category.name));
        }
        
        // Add to database
        self.db.add_category(&category).await?;
        
        // Add to cache
        self.categories_cache.insert(category.name.clone(), category);
        
        Ok(())
    }
    
    /// Update an existing category
    pub async fn update_category(&mut self, category: Category) -> CategoryResult<()> {
        // Check if category exists
        if !self.categories_cache.contains_key(&category.name) {
            return Err(CategoryError::CategoryNotFound(category.name.clone()));
        }
        
        // Update in database
        self.db.update_category(&category).await?;
        
        // Update in cache
        self.categories_cache.insert(category.name.clone(), category);
        
        Ok(())
    }
    
    /// Delete a category
    pub async fn delete_category(&mut self, name: &str) -> CategoryResult<()> {
        // Check if category exists
        if !self.categories_cache.contains_key(name) {
            return Err(CategoryError::CategoryNotFound(name.to_string()));
        }
        
        // Check if this is a built-in category
        if let Some(category) = self.categories_cache.get(name) {
            if category.built_in {
                warn!("Attempted to delete built-in category: {}", name);
                return Err(CategoryError::CategoryNotFound(
                    format!("Cannot delete built-in category: {}", name)
                ));
            }
        }
        
        // Delete from database
        self.db.delete_category(name).await?;
        
        // Remove from cache
        self.categories_cache.remove(name);
        
        // We'll also need to refresh domain categories as some may have referenced this category
        self.refresh_domain_categories().await?;
        
        Ok(())
    }
    
    /// Add a domain to a category
    pub async fn add_domain_category(&mut self, domain: &str, category_name: &str) -> CategoryResult<()> {
        // Check if category exists
        if !self.categories_cache.contains_key(category_name) {
            return Err(CategoryError::CategoryNotFound(category_name.to_string()));
        }
        
        // Create mapping
        let mapping = DomainCategory {
            domain: domain.to_lowercase(),
            category_name: category_name.to_string(),
            created_at: SystemTime::now(),
        };
        
        // Add to database
        self.db.add_domain_category(&mapping).await?;
        
        // Add to cache
        self.domain_categories_cache.insert(domain.to_lowercase(), category_name.to_string());
        
        Ok(())
    }
    
    /// Remove a domain from a category
    pub async fn remove_domain_category(&mut self, domain: &str) -> CategoryResult<()> {
        let domain_lower = domain.to_lowercase();
        
        // Check if mapping exists
        if !self.domain_categories_cache.contains_key(&domain_lower) {
            return Ok(()); // Not an error if mapping doesn't exist
        }
        
        // Remove from database
        self.db.delete_domain_category(&domain_lower).await?;
        
        // Remove from cache
        self.domain_categories_cache.remove(&domain_lower);
        
        Ok(())
    }
    
    /// Get all domains in a category
    pub async fn get_domains_in_category(&mut self, category_name: &str) -> CategoryResult<Vec<String>> {
        self.ensure_caches_fresh().await?;
        
        // Check if category exists
        if !self.categories_cache.contains_key(category_name) {
            return Err(CategoryError::CategoryNotFound(category_name.to_string()));
        }
        
        // Filter domain mappings by category
        let domains = self.domain_categories_cache
            .iter()
            .filter_map(|(domain, cat)| {
                if cat == category_name {
                    Some(domain.clone())
                } else {
                    None
                }
            })
            .collect();
            
        Ok(domains)
    }
    
    /// Cleanup routine
    pub async fn cleanup(&mut self) {
        let _ = self.ensure_caches_fresh().await;
    }
}