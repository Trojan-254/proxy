use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use proxy::dns::proxy::{DnsProxy, ProxyConfig};
use proxy::dns::cache::{DnsCache, DnsCacheConfig};
use proxy::utils::{metrics, metrics_channel, logging}; 
use proxy::utils::logging::LogLevel;

use proxy::{error, info};


// use deadpool_postgres::{Config, Manager, Pool};
// use tokio_postgres::NoTls;

#[tokio::main]
async fn main() -> std::io::Result<()> {


    // // Initialize PostgreSQL connection pool
    // let mut pg_config = Config::new();
    // pg_config.dbname = Some("proxy".to_string());
    // pg_config.user = Some("proxy_user".to_string());
    // pg_config.password = Some("39944816".to_string());
    // pg_config.host = Some("localhost".to_string());

    // // connection pool
    // let pool = pg_config.create_pool(None, NoTls).unwrap();

    // // Get a client from the pool
    // // Attempt to get a client from the pool
    // match pool.get().await {
    //     Ok(_) => info!("✅ Successfully connected to the database!"),
    //     Err(e) => eprintln!("❌ Database connection failed: {}", e),
    // }



    // Initialize custom logger first
    if let Err(e) = logging::init_logging(LogLevel::Debug, Some("dns_proxy.log"), true, true).await {
        println!("Failed to initialize custom logger: {}", e);
        // If you want to return this error, convert it:
        // return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
    } else {
        info!("Custom logger initialized successfully");
    }
    
    
    // Initialize metrics system - capture the registry
    let _metrics_registry = metrics::init(true);
    info!("Metrics system initialized");
    
    // Register DNS metrics before initializing the channel
    match metrics::register_dns_metrics().await {
        Ok(_) => info!("DNS metrics registered successfully"),
        Err(e) => error!("Failed to register DNS metrics: {}", e),
    }
    
    // Start metrics server
    let metrics_addr: SocketAddr = "0.0.0.0:9091".parse().expect("Invalid metrics address");
    match metrics::start_server(metrics_addr).await {
        Ok(_) => info!("Metrics server started on {}", metrics_addr),
        Err(e) => error!("Failed to start metrics server: {}", e),
    }
    
    // Initialize metrics channel AFTER registering metrics
    let _sender = metrics_channel::init_metrics_channel();
    info!("Metrics channel initialized");
    
    // Optionally start the console reporter for debugging
    match metrics::start_console_reporter(30).await {
        Ok(_) => info!("Metrics console reporter started"),
        Err(e) => error!("Failed to start metrics reporter: {}", e),
    }

    // Set local address for the DNS proxy to bind to
    let local_addr: SocketAddr = "0.0.0.0:2053".parse().expect("Invalid socket address");

    // Create a configuration with stricter rate limits for testing
    let config = ProxyConfig {
        upstream_servers: vec![
            "8.8.8.8:53".parse().unwrap(),
            "8.8.4.4:53".parse().unwrap(),
        ],
        upstream_timeout_ms: 2000,
        rate_limit_window_secs: 100,  // 100-second window
        rate_limit_max_requests: 1000,   // 1000 requests per 100 seconds
    };

    // Initialize the DNS cache with default configuration
    let cache_config = DnsCacheConfig::default();
    let cache = Arc::new(RwLock::new(DnsCache::with_config(cache_config.clone())));

    info!(
        "Starting DNS proxy with rate limiting and caching: window_size_secs={}, max_requests={}, rate={:.2} req/sec, cache_max_entries={}, cache_min_ttl={}, cache_max_ttl={}",
        config.rate_limit_window_secs,
        config.rate_limit_max_requests,
        config.rate_limit_max_requests as f64 / config.rate_limit_window_secs as f64,
        cache_config.max_entries,
        cache_config.min_ttl,
        cache_config.max_ttl
    );

    // Initialize the DNS Proxy with the cache
    match DnsProxy::new(local_addr, config, cache.clone()).await {
        Ok(proxy) => {
            info!("DNS proxy initialized successfully");
            
            // Print testing instructions with pretty formatting
            print_testing_instructions();
            
            // Start the DNS proxy server and handle any errors during runtime
            if let Err(e) = proxy.run().await {
                error!("Error running DNS proxy: {}", e);
            }
        }
        Err(e) => {
            // Handle errors that occurred during proxy initialization
            error!("Failed to initialize DNS proxy: {}", e);
        }
    }

    

    Ok(())
}

/// Print formatted testing instructions
fn print_testing_instructions() {
    // println!("\n{}", "═".repeat(80));
    // println!("{}  DNS PROXY TESTING INSTRUCTIONS  {}", "═".repeat(24), "═".repeat(24));
    // println!("{}", "═".repeat(80));
    
    // println!("\n📋 {} Test rate limiting:", console::style("1.").cyan().bold());
    // println!("  $ for i in {{1..10}}; do dig @127.0.0.1 -p 2053 example.com; echo \"Request $i complete\"; done");
    
    // println!("\n📋 {} Test caching (run multiple times to see cache hits):", console::style("2.").cyan().bold());
    // println!("  $ dig @127.0.0.1 -p 2053 example.com");
    // println!("  $ dig @127.0.0.1 -p 2053 +nocache example.com  # Bypass cache");
    
    // println!("\n📋 {} Test multiple domains with timing to see cache effect:", console::style("3.").cyan().bold());
    // println!("  $ time dig @127.0.0.1 -p 2053 google.com");
    // println!("  $ time dig @127.0.0.1 -p 2053 google.com  # Should be faster");
    
    // println!("\n📋 {} Compare cached vs uncached responses:", console::style("4.").cyan().bold());
    // println!("  $ dig @127.0.0.1 -p 2053 +noall +answer +ttl example.com");
    // println!("  $ dig @127.0.0.1 -p 2053 +noall +answer +ttl example.com  # TTL should decrease");
    
    println!("\n{}", "═".repeat(80));
    println!("{}  METRICS AVAILABLE AT: http://127.0.0.1:9091/metrics  {}", "═".repeat(15), "═".repeat(15));
    println!("{}", "═".repeat(80));
}