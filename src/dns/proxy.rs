use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use hickory_proto::op::{Message, ResponseCode, Header, OpCode, MessageType};
use thiserror::Error;
use tokio::net::UdpSocket as TokioUdpSocket;
// use tokio::time::timeout;

use crate::dns::cache::DnsCache;
use crate::utils::metrics_channel::{self, increment_counter};
use crate::{error, info, warn};
use crate::models::client::ClientInfo;



#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("DNS Protocol error: {0}")]
    ProtocolError(#[from] hickory_proto::ProtoError),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Timeout waiting for upstream DNS Server")]
    UpstreamTimeout,

    #[error("Invalid Request format")]
    InvalidRequest,

    #[error("Security violation: {0}")]
    SecurityViolation(String),

    #[error("Rate limit exceeded for client {0}")]
    RateLimitExceeded(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Result type for dns proxy operations
type ProxyResult<T> = Result<T, ProxyError>;

#[derive(Clone)]
pub struct ProxyConfig {
    pub upstream_servers: Vec<SocketAddr>,
    pub upstream_timeout_ms: u64,
    pub rate_limit_window_secs: u64,
    pub rate_limit_max_requests: u32,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            upstream_servers: vec![
                "8.8.8.8:53".parse().unwrap(),
                "8.8.4.4:53".parse().unwrap(),
            ],
            upstream_timeout_ms: 2000,
            rate_limit_window_secs: 60,
            rate_limit_max_requests: 100,
        }
    }
}


/// Structure to hold rate limiting for clients
struct RateLimiter {
    //Maps client IP to (last request time, request count)
    clients: HashMap<IpAddr, (Instant, u32)>,
    window_size: Duration,
    max_requests: u32,
}

impl RateLimiter {
    /// New rate limiter
    pub fn new(window_size: Duration, max_requests:u32) -> Self {
        Self {
            clients: HashMap::new(),
            window_size,
            max_requests,
        }
    }

    /// Check rate limit - using only IP address, not port
    pub fn check_rate_limit(&mut self, client_addr: SocketAddr) -> bool {
        let now = Instant::now();
        let ip = client_addr.ip(); // Extract just the IP part
        
        // Get current entry or create new one
        let entry = self.clients.entry(ip).or_insert((now, 0));
        
        // If the time window has passed, reset the counter
        if now.duration_since(entry.0) > self.window_size {
            *entry = (now, 1); // Reset with count 1 (for this request)
            info!("Rate limit window reset for {}, new count: 1", ip);
            return true;
        }
        
        // Increment counter for this request
        entry.1 += 1;
        
        // Log the current count
        info!("Client {} request count: {}/{} in current window", 
                 ip, entry.1, self.max_requests);
        
        // Check if limit exceeded
        if entry.1 > self.max_requests {
            warn!("⚠️ Rate limit EXCEEDED for {}: {}/{}", 
                     ip, entry.1, self.max_requests);
            return false;
        }
        
        true
    }

    /// Clean up old entries periodically
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let before_count = self.clients.len();
        
        self.clients.retain(|ip, (timestamp, _)| {
            let keep = now.duration_since(*timestamp) <= self.window_size * 2;
            if !keep {
                info!("Cleaning up rate limit entry for {}", ip);
            }
            keep
        });
        
        let removed = before_count - self.clients.len();
        if removed > 0 {
            info!("Rate limiter cleanup: removed {} stale entries", removed);
        }
    }
}

pub struct DnsProxy {
    socket: Arc<TokioUdpSocket>,
    buffer_size: usize,
    rate_limiter: Arc<RwLock<RateLimiter>>,
    config: ProxyConfig,
    cache: Arc<RwLock<DnsCache>>,
}

impl DnsProxy {
    pub async fn new(
        bind_addr: SocketAddr,
        config: ProxyConfig,
        cache: Arc<RwLock<DnsCache>>
    ) -> ProxyResult<Self> {
        let socket = TokioUdpSocket::bind(bind_addr).await?;
        let buffer_size = if cfg!(target_os = "linux") {
            8192
        } else {
            4086
        };
        let rate_limiter = Arc::new(RwLock::new(RateLimiter::new(
            Duration::from_secs(config.rate_limit_window_secs),
            config.rate_limit_max_requests,
        )));

        Ok(Self {
            socket: Arc::new(socket),
            buffer_size,
            config,
            rate_limiter,
            cache,
        })
    }

    
        /// Start the DNS Proxy
        pub async fn run(&self) -> ProxyResult<()> {
            info!("Starting DNS Proxy server on {}", self.socket.local_addr()?);

            // Spawn a task to periodically clean up rate limiter
            let rate_limiter_cleanup = self.rate_limiter.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    let mut limiter = rate_limiter_cleanup.write().expect("Failed to acquire write lock");
                    limiter.cleanup();
                }
            });

            // Spawn a task periodically to clean up acache
            let cache_cleanup = self.cache.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(300));
                loop {
                    interval.tick().await;
                    if let Ok(mut cache) = cache_cleanup.write() {
                        cache.cleanup();
                    }
                }
            });

            let mut recv_buffer = vec![0u8; self.buffer_size];
    
            loop {
                match self.socket.recv_from(&mut recv_buffer).await {
                    Ok((size, client_addr)) => {
                        // println!(
                        //     "Received {} bytes from {}",
                        //     size, client_addr
                        // );
                        // println!("Data: {:?}", &recv_buffer[..size]);

                        // let response = b"Hello from Rust UDP server!";
                        // self.socket.send_to(response, client_addr).await?;
                        // println!("Sent response to {}", client_addr);


                        // Clone required data
                        let socket = self.socket.clone();
                        let config = self.config.clone();
                        let cache = self.cache.clone();
                        let rate_limiter = self.rate_limiter.clone();
                        let request_data = recv_buffer[..size].to_vec();

                        // Process a request ina separeta task
                        tokio::spawn(async move {
                            let start_time = Instant::now();

                            // Handle request and send response
                            match Self::handle_request(
                                &socket,
                                &request_data,
                                client_addr,
                                &config,
                                &cache,
                                &rate_limiter,
                            ).await {
                                Ok(_) => {
                                    if cfg!(debug_assertions) {
                                        info!("Request from {} processed in {:?}", 
                                                 client_addr, start_time.elapsed());
                                    }
                                }
                                Err(e) => {
                                    warn!("Error processing request from {}: {}", client_addr, e);
                                
                                // Try to send an error response
                                if let Err(send_err) = Self::send_error_response(&socket, client_addr, &request_data, e).await {
                                    warn!("Failed to send error response: {}", send_err);
                                }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        warn!("Failed to receive data: {}", e);

                        if e.kind() == std::io::ErrorKind::WouldBlock || 
                       e.kind() == std::io::ErrorKind::TimedOut {
                        // For transient errors, just continue
                        continue;
                    } else {
                        // For other errors, break and return
                        return Err(e.into());
                    }
                    }
                }
            }
        }

        async fn handle_request(
            socket: &TokioUdpSocket,
            request_data: &[u8],
            client_addr: SocketAddr,
            config: &ProxyConfig,
            cache: &Arc<RwLock<DnsCache>>,
            rate_limiter: &Arc<RwLock<RateLimiter>>
        ) -> ProxyResult<()> {
            // We start timing the entire request
            let request_timer = metrics_channel::start_timer("dns.request.duration");

            // Check rate limit first
            let rate_limit_ok = {
                let mut limiter = rate_limiter.write().expect("Failed to acquire write lock.");
                limiter.check_rate_limit(client_addr)
            };
            
            if !rate_limit_ok {
                warn!("Rate limit exceeded for client {}", client_addr.ip());
                return Err(ProxyError::RateLimitExceeded(client_addr.to_string()));
            }
            let request = match Message::from_vec(request_data) {
                Ok(msg) => msg,
                Err(e) => {
                    warn!("Invalid DNS request from {}: {}", client_addr, e);
                    return Err(ProxyError::ProtocolError(e));

                }
            };

            // Security chcheck
            Self::security_check(&request, client_addr)?;

            

            let client_info = ClientInfo::from_addr(client_addr);

            // Log client info
            println!("🛰️  Incoming DNS request from:");
            println!("   - IP Address     : {}", client_info.ip_addr);
            println!("   - Port           : {}", client_info.port);
            println!("   - MAC Address    : {}", client_info.mac_address.as_deref().unwrap_or("Unknown"));
            println!("   - Hostname       : {}", client_info.hostname.as_deref().unwrap_or("Unknown"));
            println!("   - Group ID       : {}", client_info.group_id.as_deref().unwrap_or("Unknown"));
            println!("   - Friendly Name  : {}", client_info.friendly_name.as_deref().unwrap_or("Unnamed"));
            

            // Check if there are questions to process
            if request.queries().is_empty() {
                return Err(ProxyError::InvalidRequest);
            }

            // Process each query in a request
            let question = &request.queries()[0];
            let query_name = question.name().to_ascii();

            if cfg!(debug_assertions) {
                info!("Processing query for {} (type: {:?}) from {}", 
                         query_name, question.query_type(), client_addr);
            }

            // Try to get domain from cache
            let cached_response = {
                let cache_reader = cache.read().expect("Failure to acquire read lock");
                cache_reader.get(&query_name, question.query_type())
            };

            if let Some(cached_resp) = cached_response {
                let mut response = cached_resp.clone();
                response.set_id(request.id());
                
                // Send the cached response
                let response_data = response.to_vec()?;
                socket.send_to(&response_data, client_addr).await?;
                increment_counter("dns.cache.hits");                
                return Ok(());
            }

            // Forwad result to upstream servers
            // Time the upstream request
            let upstream_timer = metrics_channel::start_timer("dns.upstream.duration");
            let response = Self::forward_to_upstream(
                request_data,
                &config.upstream_servers,
                config.upstream_timeout_ms,
            ).await?;
            drop(upstream_timer); // Stop the timer

            let response_timer = metrics_channel::start_timer("dns.response.duration");


            // Cache the response if it's cacheable
            if Self::is_cacheable(&response) {
                let ttl = Self::get_min_ttl(&response);
                let mut cache_writer = cache.write().expect("Failed to acquire write lock");
                let _ = cache_writer.insert(&query_name, question.query_type(), response.clone(), ttl);
                increment_counter("dns.cache.insert");
            }

            // send response back to client
            let response_data = response.to_vec()?;
            socket.send_to(&response_data, client_addr).await?;
            increment_counter("dns.requests.success");

            drop(request_timer); // Stop the request timer
            drop(response_timer); // Stop the response timer
            // Record the request and response times
            // metrics_channel::record_timer("dns.request.duration", request_timer.elapsed().as_nanos() as u64);
            // metrics_channel::record_timer("dns.response.duration", response_timer.elapsed().as_nanos() as u64);
            // // Record the upstream request time
            // metrics_channel::record_timer("dns.upstream.duration", upstream_timer.elapsed().as_nanos() as u64);
            
            Ok(())
        }

        // get min ttl
        fn get_min_ttl(response: &Message) -> u32 {
            response.answers()
            .iter()
            .map(|record| record.ttl())
            .min()
            .unwrap_or(300)
        }

        async fn send_error_response (
            socket: &TokioUdpSocket,
            client_addr: SocketAddr,
            request_data: &[u8],
            error: ProxyError,
        ) -> ProxyResult<()> {
            let request = match Message::from_vec(request_data) {
                Ok(req) => req,
                Err(_) => {
                    return Err(ProxyError::InvalidRequest);
                }
            };

            let mut response = Message::new();
            response.set_id(request.id());

            let mut header = Header::new();
            header.set_message_type(MessageType::Response);
            header.set_op_code(request.op_code());

            let response_code = match &error {
                ProxyError::InvalidRequest => ResponseCode::FormErr,
                ProxyError::SecurityViolation(_) => ResponseCode::Refused,
                _ => ResponseCode::ServFail,
            };

            header.set_response_code(response_code);
            header.set_recursion_desired(request.recursion_desired());
            header.set_recursion_available(true);
            response.set_header(header);
            
            // Copy the queries from the request
            for query in request.queries() {
                response.add_query(query.clone());
            }
            
            // Send the error response
            let response_data = response.to_vec()?;
            socket.send_to(&response_data, client_addr).await?;
            increment_counter("dns.requests.error");
            
            Ok(())
        }

        /// Check if a response is cacheable
        fn is_cacheable(response: &Message) -> bool {
            // Don't cache error responses
            if response.response_code() != ResponseCode::NoError {
                return false;
            }
            
            // Don't cache empty responses
            if response.answers().is_empty() {
                return false;
            }
            
            // Check if all TTLs are > 0
            response.answers().iter().all(|record| record.ttl() > 0)
        }


        /// Forward result to upstream servers
        async fn forward_to_upstream(
            request_data: &[u8],
            upstream_servers: &[SocketAddr],
            timeout_ms: u64,
        ) -> ProxyResult<Message> {
            let upstream_socket = UdpSocket::bind("0.0.0.0:0")
                .map_err(|e| {
                    error!("Failed to bind upstream socket: {}", e);
                    e
                })?;

            upstream_socket.set_nonblocking(true)
                .map_err(|e| {
                    error!("Failed to set socket to non-blocking: {}", e);
                    e
                })?;

            // send request to upstream server
            for server in upstream_servers {
                match upstream_socket.send_to(request_data, server) {
                    Ok(_) => {
                        if cfg!(debug_assertions) {
                            info!("Request sent to upstream server {}", server);
                        }
                        
                        // Set up a timeout for receiving the response
                        let timeout_ms = timeout_ms as u64;
                        let timeout = Duration::from_millis(timeout_ms);

                        let mut buf = vec![0u8; 4096];
                        match tokio::time::timeout(timeout, async {
                            let async_socket = TokioUdpSocket::from_std(upstream_socket.try_clone()?)?;
                            async_socket.recv(&mut buf).await
                        }).await {
                            Ok(Ok(size)) => {
                                match Message::from_vec(&buf[..size]) {
                                    Ok(response) => {
                                        increment_counter("dns.upstream.requests");
                                        return Ok(response);
                                    },
                                    Err(e) => {
                                        warn!("Invalid response from upstream server {}: {}", server, e);
                                        continue;
                                    }
                                }
                            }
                            Ok(Err(e)) => {
                                warn!("Error receiving from upstream servers {}: {}", server, e);
                                continue;
                            }
                            Err(_) => {
                                warn!("Timeout waiting for response from upstream server: {}", server);
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to send to upstream servers {}: {}", server, e);
                        continue;
                    }
                }
            }
            error!("All upstream DNS servers failed to respond");
            Err(ProxyError::UpstreamTimeout)
        }

        /// Perform security checks on the DNS request
        fn security_check(request: &Message, client_addr: SocketAddr) -> ProxyResult<()> {
            // println!("Running security check for DNS request :\n {}", request);
            
            // Check for valid DNS message type
            if request.message_type() != MessageType::Query {
                return Err(ProxyError::SecurityViolation("Only DNS queries are allowed".into()));
            }
            
            // Check opcode (only standard queries allowed)
            if request.op_code() != OpCode::Query {
                return Err(ProxyError::SecurityViolation(format!(
                    "Unsupported OpCode: {:?}", request.op_code()
                )));
            }
            
            // Check that recursion is desired (we only support recursive queries)
            if !request.recursion_desired() {
                return Err(ProxyError::SecurityViolation("Only recursive queries are supported".into()));
            }
            
            // Limit query count per message (to prevent DOS)
            if request.queries().len() > 1 {
                return Err(ProxyError::SecurityViolation("Only one query per message is supported".into()));
            }
            
            // Check for DNS tunneling (excessively long domain names)
            for query in request.queries() {
                let domain = query.name().to_ascii();
                
                // Check total length (reduce from 253 to more reasonable length)
                if domain.len() > 120 {
                    warn!("Possible DNS tunneling attempt from {}: domain too long ({})", client_addr, domain.len());
                    return Err(ProxyError::SecurityViolation("Domain name too long".into()));
                }
                
                // Check individual label length
                if domain.split('.').any(|label| label.len() > 63) {
                    warn!("Possible DNS tunneling attempt from {}: label too long", client_addr);
                    return Err(ProxyError::SecurityViolation("Domain label too long".into()));
                }
                
                // Check for too many subdomains
                let label_count = domain.split('.').count();
                if label_count > 6 {
                    warn!("Possible DNS tunneling attempt from {}: too many subdomains ({})", client_addr, label_count);
                    return Err(ProxyError::SecurityViolation("Too many subdomains".into()));
                }
                
                // Check for suspicious characters in domain name (potential exfiltration)
                let suspicious_chars = domain.chars().any(|c| !c.is_ascii_alphanumeric() && c != '.' && c != '-');
                if suspicious_chars {
                    warn!("Suspicious domain name from {}: {}", client_addr, domain);
                    
                    return Err(ProxyError::SecurityViolation("Suspicious characters in domain name".into()));
                }
            }
            
            Ok(())
        }
}