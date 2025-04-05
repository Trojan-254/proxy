use std::sync::OnceLock;
use tokio::sync::mpsc;
use std::time::Instant;

// Define counter increment message
#[derive(Clone, Debug)]
pub struct CounterIncrement {
    pub name: String,
}

// Define timer record message
#[derive(Clone, Debug)]
pub struct TimerRecord {
    pub name: String,
    pub duration_nanos: u64,
}

// Message type for the metrics channel
#[derive(Clone, Debug)]
pub enum MetricsMessage {
    Counter(CounterIncrement),
    Timer(TimerRecord),
}

// Global channel sender
static METRICS_SENDER: OnceLock<mpsc::Sender<MetricsMessage>> = OnceLock::new();

// Initialize the metrics channel
pub fn init_metrics_channel() {
    let (tx, rx) = mpsc::channel::<MetricsMessage>(10000); // Buffered channel with capacity
    
    // Store sender in the global static
    METRICS_SENDER.get_or_init(|| tx);
    
    // Spawn background task to process metrics messages
    tokio::spawn(async move {
        process_metrics_messages(rx).await;
    });
}

// Process metrics messages
async fn process_metrics_messages(mut rx: mpsc::Receiver<MetricsMessage>) {
    use crate::utils::metrics;
    
    while let Some(message) = rx.recv().await {
        match message {
            MetricsMessage::Counter(increment) => {
                if let Err(e) = metrics::increment_counter(&increment.name).await {
                    eprintln!("Failed to increment counter {}: {:?}", increment.name, e);
                }
            },
            MetricsMessage::Timer(record) => {
                if let Err(e) = metrics::record_timer(&record.name, std::time::Duration::from_nanos(record.duration_nanos)).await {
                    eprintln!("Failed to record timer {}: {:?}", record.name, e);
                }
            }
        }
    }
}

// Synchronous function to increment counter
pub fn increment_counter(name: &str) {
    if let Some(sender) = METRICS_SENDER.get() {
        // Use try_send to avoid blocking if channel is full
        if let Err(e) = sender.try_send(MetricsMessage::Counter(CounterIncrement {
            name: name.to_string(),
        })) {
            eprintln!("Failed to send counter increment for {}: {:?}", name, e);
        }
    } else {
        eprintln!("Metrics channel not initialized when incrementing {}", name);
    }
}

// Synchronous function to record timer
pub fn record_timer(name: &str, duration: std::time::Duration) {
    if let Some(sender) = METRICS_SENDER.get() {
        // Use try_send to avoid blocking if channel is full
        if let Err(e) = sender.try_send(MetricsMessage::Timer(TimerRecord {
            name: name.to_string(),
            duration_nanos: duration.as_nanos() as u64,
        })) {
            eprintln!("Failed to send timer record for {}: {:?}", name, e);
        }
    } else {
        eprintln!("Metrics channel not initialized when recording timer {}", name);
    }
}

// Helper struct to automatically time operations
pub struct TimerGuard {
    name: String,
    start: Instant,
}

impl TimerGuard {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            start: Instant::now(),
        }
    }
}

impl Drop for TimerGuard {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        record_timer(&self.name, duration);
    }
}

// Convenience function to start a timer
pub fn start_timer(name: &str) -> TimerGuard {
    TimerGuard::new(name)
}