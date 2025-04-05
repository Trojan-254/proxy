use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Once, Arc};
use thiserror::Error;
use chrono::Local;
use tokio::sync::Mutex;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use colored::*;

/// Logging errors
#[derive(Error, Debug)]
pub enum LogError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid log level: {0}")]
    InvalidLogLevel(String),
    
    #[error("Logger initialization error: {0}")]
    InitError(String),
}

/// Result type for logging metrics
type LogResult<T> = Result<T, LogError>;

/// Logging levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "TRACE"),
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
        }
    }
}

impl LogLevel {
    /// Parse log level from string
    pub fn from_str(s: &str) -> LogResult<Self> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" | "warning" => Ok(LogLevel::Warn),
            "error" | "err" => Ok(LogLevel::Error),
            _ => Err(LogError::InvalidLogLevel(s.to_string())),
        }
    }
}


/// Logger logic
struct Logger {
    /// Current log level
    level: LogLevel,

    /// File for logging
    file: Option<Arc<Mutex<File>>>,

    /// Whether to log to std out or not
    stdout: bool,

    /// whether to include timestamps
    timestamps: bool,
}

impl Logger {
    /// Creates a new logger
    async fn new(level: LogLevel, log_file: Option<&str>, stdout: bool, timestamps: bool) -> LogResult<Self> {
        let file = if let Some(path) = log_file {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?;

            Some(Arc::new(Mutex::new(file)))
        } else {
            None
        };

        Ok(Self {
            level,
            file,
            stdout,
            timestamps,
        })
    }

    /// Log a message
    async fn log(&self, level: LogLevel, message: &str, module: &str) -> LogResult<()> {
        // so skip if the log level is lower than the configured level
        if level < self.level {
            return Ok(());
        }

        // format the log message
        let timestamp = if self.timestamps {
            let now = Local::now();
            format!("{} ", now.format("%Y-%m-%d %H:%M:%S%.3f"))
        } else {
            String::new()
        };

        // Create colored level string for terminal output
        let level_str = match level {
            LogLevel::Trace => level.to_string().magenta(),
            LogLevel::Debug => level.to_string().blue(),
            LogLevel::Info => level.to_string().green(),
            LogLevel::Warn => level.to_string().yellow(),
            LogLevel::Error => level.to_string().red().bold(), // Bold red for errors
        };

        // Plain text version for file logging
        let plain_formatted = format!(
            "{}[{}] [{}] {}\n",
            timestamp,
            level,
            module,
            message
        );
        
        // Colored version for stdout
        let colored_formatted = format!(
            "{}[{}] [{}] {}\n",
            timestamp,
            level_str,
            module.cyan(), // Module name in cyan for better readability
            match level {
                LogLevel::Error => message.red(),
                LogLevel::Warn => message.yellow(),
                _ => message.normal()
            }
        );
        
         // Write to file if configured (plain text)
         if let Some(file) = &self.file {
            let mut file_guard = file.lock().await;
            file_guard.write_all(plain_formatted.as_bytes()).await?;
        }
        
        // Write to stdout if configured (colored)
        if self.stdout {
            print!("{}", colored_formatted);
        }
        
        Ok(())
    }
}


/// Global logger
static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static INIT: Once = Once::new();
static mut LOGGER: Option<Arc<Mutex<Logger>>> = None;

pub async fn init_logging(level: LogLevel, log_file: Option<&str>, stdout: bool, timestamps: bool) -> LogResult<()> {
    // Reset the flag if needed for reinitialization during tests
    // LOGGER_INITIALIZED.store(false, Ordering::SeqCst);  // Uncomment if needed for testing

    if LOGGER_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    let logger = Logger::new(level, log_file, stdout, timestamps).await?;
    
    unsafe {
        // Replace the Once pattern with a simpler approach
        LOGGER = Some(Arc::new(Mutex::new(logger)));
        LOGGER_INITIALIZED.store(true, Ordering::SeqCst);
    }

    Ok(())
}


/// Initialize the logger from config string
pub async fn init_from_config(level_str: &str, log_file: Option<&str>) -> LogResult<()> {
    let level = LogLevel::from_str(level_str)?;
    init_logging(level, log_file, true, true).await
}

/// Set the current log level
pub async fn set_level(level: LogLevel) -> LogResult<()> {
    if !LOGGER_INITIALIZED.load(Ordering::SeqCst) {
        return Err(LogError::InitError("Logger not initialized".to_string()));
    }
    
    unsafe {
        if let Some(logger) = &LOGGER {
            let mut guard = logger.lock().await;
            guard.level = level;
        }
    }
    
    Ok(())
}

/// Internal log function
pub async fn log_internal(level: LogLevel, message: &str, module: &str) -> LogResult<()> {
    if !LOGGER_INITIALIZED.load(Ordering::SeqCst) {
        // If logger is not initialized, just print to stdout as fallback
        let now = Local::now();
        println!("{} [{}] [{}] {}", 
            now.format("%Y-%m-%d %H:%M:%S%.3f"),
            level,
            module,
            message
        );
        return Ok(());
    }
    
    unsafe {
        if let Some(logger) = &LOGGER {
            let guard = logger.lock().await;
            guard.log(level, message, module).await?;
        }
    }
    
    Ok(())
}

/// Get module name from file path
pub fn get_module_name(file: &str) -> &str {
    file.split('/')
        .last()
        .unwrap_or(file)
        .split('\\')
        .last()
        .unwrap_or(file)
        .split('.')
        .next()
        .unwrap_or(file)
}

/// Log at trace levels
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {{
        let module = $crate::utils::logging::get_module_name(file!());
        let message = format!($($arg)*);
        tokio::spawn(async move {
            let _ = $crate::utils::logging::log_internal(
                $crate::utils::logging::LogLevel::Trace,
                &message,
                module
            ).await;
        });
    }}
}

/// Log at debug level
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {{
        let module = $crate::utils::logging::get_module_name(file!());
        let message = format!($($arg)*);
        tokio::spawn(async move {
            let _ = $crate::utils::logging::log_internal(
                $crate::utils::logging::LogLevel::Debug,
                &message,
                module
            ).await;
        });
    }}
}

/// Log at info level
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {{
        let module = $crate::utils::logging::get_module_name(file!());
        let message = format!($($arg)*);
        tokio::spawn(async move {
            let _ = $crate::utils::logging::log_internal(
                $crate::utils::logging::LogLevel::Info,
                &message,
                module
            ).await;
        });
    }}
}

/// Log at warn level
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {{
        let module = $crate::utils::logging::get_module_name(file!());
        let message = format!($($arg)*);
        tokio::spawn(async move {
            let _ = $crate::utils::logging::log_internal(
                $crate::utils::logging::LogLevel::Warn,
                &message,
                module
            ).await;
        });
    }}
}

/// Log at error level
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {{
        let module = $crate::utils::logging::get_module_name(file!());
        let message = format!($($arg)*);
        tokio::spawn(async move {
            let _ = $crate::utils::logging::log_internal(
                $crate::utils::logging::LogLevel::Error,
                &message,
                module
            ).await;
        });
    }}
}