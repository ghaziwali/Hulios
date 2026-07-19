use thiserror::Error;

#[derive(Debug, Error)]
pub enum HuliosError {
    #[error("Fwmark conflict: {0}")]
    FwmarkConflict(String),
    #[error("Tor bootstrap timed out")]
    BootstrapTimeout,
}
