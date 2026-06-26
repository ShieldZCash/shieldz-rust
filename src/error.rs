use std::fmt;

/// Returned for any non-2xx response (status 0 for connection/timeout errors).
#[derive(Debug, Clone)]
pub struct ShieldzError {
    pub status: u16,
    pub kind: String,
    pub code: String,
    pub message: String,
    pub param: Option<String>,
    pub request_id: Option<String>,
}

impl fmt::Display for ShieldzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ShieldzError {} {}/{}: {}",
            self.status, self.kind, self.code, self.message
        )
    }
}

impl std::error::Error for ShieldzError {}
