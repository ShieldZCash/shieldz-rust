use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct SignatureVerificationError(pub String);

impl fmt::Display for SignatureVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signature verification failed: {}", self.0)
    }
}
impl std::error::Error for SignatureVerificationError {}

pub struct VerifyOptions {
    /// Max allowed clock skew in seconds. Default 300.
    pub tolerance_seconds: i64,
    /// Override "now" (unix seconds), for testing.
    pub now: Option<i64>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            tolerance_seconds: 300,
            now: None,
        }
    }
}

fn err(m: &str) -> SignatureVerificationError {
    SignatureVerificationError(m.to_string())
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Verify a Shieldz webhook signature. Pass the raw request body.
/// Header: `t=<unix>,v1=<hex>[,v1=<hex>]`; signed payload is `<t>.<body>`.
pub fn verify_signature(
    raw_body: &[u8],
    signature_header: &str,
    signing_secret: &str,
    opts: &VerifyOptions,
) -> Result<(), SignatureVerificationError> {
    if signature_header.is_empty() {
        return Err(err("missing signature header"));
    }
    if signing_secret.is_empty() {
        return Err(err("missing signing secret"));
    }

    let parts: Vec<&str> = signature_header.split(',').map(|p| p.trim()).collect();
    let t = parts.iter().find_map(|p| p.strip_prefix("t="));
    let sigs: Vec<&str> = parts.iter().filter_map(|p| p.strip_prefix("v1=")).collect();
    let t = match (t, sigs.is_empty()) {
        (Some(t), false) => t,
        _ => return Err(err("malformed signature header")),
    };

    let ts: i64 = t.parse().map_err(|_| err("malformed timestamp"))?;
    let now = opts.now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    });
    if (now - ts).abs() > opts.tolerance_seconds {
        return Err(err("timestamp outside tolerance"));
    }

    let mut mac =
        HmacSha256::new_from_slice(signing_secret.as_bytes()).map_err(|_| err("invalid key"))?;
    mac.update(format!("{}.", t).as_bytes());
    mac.update(raw_body);
    let expected = hex::encode(mac.finalize().into_bytes());

    if sigs.iter().any(|s| constant_time_eq(s, &expected)) {
        Ok(())
    } else {
        Err(err("no matching signature"))
    }
}

/// Verify the signature and return the parsed JSON event.
pub fn construct_event(
    raw_body: &[u8],
    signature_header: &str,
    signing_secret: &str,
    opts: &VerifyOptions,
) -> Result<serde_json::Value, SignatureVerificationError> {
    verify_signature(raw_body, signature_header, signing_secret, opts)?;
    serde_json::from_slice(raw_body).map_err(|e| err(&format!("invalid json: {}", e)))
}
