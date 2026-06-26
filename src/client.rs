use crate::error::ShieldzError;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const VERSION: &str = "0.1.0";
const DEFAULT_BASE_URL: &str = "https://shieldz.cash/api/v1";

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn auto_idempotency_key() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("auto_{:x}{:x}", nanos, n)
}

fn retryable(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

pub struct Shieldz {
    api_key: String,
    base_url: String,
    agent: ureq::Agent,
    max_retries: u32,
}

impl Shieldz {
    pub fn new(api_key: impl Into<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .build();
        Self {
            api_key: api_key.into(),
            base_url: DEFAULT_BASE_URL.to_string(),
            agent,
            max_retries: 2,
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_string();
        self
    }

    pub fn with_max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    pub fn invoices(&self) -> Invoices<'_> {
        Invoices { client: self }
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<Value, ShieldzError> {
        let url = format!("{}{}", self.base_url, path);

        // Attach an idempotency key to a retryable POST so retries can't duplicate.
        let body = match body {
            Some(Value::Object(mut map)) if method == "POST" && self.max_retries > 0 => {
                if !map.contains_key("idempotency_key") {
                    map.insert("idempotency_key".into(), json!(auto_idempotency_key()));
                }
                Some(Value::Object(map))
            }
            other => other,
        };

        let mut attempt = 0u32;
        loop {
            let mut req = self
                .agent
                .request(method, &url)
                .set("Authorization", &format!("Bearer {}", self.api_key))
                .set("User-Agent", &format!("shieldz-rust/{}", VERSION));
            for (k, v) in query {
                req = req.query(k, v);
            }

            let result = match &body {
                Some(b) => req.send_json(b.clone()),
                None => req.call(),
            };

            match result {
                Ok(resp) => {
                    return resp.into_json::<Value>().or(Ok(json!({})));
                }
                Err(ureq::Error::Status(code, resp)) => {
                    if retryable(code) && attempt < self.max_retries {
                        std::thread::sleep(backoff(attempt));
                        attempt += 1;
                        continue;
                    }
                    let request_id = resp
                        .header("x-request-id")
                        .or_else(|| resp.header("cf-ray"))
                        .map(|s| s.to_string());
                    let v: Value = resp.into_json().unwrap_or_else(|_| json!({}));
                    let e = v.get("error").cloned().unwrap_or_else(|| json!({}));
                    return Err(ShieldzError {
                        status: code,
                        kind: e
                            .get("type")
                            .and_then(|x| x.as_str())
                            .unwrap_or("api_error")
                            .to_string(),
                        code: e
                            .get("code")
                            .and_then(|x| x.as_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        message: e
                            .get("message")
                            .and_then(|x| x.as_str())
                            .unwrap_or("Shieldz API error")
                            .to_string(),
                        param: e
                            .get("param")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string()),
                        request_id,
                    });
                }
                Err(ureq::Error::Transport(t)) => {
                    if attempt < self.max_retries {
                        std::thread::sleep(backoff(attempt));
                        attempt += 1;
                        continue;
                    }
                    return Err(ShieldzError {
                        status: 0,
                        kind: "connection_error".to_string(),
                        code: "network_error".to_string(),
                        message: t.to_string(),
                        param: None,
                        request_id: None,
                    });
                }
            }
        }
    }
}

fn backoff(attempt: u32) -> Duration {
    let ms = (500u64 * 2u64.pow(attempt)).min(8000);
    Duration::from_millis(ms)
}

pub struct Invoices<'a> {
    client: &'a Shieldz,
}

impl<'a> Invoices<'a> {
    pub fn create(&self, params: Value) -> Result<Value, ShieldzError> {
        self.client.request("POST", "/invoices", &[], Some(params))
    }

    pub fn retrieve(&self, id: &str) -> Result<Value, ShieldzError> {
        self.client
            .request("GET", &format!("/invoices/{}", id), &[], None)
    }

    pub fn list(&self, query: &[(&str, String)]) -> Result<Value, ShieldzError> {
        self.client.request("GET", "/invoices", query, None)
    }

    /// Collect every invoice, following the cursor across pages.
    pub fn list_all(&self, query: &[(&str, String)]) -> Result<Vec<Value>, ShieldzError> {
        let mut out = Vec::new();
        let mut starting_after: Option<String> = None;
        loop {
            let mut q: Vec<(&str, String)> = query.to_vec();
            if let Some(ref s) = starting_after {
                q.push(("starting_after", s.clone()));
            }
            let page = self.list(&q)?;
            let data = page
                .get("data")
                .and_then(|d| d.as_array())
                .cloned()
                .unwrap_or_default();
            for inv in &data {
                out.push(inv.clone());
            }
            let has_more = page
                .get("has_more")
                .and_then(|h| h.as_bool())
                .unwrap_or(false);
            if !has_more || data.is_empty() {
                return Ok(out);
            }
            starting_after = data
                .last()
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            if starting_after.is_none() {
                return Ok(out);
            }
        }
    }
}
