use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use shieldz::{construct_event, verify_signature, Shieldz, VerifyOptions};

type HmacSha256 = Hmac<Sha256>;

struct Recorded {
    method: String,
    path: String,
    auth: String,
    body: String,
}

fn read_request(stream: &mut TcpStream) -> Recorded {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        let n = stream.read(&mut tmp).unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).to_string();
            let cl = head
                .lines()
                .find_map(|l| {
                    l.to_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            let mut body = buf[pos + 4..].to_vec();
            while body.len() < cl {
                let n = stream.read(&mut tmp).unwrap();
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&tmp[..n]);
            }
            let first = head.lines().next().unwrap_or("");
            let mut it = first.split_whitespace();
            let method = it.next().unwrap_or("").to_string();
            let path = it.next().unwrap_or("").to_string();
            let auth = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    if k.trim().eq_ignore_ascii_case("authorization") {
                        Some(v.trim().to_string())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
            return Recorded {
                method,
                path,
                auth,
                body: String::from_utf8_lossy(&body).to_string(),
            };
        }
    }
    Recorded {
        method: String::new(),
        path: String::new(),
        auth: String::new(),
        body: String::new(),
    }
}

fn respond(stream: &mut TcpStream, status: u16, body: &str) {
    let resp = format!(
        "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
}

fn start_mock() -> (String, Arc<Mutex<Vec<Recorded>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let recorded = Arc::new(Mutex::new(Vec::<Recorded>::new()));
    let rec = recorded.clone();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let mut stream = match conn {
                Ok(s) => s,
                Err(_) => continue,
            };
            let r = read_request(&mut stream);
            let invoice =
                json!({"id":"inv_1","object":"invoice","amount_usd_cents":5000,"status":"pending"});
            if r.method == "POST" && r.path.starts_with("/invoices") {
                let parsed: serde_json::Value = serde_json::from_str(&r.body).unwrap_or(json!({}));
                if parsed["amount_usd_cents"].as_i64().unwrap_or(0) < 100 {
                    respond(&mut stream, 400, &json!({"error":{"type":"invalid_request","code":"invalid_amount","message":"too small","param":"amount_usd_cents"}}).to_string());
                } else {
                    respond(&mut stream, 201, &invoice.to_string());
                }
            } else if r.method == "GET" && r.path.starts_with("/invoices/inv_1") {
                respond(&mut stream, 200, &invoice.to_string());
            } else if r.method == "GET" && r.path.starts_with("/invoices") {
                respond(
                    &mut stream,
                    200,
                    &json!({"object":"list","data":[invoice],"has_more":false}).to_string(),
                );
            } else {
                respond(
                    &mut stream,
                    404,
                    &json!({"error":{"code":"not_found","type":"invalid_request","message":"no"}})
                        .to_string(),
                );
            }
            rec.lock().unwrap().push(r);
        }
    });
    (url, recorded)
}

#[test]
fn create_retrieve_list() {
    let (url, rec) = start_mock();
    let s = Shieldz::new("sk_test").with_base_url(&url);
    let inv = s
        .invoices()
        .create(json!({"amount_usd_cents":5000,"memo":"x"}))
        .unwrap();
    assert_eq!(inv["id"], "inv_1");
    let got = s.invoices().retrieve("inv_1").unwrap();
    assert_eq!(got["id"], "inv_1");
    let page = s.invoices().list(&[("limit", "10".into())]).unwrap();
    assert_eq!(page["object"], "list");

    let r = rec.lock().unwrap();
    let post = r.iter().find(|x| x.method == "POST").unwrap();
    assert_eq!(post.auth, "Bearer sk_test");
    let body: serde_json::Value = serde_json::from_str(&post.body).unwrap();
    assert!(body["idempotency_key"]
        .as_str()
        .unwrap()
        .starts_with("auto_"));
}

#[test]
fn error_envelope() {
    let (url, _rec) = start_mock();
    let s = Shieldz::new("sk_test")
        .with_base_url(&url)
        .with_max_retries(0);
    let err = s
        .invoices()
        .create(json!({"amount_usd_cents":1}))
        .unwrap_err();
    assert_eq!(err.status, 400);
    assert_eq!(err.code, "invalid_amount");
    assert_eq!(err.param.as_deref(), Some("amount_usd_cents"));
}

#[test]
fn list_all_collects() {
    let (url, _rec) = start_mock();
    let s = Shieldz::new("sk_test").with_base_url(&url);
    let all = s.invoices().list_all(&[]).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["id"], "inv_1");
}

const SECRET: &str = "whsec_test";

fn sign(body: &str, secret: &str, t: i64) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{}.{}", t, body).as_bytes());
    format!("t={},v1={}", t, hex::encode(mac.finalize().into_bytes()))
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn webhook_valid() {
    let body = r#"{"type":"invoice.paid","id":"inv_1"}"#;
    let h = sign(body, SECRET, now());
    assert!(verify_signature(body.as_bytes(), &h, SECRET, &VerifyOptions::default()).is_ok());
    let ev = construct_event(body.as_bytes(), &h, SECRET, &VerifyOptions::default()).unwrap();
    assert_eq!(ev["type"], "invoice.paid");
}

#[test]
fn webhook_rotation_multiple_v1() {
    let body = r#"{"type":"invoice.paid"}"#;
    let t = now();
    let good = sign(body, SECRET, t);
    let good_hex = good.split("v1=").nth(1).unwrap();
    let header = format!("t={},v1={},v1={}", t, "0".repeat(64), good_hex);
    assert!(verify_signature(body.as_bytes(), &header, SECRET, &VerifyOptions::default()).is_ok());
}

#[test]
fn webhook_rejections() {
    let body = r#"{"type":"invoice.paid"}"#;
    let h = sign(body, SECRET, now());
    // tampered
    assert!(verify_signature(
        format!("{} ", body).as_bytes(),
        &h,
        SECRET,
        &VerifyOptions::default()
    )
    .is_err());
    // wrong secret
    assert!(verify_signature(
        body.as_bytes(),
        &h,
        "whsec_other",
        &VerifyOptions::default()
    )
    .is_err());
    // stale
    let old = sign(body, SECRET, now() - 3600);
    assert!(verify_signature(body.as_bytes(), &old, SECRET, &VerifyOptions::default()).is_err());
    // malformed
    for bad in ["", "garbage", "v1=abc"] {
        assert!(verify_signature(body.as_bytes(), bad, SECRET, &VerifyOptions::default()).is_err());
    }
}

#[test]
fn webhook_custom_now_tolerance() {
    let body = r#"{"x":1}"#;
    let t = 1_000_000;
    let h = sign(body, SECRET, t);
    let opts = VerifyOptions {
        tolerance_seconds: 60,
        now: Some(t + 10),
    };
    assert!(verify_signature(body.as_bytes(), &h, SECRET, &opts).is_ok());
}
