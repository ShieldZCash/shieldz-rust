//! Official Rust SDK for [Shieldz](https://shieldz.cash) — non-custodial crypto
//! payments. Create invoices, accept USDC/USDT/BTC/ZEC, and verify webhooks.
//!
//! ```no_run
//! use shieldz::Shieldz;
//! use serde_json::json;
//!
//! let shieldz = Shieldz::new(std::env::var("SHIELDZ_API_KEY").unwrap());
//! let invoice = shieldz.invoices().create(json!({
//!     "amount_usd_cents": 5000,
//!     "memo": "Order #1234",
//! }))?;
//! println!("{}", invoice["pay_url"]);
//! # Ok::<(), shieldz::ShieldzError>(())
//! ```
#![allow(clippy::result_large_err)]

mod client;
mod error;
mod webhooks;

pub use client::{Invoices, Shieldz};
pub use error::ShieldzError;
pub use webhooks::{construct_event, verify_signature, SignatureVerificationError, VerifyOptions};
