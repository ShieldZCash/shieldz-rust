# shieldz

[![CI](https://github.com/ShieldZCash/shieldz-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/ShieldZCash/shieldz-rust/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/shieldz.svg)](https://crates.io/crates/shieldz)
[![docs.rs](https://img.shields.io/docsrs/shieldz)](https://docs.rs/shieldz)

Official Rust SDK for [**Shieldz**](https://shieldz.cash) — non-custodial crypto payments with **$0 fees**.

Accept **USDC/USDT** across Base, Arbitrum, Optimism, Polygon, and Ethereum, plus native **Bitcoin** and shielded **Zcash**. Funds settle straight to your own wallet — Shieldz never holds them, and never asks for your keys.

## Install

```toml
[dependencies]
shieldz = "0.1"
```

## Quickstart

```rust
use shieldz::Shieldz;
use serde_json::json;

let shieldz = Shieldz::new(std::env::var("SHIELDZ_API_KEY")?);

let invoice = shieldz.invoices().create(json!({
    "amount_usd_cents": 5000,        // $50.00
    "memo": "Order #1234",
    "metadata": { "order_id": "1234" },
}))?;

println!("{} {}", invoice["status"], invoice["pay_url"]);
// → send your customer to invoice["pay_url"] (the hosted checkout)
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Retrieve, list & auto-paginate

```rust
let inv = shieldz.invoices().retrieve("Qgvz8WQw0mnv2M8")?;

let page = shieldz.invoices().list(&[("limit", "20".into()), ("status", "paid".into())])?;

let all = shieldz.invoices().list_all(&[("status", "paid".into())])?; // follows the cursor
```

Retryable POSTs get an auto `idempotency_key` so a retried create can't duplicate; pass your own to tie it to an order.

## Webhooks

Verify against the **raw request body**:

```rust
use shieldz::{construct_event, VerifyOptions};

let event = construct_event(
    raw_body,                        // &[u8]
    signature_header,                // X-Shieldz-Signature
    &signing_secret,                 // whsec_…
    &VerifyOptions::default(),       // 300s tolerance
)?;

if event["type"] == "invoice.paid" {
    // fulfill — dedupe on X-Shieldz-Delivery (at-least-once)
}
# Ok::<(), shieldz::SignatureVerificationError>(())
```

`verify_signature(...)` is also available if you just want a `Result<(), _>`. During the 24h after a secret rotation the header carries both signatures and either matches.

## Errors

Any non-2xx returns `ShieldzError { status, kind, code, message, param, request_id }`.

## Links

- Docs / API quickstart: https://shieldz.cash/docs
- Is it safe? (non-custodial proof): https://shieldz.cash/verify
- Node SDK: https://github.com/ShieldZCash/shieldz-sdk · Python SDK: https://github.com/ShieldZCash/shieldz-python

## License

MIT © Deniz Yanbollu / Shieldz
