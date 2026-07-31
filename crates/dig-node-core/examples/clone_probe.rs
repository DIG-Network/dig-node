//! TEMPORARY diagnostic probe (#1886): issue the §21.9-signed `GET /stores/{id}/module`
//! exactly as `DigClient::clone_store` does, and print the status AND body.
//! Deleted before the PR is finalized.

use digstore_core::Bytes32;
use digstore_crypto::bls::SecretKey;

#[tokio::main]
async fn main() {
    let store_hex = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "1426d9064bb59353e2ad3845c1d250af1f75476a6d4d85f2c4d6b90696359907".into());
    let path = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "module".into());
    let store_id = Bytes32::from_hex(&store_hex).expect("64-hex store id");

    let (seed, pk) = digstore_remote::identity::load_or_create_seed().expect("identity");
    let sk = SecretKey::from_seed(&seed);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).unwrap();
    let method = if path == "module" { "module" } else { "fetch" };
    let msg = digstore_crypto::request_signing_message(method, &store_id, ts, &nonce);
    let sig = sk.sign(&msg);

    let url = if path == "module" {
        { let r = std::env::var("PROBE_ROOT").unwrap_or_default(); if r.is_empty() { format!("https://rpc.dig.net/stores/{store_hex}/module") } else { format!("https://rpc.dig.net/stores/{store_hex}/module?root={r}") } }
    } else {
        format!("https://rpc.dig.net/stores/{store_hex}")
    };
    println!("identity pk = {}", pk.to_hex());
    println!("GET {url}");
    let http = reqwest::Client::builder()
        .user_agent("dig-node/0.1")
        .build()
        .unwrap();
    let resp = http
        .request(if std::env::var("PROBE_HEAD").is_ok() { reqwest::Method::HEAD } else { reqwest::Method::GET }, &url)
        .header("X-Dig-Identity", pk.to_hex())
        .header("X-Dig-Timestamp", ts.to_string())
        .header("X-Dig-Nonce", hex::encode(nonce))
        .header("X-Dig-Auth", hex::encode(sig.to_bytes().0))
        .send()
        .await
        .expect("send");
    println!("status = {}", resp.status());
    for (k, v) in resp.headers() {
        println!("  {k}: {v:?}");
    }
    let body = resp.bytes().await.unwrap();
    println!("body ({} bytes): {}", body.len(), String::from_utf8_lossy(&body[..body.len().min(2000)]));
}
