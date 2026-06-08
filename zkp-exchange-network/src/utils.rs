//! Utility functions for the ZKP operations

use crate::errors::{ZkpError, ZkpResult};
use sha2::{Digest,Sha256};
use std::time::{SystemTime,UNIX_EPOCH};


/// Get current unix timestamp
pub fn current_timestamp() -> u64 {
    SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs()

}

/// SHA-256 hash of data
pub fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())

}

/// convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> ZkpResult<Vec<u8>> {
    hex::decode(hex).map_err(|e|
    ZkpError::EncodingError(e.to_string()))
}

// Encode bytes to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}


/// Enocde bytes as base64

pub fn base64_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose,Engine};
    general_purpose::STANDARD.encode(data)
}

/// Decode base64 string
pub fn base64_decode(encoded: &str) -> ZkpResult<Vec<u8>> {
    use base64::{engine::general_purpose,Engine};
    general_purpose::STANDARD
    .decode(encoded)
    .map_err(|e| ZkpError::EncodingError(e.to_string()))
}

/// Validate timestamp is recent (within max_age seconds)
pub fn validate_timestamp(timestamp: u64 , max_age: u64) -> bool {
    let now = current_timestamp();
    now >= timestamp && (now - timestamp) <= max_age

}

/// Parse JSON value safely
pub fn safe_json_parse(json: &str) ->  ZkpResult<serde_json::Value> {
    serde_json::from_str(json).map_err(|e|
    ZkpError::SerializationError(e))

}

/// Serialization to JSON
pub fn to_json<T: serde::Serialize>(value: &T) -> ZkpResult<String> {
    serde_json::to_string(value).map_err(|e|
    ZkpError::SerializationError(e))
}

pub fn to_json_pretty<T:serde::Serialize>(value:&T) ->ZkpResult<String> {
    serde_json::to_string_pretty(value).map_err(|e|
    ZkpError::SerializationError(e))
}

/// Generate a random nonce for replay protection 

pub fn  generate_nonce() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8;32] = rng.gen();
    hex::encode(bytes)

}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sha256_hash() {
        let data = b"test";
        let hash = sha256_hash(data);
        assert_eq!(hash.len(),64);

    }

    #[test]
    fn test_base64_encoding() {
        let data = b"lhelow world";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded,data);

    }

    #[test]
    fn test_timestamp_validation() {
        let now = current_timestamp();
        assert!(validate_timestamp(now,60));
        assert!(!validate_timestamp(now-200,60));


    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_eq!(nonce1.len(),64);
        assert_ne!(nonce1,nonce2);

    }
}