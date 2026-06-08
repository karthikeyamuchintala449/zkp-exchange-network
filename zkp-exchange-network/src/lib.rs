//! ZKP Exchange Network Library
//! 
//! A production-ready library for generating, transmitting, and verifying
//! zero-knowledge proofs entirely offline without exposing sensitive data.

pub mod types;
pub mod errors;
pub mod utils;
pub mod circuits;
pub mod keys;
pub mod prover;
pub mod verifier;
pub mod exchange;

// Re-export commonly used types
pub use types::{
    ZkProof, ProofPacket, ProofRequest, VerificationRequest, VerificationResult,
    CircuitConfig, TransmissionChannel, KeyMaterial, KeyType,
};
