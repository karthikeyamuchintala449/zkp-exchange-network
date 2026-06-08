//! Core Data types for ZKP Operations
use serde::{Deserialize,Serialize};

/// A Zero-knowledge proof with associated metadata

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]
pub struct ZkProof {
    /// Serialized proof (typically base64 encoded)
    pub proof_data: String,

    /// Public signals/inputs that are revealed 
    pub public_signals: Vec<String>,

    /// Identifier for the circuit used to generate this proof 
    pub circuit_id:String,

    /// Timestamp when the proof was generated (Unix timestamp)

    pub timestamp:u64,

    /// Optional signature for authenticity verification

    pub signature: Option<String>,
    
    /// Proof format version for compatibility

    pub version: String,

}

/// Proof packet for offline transmission 
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ProofPacket {
    /// TThe proof itself
    pub proof:ZkProof,
    /// Metadata for transmission
    pub metadata:TransmissionMetadata,

}

/// Metadata for proof transmission
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct TransmissionMetadata {
    /// Transmission channel used 
    pub channel:TransmissionChannel,

    /// Optional nonce for replay protection
    pub nonce : Option<String>,

    /// Compressions used (if any)
    pub compression:Option<String>,

    /// receiver pubnlic key (optinal)
    pub receiver_pubkey:Option<String>,

    
}

/// Supported transmission channels
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub enum TransmissionChannel {
    QrCode,
    BluetoothLe,
    UltrasonicAudio,
    Nfc,
    DirectTransfer,

}


/// Circuit configuration
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct CircuitConfig {
    /// Unique identifier for the circuit
    pub id:String,

    /// Human-readable name
    pub name: String,

    /// circuit description
    pub description:String,

    /// Number of private inputs
    pub num_private_inputs:usize,

    /// Number of public inputs (signals)
    pub num_public_inputs: usize,

    /// Circuit constraints count (approximate)
    pub num_constraints: usize,

    /// Metadata/version

    pub version: String,


}

/// Proof requiest specifying what to prove 
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ProofRequest {
    /// Cricuit to use for proof generation
    pub circuit_id:String,
    /// Private inputs (not revealed)
    pub private_inputs:serde_json::Value,

    /// public inputs (revealed)
    pub  public_inputs:serde_json::Value,

    /// optional metadata
    pub metadata:Option<serde_json::Value>,

}

/// Verification request for a proof 
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct VerificationRequest {
    /// The proof to verify
    pub proof:ZkProof,

    /// expected public signals (for double-checking)
    pub expected_signals:Option<Vec<String>>,

    /// Maximum acceptable timestamp age in seconds
    pub max_age:Option<u64>,

}

/// Verification Result
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct VerificationResult {
    /// whether the proof is valid 
    pub is_valid:bool,

    //// Detaild message
    pub message:String,
    
    /// Verification timestamp
    pub verified_at:u64,

    /// Circuit used for verification
    
    pub circuit_id:String,



    /// public signals that were revealed

    pub public_signals:Vec<String>,

}

/// key material for zkp operations
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct KeyMaterial {
    /// key identifier

    pub key_id:String,

    /// key types 
    pub key_type:KeyType,


    /// Base64-encoded key material

    pub key_data:String,

    /// Associated circuit

    pub circuit_id:String,

    /// creation timesstamp
    pub created_at:u64,

    /// Expirartion timestamp (optonal)
    pub expires_at:Option<u64>,


}


/// types of  keys for Zkp

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub enum KeyType {
    /// proving key (secret,for proof generation)
    ProvingKey,


    /// Verification key (public,for proof verification)
    VerificationKey,


    /// Keypair (contains both proving and verification keys)

    Keypair,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_zkproof_serialization() {
        let proof =ZkProof {
            proof_data: "test_proof_data".to_string(),
            public_signals: vec!["signal1".to_string()],
            circuit_id:"age_proof".to_string(),
            timestamp:1234567890,
            signature:None,
            version:"1.0".to_string(),

        };
        let json  = serde_json::to_string(&proof).unwrap();
        let deserialized: ZkProof = serde_json::from_str(&json).unwrap();

        assert_eq!(proof,deserialized);

    }
}