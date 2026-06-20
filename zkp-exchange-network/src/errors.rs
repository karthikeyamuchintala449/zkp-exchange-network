//! Error types for ZKP Operations

use thiserror::Error;

#[derive(Error,Debug)]
pub enum ZkpError {
    #[error("Proof verification failed:{0}")]
    VerificationFailed(String),

    /// invalidfromat errror
    #[error("Invalid proof format:{0}")]
    InvalidProofFormat(String),

    #[error("Circuit not found: {0}")]
    CircuitNotFound(String),

    #[error("Proof generation failed: {0}")]
    ProofGeneration(String),

    #[error("Verification failed: {0}")]
    Verification(String),

    // 2. Add this variant to automatically handle serde_json errors
   

    /// circuit error
    #[error("Circuit error:{0}")]
    CircuitError(String),

    /// no circuits registered
    #[error("No circuits registered:{0}")]
    NoCircuitsRegistered(&'static str),

    #[error("WASM Runtime initialization error: {0}")]
    WasmInit(String),
    #[error("Witness generation failed: {0}")]
    WitnessGeneration(String),
    #[error("Invalid Proving Key (zkey) format: {0}")]
    InvalidZkey(String),
    #[error("Proof generation failed: {0}")]
    ProofGeneration(String),
    #[error("Serialization failed: {0}")]
    Serialization(String)
    /// keyerror
    #[error("Key management error:{0}")]
    KeyError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// encdoign error
    #[error("encoding error:{0}")]
     EncodingError(String),

     /// invalid input
     #[error("Invalid input:{0}")]
     InvalidInput(String),

     /// unknown circuit
     #[error("Unknown Circuit:{0}")]
     UnknownCircuit(String),

     /// Proof generation failed
     #[error("Proof generation failed:{0}")]
     ProofGenerationFailed(String),

     /// public signal mismatch

     #[error("Public signal mismatch:{0}")]
     PublicSignalMismatch(String),

     /// io error
     #[error("IO error:{0}")]
     IoError(#[from] std::io::Error),

     // internal error
     #[error("Intrenal error:{0}")]
     InternalError(String),



}

pub type ZkpResult<T> = Result<T, ZkpError>;


// unit test
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_failed_error() {
        let error = ZkpError::VerificationFailed("Proof does not match".to_string());
        assert_eq!(error.to_string(), "Proof verification failed:Proof does not match");
    }

    #[test]
    fn test_invalid_proof_format_error() {
        let error = ZkpError::InvalidProofFormat("Missing field".to_string());
        assert_eq!(error.to_string(), "Invalid proof format:Missing field");
    }
}
