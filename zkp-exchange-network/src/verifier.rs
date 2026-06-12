//! Verifier module for validating zero knowledge proofs

use crate::errors::{ZkpError,ZkpResult};
use crate::types::{CircuitConfig,VerificationRequest,VerificationResult,ZkProof};
use crate::utils;


// The Verifier validates zero knowledge proofs
pub struct Verifier {
    circuits:std::collections::HashMap<String,CircuitConfig>,
    verification_keys:std::collections::HashMap<String,String>,

}

/// verification implements
impl Verifier {
    /// Create a new Verifier instance 
    pub fn new() -> Self {
        Self {
            circuits:std::collections::HashMap::new(),
            verification_keys:std::collections::HashMap::new(),
        }
    }

    /// Register a circuit with the verifier 
    pub fn register_circuit(&mut self,circuit:CircuitConfig) -> ZkpResult<()> {
        if self.circuits.contains_key(&circuit.id) {
            return Err(ZkpError::CircuitError(format!(
                "circuit {} already registered",
                circuit.id
            )));
        }
        self.circuits.insert(circuit.id.clone(),circuit);
        Ok(())
    }

    /// Load a configuration key for a circuit
    pub fn load_verification_key(&mut self,circuit_id:&str,key_data:String) -> ZkpResult<()> {

        // check if it contains circuit id already
        if !self.circuits.contains_key(circuit_id) {
            return Err(ZkpError::UnknownCircuit(circuit_id.to_string()));

        }

        // else
        self.verification_keys
            .insert(circuit_id.to_string(),key_data);
        Ok(())

    }

    /// Verify a zero-knowledge proof
    pub fn verify_proof(&self,request:VerificationRequest) -> ZkpResult<VerificationResult> {
        // Verify circuit exists
      let circuit = self
      .circuits
      .get(&request.proof.circuit_id)
      .ok_or_else(|| ZkpError::UnknownCircuit(request.proof.circuit_id.clone()))?;
    

    // Verify verification key is loaded 
    let _verification_key = self
    .verification_keys
    .get(&request.proof.circuit_id)
    .ok_or_else(|| {
        ZkpError::KeyError(format!(
            "Verification Key not loaded for {}",
            request.proof.circuit_id

        ))
    })?;

    // validate proof format 
    self.validate_proof_format(&request.proof)?;

    // check timestamp if max_age is specified
    if let Some(max_age) = request.max_age {
        if !utils::validate_timestamp(request.proof.timestamp,max_age) {
            return  Ok(VerificationResult {
                is_valid:false,
                message:"Proof is too old".to_string(),
                verified_at:utils::current_timestamp(),
                circuit_id:request.proof.circuit_id.clone(),
                public_signals:request.proof.public_signals.clone(),

            });
        }
    }

    // Verify public signals match expected (if provided)
    if let Some(expected_signals) = request.expected_signals {
        if request.proof.public_signals != expected_signals {
            return Ok(VerificationResult {
               is_valid:false,
               message:"Public signals do not match expected values".to_string(),
               verified_at:utils::current_timestamp(),
               circuit_id:request.proof.circuit_id.clone(),
               public_signals:request.proof.public_signals.clone(),
            });
        }
    }

    // Perform cryptographic verification
    let is_valid = self.verify_proof_cryptography(&request.proof,circuit)?;
    let result = VerificationResult {
        is_valid,
        message:if is_valid {
            "Proof is valid".to_string()

        } else {
            "Proof verification failed".to_string()
        },
        verified_at:utils::current_timestamp(),
        circuit_id:request.proof.circuit_id.clone(),
        public_signals:request.proof.public_signals.clone(),
    };

    Ok(result)

  } 

   /// Validate proof format
   fn validate_proof_format(&self,proof:&ZkProof) -> ZkpResult<()> {
    if proof.proof_data.is_empty() {
        return Err(ZkpError::InvalidProofFormat("Proof data is empty".to_string()));
    }
    if proof.public_signals.is_empty() {
        return Err(ZkpError::InvalidProofFormat("Proof has no public signals".to_string()));

    }

    if proof.circuit_id.is_empty() {
        return Err(ZkpError::InvalidProofFormat("Circuit ID is empty".to_string()));
    }

    // Try to decode the proof data from base64

    utils::base64_decode(&proof.proof_data)?;


    Ok(())
   }


   /// Peform cryptographic verification  just demo for in this code base for testing
   fn verify_proof_cryptography(&self,proof:&ZkProof,_circuit:&CircuitConfig) -> ZkpResult<bool> {
    // In a real implementation , this would :
    // 1.Decode the proof 
    // 2.load the verification key 
    // 3. call the actual verifier (e.g,via snarkjs ,wasm,groth16)
    // 4.Return verification result

    // for now ,perform basic structural validation

    let proof_data = utils::base64_decode(&proof.proof_data)?;

    let _parsed:serde_json::Value = serde_json::from_slice(&proof_data)?;


    // Simulate verification with  mock logic 
    // In reality , this would use elliptic curve match
    Ok(true)
   }

   /// Quick verify without full validation
   pub fn quick_verify(&self,proof:&ZkProof) -> ZkpResult<bool> {
    // Verify circuit exists
    if !self.circuits.contains_key(&proof.circuit_id) {
        return Err(ZkpError::UnknownCircuit(proof.circuit_id.clone()));

    }
   // Verify verification key is loaded 
   if !self.verification_keys.contains_key(&proof.circuit_id) {
    return Err(ZkpError::KeyError(format!(
        "Verification key not loaded for {} ",
        proof.circuit_id
    )));


   }


    // Basic format validation
    self.validate_proof_format(proof)?;

    Ok(true)

   }

   /// Get registered circuits
   pub fn get_circuits(&self) -> Vec<CircuitConfig> {
     self.circuits.values().cloned().collect()
   }

   /// Get circuit by ID 
   pub fn get_circuit(&self,circuit_id:&str) -> Option<CircuitConfig> {
    self.circuits.get(circuit_id).cloned()
   }

}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    fn create_test_circuit() -> CircuitConfig {
        CircuitConfig {
            id:"test_circuit".to_string(),
            name:"Test Circuit".to_string(),
            description:"A test circuit".to_string(),
            num_private_inputs:2,
            num_public_inputs:1,
            num_constraints:100,
            version:"1.0".to_string(),

        }
    }

    // create a test proof 
    fn create_test_proof() -> ZkProof {
        ZkProof {
            proof_data:utils::base64_encode(
                serde_json::json!({
                    "pi_a":["1","2"],
                    "pi_b":[["3","4"],["5","6"]],
                    "pi_c":["7","8"],
                    "protocol":"groth16"


                })
                .to_string()
                .as_bytes(),

            ),
            public_signals:vec!["signal1".to_string()],
            circuit_id:"test_circuit".to_string(),
            timestamp:utils::current_timestamp(),
            signature:None,
            version:"1.0".to_string(),

        }
    }

    #[test]
    fn test_verifier_creation() {
        let verifier =  Verifier::new();
        assert_eq!(verifier.get_circuits().len(),0);

    }

    #[test]
    fn test_register_circuit() {
        let mut verifier  = Verifier::new();
        let circuit = create_test_circuit();
        assert!(verifier.register_circuit(circuit).is_ok());
        assert_eq!(verifier.get_circuits().len(),1);

    }
    // test loading verification key
    #[test]
    fn test_verify_proof_missing_key() {
        let mut verifier = Verifier::new();
        let circuit = create_test_circuit();
        verifier.register_circuit(circuit).unwrap();

        // generate the test proof
        let proof = create_test_proof();
        let request = VerificationRequest {
            proof,
            expected_signals:None,
            max_age:None,

        };


        // verify the result 
        let result = verifier.verify_proof(request);

        assert!(result.is_err());

    }

    // test function for proof verification success
    #[test]
    fn test_verify_proof_success() {
        let mut verifier = Verifier::new();
        let circuit = create_test_circuit();
        verifier.register_circuit(circuit).unwrap();
        verifier.load_verification_key("test_circuit","dummy_key".to_string()).unwrap();


        // generate a proof
        let proof = create_test_proof();
        let request = VerificationRequest {
            proof,
            expected_signals:None,
            max_age:None,

        };

        let result = verifier.verify_proof(request);
        assert!(result.is_ok());
        // unwrap the result
        let verification_result = result.unwrap();
        assert!(verification_result.is_valid);

    }

    #[test]
    fn test_quick_verify(){
        let mut verifier = Verifier::new();
        let circuit = create_test_circuit();
        verifier.register_circuit(circuit).unwrap();
        verifier.load_verification_key("test_circuit","dummy_key".to_string()).unwrap();

        let proof = create_test_proof();
        let result = verifier.quick_verify(&proof);
        assert!(result.is_ok());

    }

    #[test]
    fn test_timestamp_validation() {
        let mut verifier = Verifier::new();
        let circuit = create_test_circuit();
        verifier.register_circuit(circuit).unwrap();
        verifier.load_verification_key("test_circuit","dummy_key".to_string()).unwrap();


        // create the proof with old timestamp
        let mut proof = create_test_proof();

        proof.timestamp = utils::current_timestamp() - 1000;

        let request = VerificationRequest {
            proof,
            expected_signals:None,
            max_age:Some(60),

        };

        let result = verifier.verify_proof(request);
        assert!(result.is_ok());
        let verification_result = result.unwrap();
        assert!(!verification_result.is_valid);


    }
}