//! Prover module for generating zero-knowledge proofs
use crate::errors::{ZkpError,ZkpResult};
use crate::types::{CircuitConfig,ProofRequest,ZkProof};
use crate::utils;
use serde_json::json;


/// The Prover genertes zero-knowledge proofs

pub struct Prover {
    circuits: std::collections::HashMap<String,CircuitConfig>,
    proving_keys: std::collections::HashMap<String,String>,

}

impl Prover {
    /// Create a new Prover instance
    pub fn new() -> Self {
        Self {
            circuits: std::collections::HashMap::new(),
            proving_keys: std::collections::HashMap::new(),
            
        }
    }


    /// Register a circuit with the prover
    pub fn register_circuit(&mut self,circuit:CircuitConfig) -> ZkpResult<()> {
        if self.circuits.contains_key(&circuit.id) {
            return Err(ZkpError::CircuitError(format!(
                "Cicruit {} already registered",
                circuit.id
            )));

        }
        self.circuits.insert(circuit.id.clone(),circuit);
        Ok(())
    }

    /// Load a proving key for a circuit
    pub fn load_proving_key(&mut self,circuit_id:&str,key_data: String) -> ZkpResult<()> {
        if !self.circuits.contains_key(circuit_id) {
            return Err(ZkpError::UnknownCircuit(circuit_id.to_string()));

        }
        self.proving_keys.insert(circuit_id.to_string(),key_data);
        Ok(())
    }


    /// Generate a zero-knowledge proof 
    pub fn generate_proof(&self,request:ProofRequest) -> ZkpResult<ZkProof> {
        // Verify circuit exists
        let circuit = self
        .circuits
        .get(&request.circuit_id)
        .ok_or_else(|| ZkpError::UnknownCircuit(request.circuit_id.clone()))?;

        // Verify proving key is loaded 
        let _proving_key = self
        .proving_keys
        .get(&request.circuit_id)
        .ok_or_else(|| {
            ZkpError::KeyError(format!(
                "Proving Key not loaded for {}",
                request.circuit_id
            ))
        })?;

        // Validate inputs 9570446067
        self.validate_inputs(&request,circuit)?;

        // simulate proof generation (in production , this world call actuall zkp  prover)
        let proof_data = self.simulate_proof_generation(&request)?;

        // Extract public signals from public inputs
        let public_signals = self.extract_public_signals(&request.public_inputs)?;


        // Crate the proof 
        let proof = ZkProof {
            proof_data,
            public_signals,
            circuit_id:request.circuit_id.clone(),
            timestamp:utils::current_timestamp(),
            signature:None,
            version:"1.0".to_string(),


        };

        Ok(proof)

    }

    /// Validata proof request inputs
    fn validate_inputs(&self,request:&ProofRequest,circuit:&CircuitConfig) -> ZkpResult<()> {
        // Validate private inputs count 
        if let serde_json::Value::Object(obj) = &request.private_inputs {
            if obj.len() != circuit.num_private_inputs {
                return Err(ZkpError::InvalidInput(format!(
                    "Expected {} private inputs, got {} ",
                    circuit.num_private_inputs,
                    obj.len()
                )));
            }
        } else {
            return Err(ZkpError::InvalidInput("Private inputs must be a JSON object".to_string(),
        ));
        }

        // Validate public inpust count 
        if let serde_json::Value::Object(obj) = &request.public_inputs {
            if obj.len() != circuit.num_public_inputs
            {
                return Err(ZkpError::InvalidInput(format!(
                    "Expected {} public inputs ,got {}",
                    circuit.num_public_inputs,
                    obj.len()
                )));
            }
        } else {
            return Err(ZkpError::InvalidInput(
                "Public inputs must be a JSON object".to_string(),
            ));
        }
        Ok(())
    }
      /// Simulate proof generation (placeholder for actual ZK-SNARK prover)
    fn simulate_proof_generation(&self, request: &ProofRequest) -> ZkpResult<String> {
        // In a real implementation, this would:
        // 1. Create witness from inputs
        // 2. Call the actual prover (e.g., via SnarkJS WASM or Groth16)
        // 3. Return serialized proof

        // For now, create a deterministic mock proof based on inputs
        let input_data = format!("{}{}", request.private_inputs, request.public_inputs);
        let proof_hash = utils::sha256_hash(input_data.as_bytes());

        // Create a mock proof structure
        let mock_proof = json!({
            "pi_a": [
                "123456789012345678901234567890123456789012345678901234567890",
                "987654321098765432109876543210987654321098765432109876543210"
            ],
            "pi_b": [
                [
                    "111111111111111111111111111111111111111111111111111111111111",
                    "222222222222222222222222222222222222222222222222222222222222"
                ],
                [
                    "333333333333333333333333333333333333333333333333333333333333",
                    "444444444444444444444444444444444444444444444444444444444444"
                ]
            ],
            "pi_c": [
                "555555555555555555555555555555555555555555555555555555555555",
                "666666666666666666666666666666666666666666666666666666666666"
            ],
            "protocol": "groth16",
            "curve": "bls12381",
            "hash": proof_hash
        });

        // Encode as base64
        let proof_json = serde_json::to_string(&mock_proof)?;
        Ok(utils::base64_encode(proof_json.as_bytes()))
    }

    /// Extract public signals from public inputs 
     fn extract_public_signals(&self, public_inputs: &serde_json::Value) -> ZkpResult<Vec<String>> {
        match public_inputs {
            serde_json::Value::Object(obj) => {
                let signals: Vec<String> = obj
                    .values()
                    .filter_map(|v| v.as_str().map(String::from).or_else(|| Some(v.to_string())))
                    .collect();
                Ok(signals)
            }
            _ => Err(ZkpError::InvalidInput(
                "Public inputs must be a JSON object".to_string(),
            )),
        }
    }

    /// Get registered circuits
    pub fn get_circuits(&self) -> Vec<CircuitConfig> {
        self.circuits.values().cloned().collect()
    }

    /// Get circuit by ID 
    pub fn get_circuit(&self,circuit_id:&str) -> Option<CircuitConfig>{
        self.circuits.get(circuit_id).cloned()
    }
}

impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_circuit() -> CircuitConfig {
        CircuitConfig {
            id: "test_circuit".to_string(),
            name: "Test Circuit".to_string(),
            description: "A test circuit".to_string(),
            num_private_inputs: 2,
            num_public_inputs: 1,
            num_constraints: 100,
            version: "1.0".to_string(),
        }
    }

    #[test]
    fn test_prover_creation() {
        let prover = Prover::new();
        assert_eq!(prover.get_circuits().len(), 0);
    }

    #[test]
    fn test_register_circuit() {
        let mut prover = Prover::new();
        let circuit = create_test_circuit();
        assert!(prover.register_circuit(circuit).is_ok());
        assert_eq!(prover.get_circuits().len(), 1);
    }

    #[test]
    fn test_duplicate_circuit_registration() {
        let mut prover = Prover::new();
        let circuit = create_test_circuit();
        assert!(prover.register_circuit(circuit.clone()).is_ok());
        assert!(prover.register_circuit(circuit).is_err());
    }

    #[test]
    fn test_load_proving_key() {
        let mut prover = Prover::new();
        let circuit = create_test_circuit();
        prover.register_circuit(circuit).unwrap();
        let result = prover.load_proving_key("test_circuit", "key_data".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_proving_key_unknown_circuit() {
        let mut prover = Prover::new();
        let result = prover.load_proving_key("unknown", "key_data".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_generation() {
        let mut prover = Prover::new();
        let circuit = create_test_circuit();
        prover.register_circuit(circuit).unwrap();
        prover
            .load_proving_key("test_circuit", "dummy_key".to_string())
            .unwrap();

        let request = ProofRequest {
            circuit_id: "test_circuit".to_string(),
            private_inputs: serde_json::json!({
                "secret1": "value1",
                "secret2": "value2"
            }),
            public_inputs: serde_json::json!({
                "public1": "visible"
            }),
            metadata: None,
        };

        let proof = prover.generate_proof(request);
        assert!(proof.is_ok());

        let proof = proof.unwrap();
        assert_eq!(proof.circuit_id, "test_circuit");
        assert!(!proof.proof_data.is_empty());
        assert_eq!(proof.public_signals.len(), 1);
    }
}
