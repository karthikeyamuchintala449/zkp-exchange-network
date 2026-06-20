//! Prover module for generating zero-knowledge proofs
use crate::errors::{ZkpError,ZkpResult};
use crate::types::{CircuitConfig,ProofRequest,ZkProof};
use crate::utils;
use serde_json::json;

// new imports 
use std::colletcions::HashMap;
use ark_bn254::{Bn254,Fr,G1Affine,G2Affine};
use ark_groth16::{Groth16,ProvingKey};
use ark_serialize::{CanonicalDeserialize,CanonicalSerialize};
use serde::{Deserialize,Serialize};
use wasmer::{Instance,Module,Store,Value,Imports};



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

    pub fn load_default_circuits(&mut self) -> ZkpResult<()> {
        // Age Proof circuit - prove age >=18 without revealing actual age 
        self.register_circuit(CircuitConfig {
            id:"age_proof".to_string(),
            name: "Age Proof".to_string(),
            description:"Prove that age >=18 without revealing actual age".to_string(),
            num_private_inputs:1,
            num_public_inputs:1,
            num_constraints:500,
            version:"1.0".to_string(),

        })?;

        self.register_circuit(CircuitConfig {
            id:"ownership_proof".to_string(),
            name:"Ownership Proof".to_string(),
            description:"Prove ownership of a secret key or asset".to_string(),
            num_private_inputs:1,
            num_public_inputs:1,
            num_constraints:300,
            version:"1.0".to_string(),
        })?;

        // Membership Proof circuit
        self.register_circuit(CircuitConfig{
            id:"membership_proof".to_string(),
            name:"Memberhip proof".to_string(),
            description:"Prove Membership in a set without revealing which member".to_string(),
            num_private_inputs:2,
            num_public_inputs:1,
            num_constraints:800,
            version:"1.0".to_string(),
        })?;


        // Credentail proof circuit

        self.register_circuit(CircuitConfig{
            id:"credential_proof".to_string(),
            name:"Credential Proof".to_string(),
            description:"Prove Posssession of a valid credential".to_string(),
            num_private_inputs: 2,
            num_public_inputs:1,
            num_constraints:600,
            version:"1.0".to_string(),
        })?;

       Ok(())

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
        // 1. Get circuit configuration
        self.circuits.get(&request.circuit_id)
            .ok_or_else(|| ZkpError::CircuitNotFound(request.circuit_id.clone()))?;
        
        // 2. Load proving key
        let zkey_path = format!("../keys/{}_0001.zkey", request.circuit_id);
        let zkey_data = std::fs::read(&zkey_path)
            .map_err(|e| ZkpError::ProofGeneration(format!("Failed to load zkey: {}", e)))?;
        
        // 3. Load witness generator WASM
        let wasm_path = format!("../build/circuits/{}/{}_js/{}.wasm",request.circuit_id,request.circuit_id,request.circuit_id);
        let wasm_code = std::fs::read(&wasm_path)
            .map_err(|e| ZkpError::ProofGeneration(format!("Failed to load WASM: {}", e)))?;
        
        // 4. Create witness from inputs
        let witness = self.create_witness(request, &wasm_code)?;
        
        // 5. Call Groth16 prover (via FFI or WASM runtime)
        let proof = self.groth16_prove(&zkey_data, &witness)?;
        
        // 6. Serialize and return proof
        serde_json::to_string(&proof)
            .map_err(|e| ZkpError::ProofGeneration(format!("Serialization failed: {}", e)))
    }
    
    /// Create witness vector from circuit inputs
    fn create_witness(&self, request: &ProofRequest, wasm: &[u8]) -> ZkpResult<Vec<String>> {
       let mut store = Store::defautl();
       let module = Module::new(&strore,wasm)
       .map_err(|e| ZkpError::wasmIniti(format!("failded to compie WASM:{}",e)))?;

       // Circom WASM imports basic env utilities for memory/printing
       let import_object = Inports! {};
       let instance = Instance::new(&mut store,&module,&import_object)
       .map_err(|e| ZkpError::WasmInit(format!("Failed to instantiate WASM:{}",e)))?;


       // Extract required exported runtime symbols from Circom WASM
       let init_func = instance.exports.get_function("init")
       .map_err(|e| ZkpError::WasmInit(format!("Missing init function:{}",e)))?;
       let get_witness_size  = instance.exports.get_function("getFieldNumLen32")
       .map_err(|e| ZkpError::WasmInit(format!("Missing getFieldNumLen32:{}",e)))?;
       // set the input
       let set_input = instance.exports.get_function("setInputSignal")
       .map_err(|e| ZkpError::WasmInit(format!("Missing setInput signal:{}",e)))?;

       // get witness val
       let get_witness_val = isntance.exports.get_function("getWitnessValue")
       .map_err(|e| ZkpError::WasmInit(format!("Missing getWitnessValue:{}",e)))?;



       // Initialize sanity check values
       init_func_call(&mut store,&[Value::I32[0]])
       .map_err(|e| ZkpError::WitnessGeneration(format!("inti failed:{}",e)))?;

       // Bind request input maps into the Circom state engine
       // Loops through variable and signals sequentially
       for(signal_name,values) in &request.inputs {
        // Compute or resolve the exact signal offset hash expected by circom runtime
        // For
       }
        
        Ok(witness)
    }
    
    /// Call Groth16 proving algorithm
    fn groth16_prove(&self, zkey: &[u8], witness: &[String]) -> ZkpResult<serde_json::Value> {
        // This would call the actual Groth16 prover
        // For now, return structured proof format
        
        Ok(serde_json::json!({
            "pi_a": ["0", "0"],
            "pi_b": [["0", "0"], ["0", "0"]],
            "pi_c": ["0", "0"],
            "protocol": "groth16",
            "curve": "bn128"
        }))
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
    pub fn get_circuits(&self) -> Result<Vec<CircuitConfig>, ZkpError> {
        let circuits: Vec<CircuitConfig> = self.circuits.values().cloned().collect();
        if !circuits.is_empty() {
            // 2. Wrap the successful vector return in Ok()
            Ok(circuits)
        } else { 
            Err(ZkpError::NoCircuitsRegistered("no circuits are there")) 
        }
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
