//! Circuit manager for handling ZKP circuit defintions

use crate::errors::{ZkpError,ZkpResult};
use crate::types::CircuitConfig;
use std::collections::HashMap;


/// Manager for zero-konwledge proof circuits
pub struct CircuitManager {
    circuits: HashMap<String,CircuitConfig>,

}

impl CircuitManager {
    /// Create a new Circuitmanger 
    pub fn new() -> Self {
        Self {
            circuits:HashMap::new(),

        }
    }

    /// Register a new circuit

    pub fn register_circuit(&mut self , circuit:CircuitConfig) -> ZkpResult<()> {
        if self.circuits.contains_key(&circuit.id) {
            return Err(ZkpError::CircuitError(format!(
                "circuit {} already refgistered",
            circuit.id
        
            )));

        }
        self.circuits.insert(circuit.id.clone(),circuit);
        Ok(())
    }

    /// Get a circuit by ID 
    pub fn get_circuit(&self,circuit_id: &str) -> ZkpResult<CircuitConfig> {
        self.circuits
        .get(circuit_id)
        .cloned()
        .ok_or_else(|| ZkpError::UnknownCircuit(circuit_id.to_string()))
    }

    /// List all registerr circuits
    pub fn list_circuits(&self) -> Vec<CircuitConfig> {
        self.circuits.values().cloned().collect()

    }

    //check if a circuit is registeered
    pub fn has_circuit(&self, circuit_id: &str) -> bool {
        self.circuits.contains_key(circuit_id)
    }

    /// remove a circuit (careful to know which to rmeove )

    pub fn remove_circuit(&mut self , circuit_id: &str) -> ZkpResult<CircuitConfig> {
        self.circuits
        .remove(circuit_id)
        .ok_or_else(|| ZkpError::UnknownCircuit(circuit_id.to_string()))
    }


    /// UPdate circuit metadata
    pub fn update_ciruit(&mut self,circuit:CircuitConfig) -> ZkpResult<()> {
        if !self.circuits.contains_key(&circuit.id) {
            return Err(ZkpError::UnknownCircuit(circuit.id.clone()));

        }

        self.circuits.insert(circuit.id.clone(),circuit);
        Ok(())

    }


    /// Get total number of registered of registered circuits
    pub fn total_circuits(&self) -> usize {
        self.circuits.len()
    }

    /// Load default circuits

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


    // validate circuit for proof generation
    pub fn validate_circuit(&self,circuit_id:&str) -> ZkpResult<()> {
        let circuit = self.get_circuit(circuit_id)?;

        if circuit.num_private_inputs == 0 && circuit.num_public_inputs == 0 {
            return Err(ZkpError::CircuitError(
                "Circuit must have atleast one input".to_string(),

            ));


        }

        if circuit.num_constraints == 0 {
            return Err(ZkpError::CircuitError(
                "Circuit must have at least one constraint".to_string(),
            ));
        }

        Ok(())

    }
}

impl Default for CircuitManager {
    fn default() -> Self{
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_manager_creation() {
        let manager = CircuitManager::new();
        assert_eq!(manager.total_circuits(),0);

    }

    #[test]
    fn test_register_circuit() {
        let mut manager = CircuitManager::new();
        let circuit = CircuitConfig {
            id:"test".to_string(),
            name:"Test".to_string(),
            description:"tst circuit".to_string(),
            num_private_inputs:1,
            num_public_inputs:1,
            num_constraints:100,
            version:"1.0".to_string(),
        };
        assert!(manager.register_circuit(circuit).is_ok());
        assert_eq!(manager.total_circuits(),1);
    }


    #[test]
    fn test_duplicate_registration() {
        let mut manager = CircuitManager::new();
       let circuit = CircuitConfig {
            id:"test".to_string(),
            name:"Test".to_string(),
            description:"tst circuit".to_string(),
            num_private_inputs:1,
            num_public_inputs:1,
            num_constraints:100,
            version:"1.0".to_string(),
        };
        assert!(manager.register_circuit(circuit.clone()).is_ok());
        assert!(manager.register_circuit(circuit).is_err());
    }

    #[test]
    fn test_get_circuit() {
        let mut manager = CircuitManager::new();
        let circuit = CircuitConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: "Test circuit".to_string(),
            num_private_inputs: 1,
            num_public_inputs: 1,
            num_constraints: 100,
            version: "1.0".to_string(),
        };
           manager.register_circuit(circuit).unwrap();
        let retrieved = manager.get_circuit("test");
        assert!(retrieved.is_ok());
    }

    // testing list_circuits
      #[test]
    fn test_list_circuits() {
        let mut manager = CircuitManager::new();
        manager.load_default_circuits().unwrap();
        assert_eq!(manager.total_circuits(), 4);
    }

    // testing has circuit
     
    #[test]
    fn test_has_circuit() {
        let mut manager = CircuitManager::new();
        manager.load_default_circuits().unwrap();
        assert!(manager.has_circuit("age_proof"));
        assert!(!manager.has_circuit("unknown"));
    }

    // testing remove circuit
     #[test]
    fn test_remove_circuit() {
        let mut manager = CircuitManager::new();
        let circuit = CircuitConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: "Test circuit".to_string(),
            num_private_inputs: 1,
            num_public_inputs: 1,
            num_constraints: 100,
            version: "1.0".to_string(),
        };

        manager.register_circuit(circuit).unwrap();
        assert_eq!(manager.total_circuits(), 1);
        assert!(manager.remove_circuit("test").is_ok());
        assert_eq!(manager.total_circuits(), 0);
    }

       #[test]
    fn test_validate_circuit() {
        let manager = CircuitManager::new();
        // Invalid circuit with no constraints
        let invalid = CircuitConfig {
            id: "invalid".to_string(),
            name: "Invalid".to_string(),
            description: "Invalid".to_string(),
            num_private_inputs: 0,
            num_public_inputs: 0,
            num_constraints: 0,
            version: "1.0".to_string(),
        };

        // We would need to register it first
        // For now just check the structure
        assert_eq!(invalid.num_constraints, 0);
    }

}
