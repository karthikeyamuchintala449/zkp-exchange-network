//! Key Manager for handling cryptographic keys

use crate::errors::{ZkpError,ZkpResult};
use crate::types::{KeyMaterial,KeyType};
use crate::utils;
use std::collections::HashMap;


/// Manager for cryptographic keys
pub struct KeyManager {
    keys: HashMap<String, KeyMaterial>,

}

impl KeyManager {
    /// Crate a new KeyManager 
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// store a key
    pub fn store_key(&mut self, key: KeyMaterial) -> ZkpResult<()> {
        if self.keys.contains_key(&key.key_id) {
            return Err(ZkpError::KeyError(format!(
                "key {} already exists",
                key.key_id
            )));

        }
        self.keys.insert(key.key_id.clone(),key);
        Ok(())
    }

    /// Retrive a key by ID 
    pub fn get_key(&self,key_id: &str) -> ZkpResult<KeyMaterial> {
        self.keys
        .get(key_id)
        .cloned()
        .ok_or_else(|| ZkpError::KeyError(format!("Key {} not found",key_id)))
    }

    ///  Get all keys for a specific circuit
    pub fn get_keys_for_circuit(&self,circuit_id: &str) -> Vec<KeyMaterial> {
        self.keys
        .values()
        .filter(|k| k.circuit_id == circuit_id)
        .cloned()
        .collect()
    }


    /// Get Verification key for a circuit
    pub fn get_verification_key(&self,circuit_id: &str) -> ZkpResult<KeyMaterial> {
        let keys = self.get_keys_for_circuit(circuit_id);
        keys.into_iter()
        .find(|k| k.key_type == KeyType::VerificationKey)
        .ok_or_else(|| {
            ZkpError::KeyError(format!(
                "Verification key not found for circuit {}",
                circuit_id
            ))
        })
    }


    /// Get Proving key for a circuit
    pub fn get_proving_key(&self,circuit_id : &str) -> ZkpResult<KeyMaterial> {
        let keys = self.get_keys_for_circuit(circuit_id);
        keys.into_iter()
        .find(|k| k.key_type == KeyType::ProvingKey)
        .ok_or_else(|| {
            ZkpError::KeyError(format!(
                "Proving key not found for circuit {}",
                circuit_id
            ))
        })
    }

    /// Remove a key 
    pub fn remove_key(&mut self,key_id:&str) ->ZkpResult<KeyMaterial> {
      self.keys
      .remove(key_id)
      .ok_or_else(|| ZkpError::KeyError(format!(
        "key {} doens not exist",
        key_id
      )))
    }

    /// check if a key exists
    pub fn has_key(&self,key_id:&str) -> bool {
        self.keys.contains_key(key_id)
    }

    /// get a total number of keys
    pub fn total_keys(&self) -> usize {
        self.keys.len()

    }

    /// List all keys for a circuit

    pub fn list_circuit_keys(&self,circuit_id:&str) -> Vec<String> {
        self.get_keys_for_circuit(circuit_id)
        .into_iter()
        .map(|k| k.key_id)
        .collect()

    }

    /// check if a key is expired 
    pub fn is_key_expired(&self,key_id:&str) -> ZkpResult<bool> {
        let key = self.get_key(key_id)?;
        if let Some(expires_at) = key.expires_at {
            let now = utils::current_timestamp();
            Ok(now >= expires_at)
        } else {
            Ok(false)
        }
    }


    /// validate a key is usable 
    pub fn validate_key(&self,key_id:&str) -> ZkpResult<()> {
        let key = self.get_key(key_id)?;

        // check if expired
        if self.is_key_expired(key_id)? {
            return  Err(ZkpError::KeyError(format!(
                "Key {} is expired",
                key_id
            )));
        }

        // check if data is not empty 
        if key.key_data.is_empty() {
            return Err(ZkpError::KeyError(format!(
                "Key {} has no data key",
                key_id
            )));
        }
       Ok(())
    }

    /// Rotate a key (create new one ,deprecate old)
    pub fn rotate_key(&mut self,old_key_id:&str,new_key:KeyMaterial) -> ZkpResult<()> {
        let _old_key = self.get_key(old_key_id)?;


        // Add new key 
        self.store_key(new_key)?;

        Ok(())

    }



    /// Load default keys for built in circuits (mock data)
   pub fn load_default_keys(&mut self) -> ZkpResult<()> {
        // Age Proof keys
        self.store_key(KeyMaterial {
            key_id: "age_proof_proving_key".to_string(),
            key_type: KeyType::ProvingKey,
            key_data: utils::base64_encode(b"mock_age_proving_key"),
            circuit_id: "age_proof".to_string(),
            created_at: utils::current_timestamp(),
            expires_at: None,
        })?;

        self.store_key(KeyMaterial {
            key_id: "age_proof_verification_key".to_string(),
            key_type: KeyType::VerificationKey,
            key_data: utils::base64_encode(b"mock_age_verification_key"),
            circuit_id: "age_proof".to_string(),
            created_at: utils::current_timestamp(),
            expires_at: None,
        })?;

        // Ownership Proof keys
        self.store_key(KeyMaterial {
            key_id: "ownership_proof_proving_key".to_string(),
            key_type: KeyType::ProvingKey,
            key_data: utils::base64_encode(b"mock_ownership_proving_key"),
            circuit_id: "ownership_proof".to_string(),
            created_at: utils::current_timestamp(),
            expires_at: None,
        })?;

        self.store_key(KeyMaterial {
            key_id: "ownership_proof_verification_key".to_string(),
            key_type: KeyType::VerificationKey,
            key_data: utils::base64_encode(b"mock_ownership_verification_key"),
            circuit_id: "ownership_proof".to_string(),
            created_at: utils::current_timestamp(),
            expires_at: None,
        })?;

        Ok(())
    }
    /// Export key material (use with caution!)
    pub fn export_key_data(&self, key_id: &str) -> ZkpResult<String> {
        let key = self.get_key(key_id)?;
        Ok(key.key_data)
    }
    
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_key(key_id: &str, circuit_id: &str) -> KeyMaterial {
        KeyMaterial {
            key_id: key_id.to_string(),
            key_type: KeyType::VerificationKey,
            key_data: "test_key_data".to_string(),
            circuit_id: circuit_id.to_string(),
            created_at: utils::current_timestamp(),
            expires_at: None,
        }
    }

    #[test]
    fn test_key_manager_creation() {
        let manager = KeyManager::new();
        assert_eq!(manager.total_keys(), 0);
    }

    #[test]
    fn test_store_and_retrieve_key() {
        let mut manager = KeyManager::new();
        let key = create_test_key("test_key", "test_circuit");
        assert!(manager.store_key(key).is_ok());
        assert_eq!(manager.total_keys(), 1);

        let retrieved = manager.get_key("test_key");
        assert!(retrieved.is_ok());
    }

    #[test]
    fn test_duplicate_key_storage() {
        let mut manager = KeyManager::new();
        let key = create_test_key("test_key", "test_circuit");
        assert!(manager.store_key(key.clone()).is_ok());
        assert!(manager.store_key(key).is_err());
    }

    #[test]
    fn test_get_keys_for_circuit() {
        let mut manager = KeyManager::new();
        manager
            .store_key(create_test_key("key1", "circuit1"))
            .unwrap();
        manager
            .store_key(create_test_key("key2", "circuit1"))
            .unwrap();
        manager
            .store_key(create_test_key("key3", "circuit2"))
            .unwrap();

        let circuit1_keys = manager.get_keys_for_circuit("circuit1");
        assert_eq!(circuit1_keys.len(), 2);

        let circuit2_keys = manager.get_keys_for_circuit("circuit2");
        assert_eq!(circuit2_keys.len(), 1);
    }

    #[test]
    fn test_remove_key() {
        let mut manager = KeyManager::new();
        let key = create_test_key("test_key", "test_circuit");
        manager.store_key(key).unwrap();
        assert_eq!(manager.total_keys(), 1);

        assert!(manager.remove_key("test_key").is_ok());
        assert_eq!(manager.total_keys(), 0);
    }

    #[test]
    fn test_has_key() {
        let mut manager = KeyManager::new();
        let key = create_test_key("test_key", "test_circuit");
        manager.store_key(key).unwrap();

        assert!(manager.has_key("test_key"));
        assert!(!manager.has_key("nonexistent"));
    }

    #[test]
    fn test_key_expiration() {
        let mut manager = KeyManager::new();
        let now = utils::current_timestamp();

        // Create an expired key
        let expired_key = KeyMaterial {
            key_id: "expired_key".to_string(),
            key_type: KeyType::VerificationKey,
            key_data: "test".to_string(),
            circuit_id: "test".to_string(),
            created_at: now - 100,
            expires_at: Some(now - 10), // Expired 10 seconds ago
        };

        manager.store_key(expired_key).unwrap();
        assert!(manager.is_key_expired("expired_key").unwrap());
        assert!(manager.validate_key("expired_key").is_err());
    }

    #[test]
    fn test_load_default_keys() {
        let mut manager = KeyManager::new();
        assert!(manager.load_default_keys().is_ok());
        assert!(manager.total_keys() > 0);
    }
}
