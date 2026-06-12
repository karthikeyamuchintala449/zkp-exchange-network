//! Proof Exchange Layer for offline transmission of proofs

use crate::errors::{ZkpError,ZkpResult};
use crate::types::{ProofPacket,TransmissionChannel,TransmissionMetadata,ZkProof};
use crate::utils;

/// Handler for exchanging prooofs via various channels 
pub struct ProofExchange;


impl ProofExchange {
    /// Encode a proof for transmission via QR code 
    pub fn encode_for_qr(proof:&ZkProof) -> ZkpResult<String> {
        // Serialize the proof to compact JSON
        let proof_json = utils::to_json(proof)?;

        // Compress using basae64 for QR compatiblity
        let compressed = utils::base64_encode(proof_json.as_bytes());


        // QR codes can handle ~2953 bytes in alphanumeric mode 
        if compressed.len() > 2900 {
            return Err(ZkpError::EncodingError(
                format!(
                    "Proof too large for QR code  ({} bytes,
                    max 2900)",
                    compressed.len()
                ),
            ));
        }
        Ok(compressed)
    }

    /// Deocde a prooof from QR code data
    pub fn decode_from_qr(qr_data:&str) -> ZkpResult<ZkProof> {
        let decoded_bytes = utils::base64_decode(qr_data)?;
        let proof_json = String::from_utf8(decoded_bytes)
        .map_err(|e| ZkpError::EncodingError(format!(
            "Invalid UTF-8:{}",e
        )))?;

        serde_json::from_str::<ZkProof>(&proof_json)
        .map_err(|e| ZkpError::SerializationError(e))
    }

    /// Encode a proof for BLE transmission (split into chunks)
    pub fn encode_for_ble(proof:&ZkProof,chunk_size:usize) -> ZkpResult<Vec<Vec<u8>>> {
        let proof_bytes = utils::to_json(proof)?.into_bytes();

        if chunk_size == 0 {
            return Err(ZkpError::EncodingError("
            Chunk size must be greater than 0".to_string(),
        ));
        }

        let chunks:Vec<Vec<u8>> = proof_bytes
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect();

        Ok(chunks)
    }

    /// Reassemble BLE chunks into a complete proof
    pub fn decode_from_ble(chunks:&[Vec<u8>])  -> ZkpResult<ZkProof> {
         let mut complete_data = Vec::new();
         for chunk in chunks {
            complete_data.extend_from_slice(chunk);

         }

        let proof_json = String::from_utf8(complete_data)
        .map_err(|e| ZkpError::EncodingError(format!(
            "Invalid UTF-8 {} ",e
        )))?;
        
        
        serde_json::from_str::<ZkProof>(&proof_json)
        .map_err(|e| ZkpError::SerializationError(e))
    }


    /// Encode proof for ultrasonic transmission (compact binary format)
    pub fn encode_for_ultrasonic(proof:&ZkProof) ->  ZkpResult<Vec<u8>> {
        // Create compact representation

        let compact = serde_json::json!({
            "p":proof.proof_data,
            "s":proof.public_signals,
            "c":proof.circuit_id,
            "t":proof.timestamp,
            "v":proof.version
        });


        let json_bytes = serde_json::to_vec(&compact)?;

        // Compress with simple run length for ultrasonic (minimal overhead)
        Ok(json_bytes)
    }


    /// Decode proof form ultrasonic transmisssion
    pub fn decode_from_ultrasonic(data: &[u8]) -> ZkpResult<ZkProof> {
        let compact : serde_json::Value = serde_json::from_slice(data)?;

        // proof generation
        let proof = ZkProof {
            proof_data:compact["p"]
            .as_str()
            .ok_or_else(|| ZkpError::InvalidProofFormat(
                "Missing proof data".to_string()))?.to_string(),
            public_signals:compact["s"]
            .as_array()
            .ok_or_else(|| ZkpError::InvalidProofFormat(
                "Missing signals".to_string()))?
            .iter()
            .filter_map(|s| s.as_str().map(String::from))
            .collect(),
            circuit_id:compact["c"]
            .as_str()
            .ok_or_else(|| ZkpError::InvalidProofFormat("Missing circuit ID".to_string()))?.to_string(),
            timestamp:compact["t"]
            .as_u64()
            .ok_or_else(|| ZkpError::InvalidProofFormat("Missing timestamp".to_string()))?,
            signature:compact["sig"].as_str().map(String::from),
            version:compact["v"]
            .as_str()
            .unwrap_or("1.0")
            .to_string(),    

        };
       Ok(proof)
    }

    /// Create a proof packer with transmission metadata
    pub fn create_packet(
        proof:ZkProof,
        channel:TransmissionChannel,
        receiver_pubkey:Option<String>,

    ) -> ZkpResult<ProofPacket> {
        let packet = ProofPacket {
            proof,
            metadata:TransmissionMetadata {
                channel,
                nonce:Some(utils::generate_nonce()),
                compression:Some("base64".to_string()),
                receiver_pubkey,

            },

        };
        Ok(packet)
    }

    /// Validate a received proof packet 
    pub fn validate_packet(packet:&ProofPacket,max_age : u64) -> ZkpResult<()> {
        // Validate proof format 
        if packet.proof.proof_data.is_empty() {
            return Err(ZkpError::InvalidProofFormat("Proof data is empty".to_string()));

        }


       
        if !utils::validate_timestamp(packet.proof.timestamp,max_age) {
            return Err(ZkpError::InvalidProofFormat("Proof is too old".to_string(),));

        }

        // validate nonce is present 
        if packet.metadata.nonce.is_none() {
            return Err(ZkpError::InvalidProofFormat("Missing nonce".to_string()));

     
        }
       Ok(())
    }
    /// Estimate transmission size for different channels
    pub fn estimate_transmission_size(proof:&ZkProof,channel:&TransmissionChannel) -> ZkpResult<usize> {
        let proof_json = utils::to_json(proof)?;
        let base_size = proof_json.len();

        let size = match channel {
            TransmissionChannel::QrCode => {
                // QR encoding adds ~33% overhead
                (base_size as f64 * 1.33) as usize 
            }

            TransmissionChannel::BluetoothLe => {
                // BLE uses standard serialization
                base_size

            }
            TransmissionChannel::UltrasonicAudio => {
                // Ultrasonic may need encoding/error correction (~50% overhead)
                (base_size as f64 * 1.5) as usize
            }

            TransmissionChannel::Nfc => {
                //NFC similar to QR
                (base_size as f64 * 1.2) as usize
            }

            TransmissionChannel::DirectTransfer => {
                //Direct transfer is just the data
                base_size
            }
        };

        Ok(size)
    }

}


#[cfg(test)]
mod tests {
    use super::*;
    fn create_test_proof() -> ZkProof {
        ZkProof {
            proof_data:"test_proof".to_string(),
            public_signals:vec!["signal1".to_string()],
            circuit_id:"test".to_string(),
            timestamp:utils::current_timestamp(),
            signature:None,
            version:"1.0".to_string(),

        }
    }

    #[test]
    fn test_qr_encoding_decoding() {
        let proof = create_test_proof();
        let encoded = ProofExchange::encode_for_qr(&proof);
        assert!(encoded.is_ok());

        let decoded = ProofExchange::decode_from_qr(&encoded.unwrap());

        assert!(decoded.is_ok());
        

        let decoded_proof = decoded.unwrap();
        assert_eq!(decoded_proof.circuit_id,proof.circuit_id);

    }

    #[test]
    fn test_qr_encoding_size_limits() {
        // Create a large proof that exceeds QR capacity 
        let mut proof = create_test_proof();
        proof.proof_data = "x".repeat(5000);

        let encoded = ProofExchange::encode_for_qr(&proof);
        assert!(encoded.is_err());
    }

    #[test]
    fn test_ble_chunking() {
        let proof = create_test_proof();
        let chunks = ProofExchange::encode_for_ble(&proof,100);
        assert!(chunks.is_ok());
        let chunks = chunks.unwrap();
        assert!(chunks.len() > 0);


        // Reasssamble 
        let reassambled = ProofExchange::decode_from_ble(&chunks);
        assert!(reassambled.is_ok());
    }


    #[test]
    fn test_ultrasonic_encoding() {
    let proof = create_test_proof();
    let encoded = ProofExchange::encode_for_ultrasonic(&proof);
    assert!(encoded.is_ok());

    let decoded = ProofExchange::decode_from_ultrasonic(&encoded.unwrap());
    assert!(decoded.is_ok());

    }

    #[test]
    fn test_create_packet() {
        let proof = create_test_proof();
        let packet = ProofExchange::create_packet(
            proof,
            TransmissionChannel::BluetoothLe,
            None,

        );

        assert!(packet.is_ok());
        let packet = packet.unwrap();
        assert!(packet.metadata.nonce.is_some());

    }

    #[test]
    fn test_transmission_size_estimation() {
        let proof = create_test_proof();

        let qr_size = 
        ProofExchange::estimate_transmission_size(&proof,&TransmissionChannel::QrCode);
       let ble_size =
       ProofExchange::estimate_transmission_size(&proof,&TransmissionChannel::BluetoothLe);
       let ultrasonic_size=
       ProofExchange::estimate_transmission_size(&proof,&TransmissionChannel::UltrasonicAudio);

       assert!(qr_size.is_ok());
       assert!(ble_size.is_ok());
       assert!(ultrasonic_size.is_ok());
       // ultrasonic should be larger due to error correction

       assert!(ultrasonic_size.unwrap() > ble_size.unwrap());

    }
}