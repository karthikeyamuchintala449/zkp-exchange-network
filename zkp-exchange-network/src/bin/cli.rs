//! Command line interface for zkp exchange network

use zkp_exchange_network::{
    circuits::CircuitManager,keys::KeyManager,
    prover::Prover,types::*,verifier::Verifier,

};

use std::env;
use std::fs;
use std::path::Path;


fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    let command = &args[1];


    match command.as_str() {
        "list-circuits" => cmd_list_circuits(),
        "list-keys" => cmd_list_keys(),
        "prove" => cmd_prove(&args[2..]),
        "verify" => cmd_verify(&args[2..]),
        "encode-qr" => cmd_encode_qr(&args[2..]),
        "decode-qr" => cmd_decode_qr(&args[2..]),
        "help" => print_help(),
        _ => {
            eprintln!("Unknown command : {} ", command);
            print_usage(&args[0]);
            std::process::exit(1);

        }
    }
}

fn print_usage(prog:&str) {
    eprintln!("Usage:{} <command> [options]",prog);
    eprintln!("Use '{} help' for more information",prog);

}

fn print_help()  {
    println!("ZKP Exchange Network Cli");
    println!();
    println!("Commands:");
    println!("  list-circuits         List all registered circuits");
    println!("  list-keys             List all stored keys");
    println!("  prove <args>          Generate a zero-knowledge proof");
    println!("  verify <args>         Verify a zero-knowledge proof");
    println!("  encode-qr <proof>     Encode proof for QR transmission");
    println!("  decode-qr <data>      Decode proof from QR data");
    println!("  help                  Show this help message");
    println!();
    println!("Examples:");

    println!("   prove --circuit age_proof --private '{{{}}}'", "zkp-cli");
    println!("  {} verify --proof proof.json", "zkp-cli");
}


fn cmd_list_circuits() {
    let mut manager = CircuitManager::new();
    if let Err(e) = manager.load_default_circuits() {
        eprintln!("Error Loading circuits:{}",e);
        return;
    }

   // listing the circuits
   let circuits = manager.list_circuits();
   println!("Registered Circuits:");
   println!();

   for circuit in circuits {
      println!(" ID: {} ",circuit.id);
      println!(" Name:{}",circuit.name);
      println!("   Description:{}",circuit.description);
      println!("   Private Inputs: {} ",circuit.num_private_inputs);
      println!("  Public Inputs:{}",circuit.num_public_inputs);
      println!("  Constraints:{}",circuit.num_constraints);
      println!();
   }
}



fn cmd_list_keys() {
    let mut manager = KeyManager::new();
    if let Err(e) = manager.load_default_keys() {
        eprintln!("Error loading keys: {}", e);
        return;
    }

    let total = manager.total_keys();
    println!("Stored Keys: {}", total);
    println!();

    for key in manager.list_circuit_keys("age_proof") {
        println!("  - {}", key);
    }
}


fn cmd_prove(args: &[String]) {
  
    if args.len() < 4 {
        eprintln!("Usage zkp-cli prove --circuit <id> --private '<json>' --public '<json>'");
        return;
    }

    // Parse command line arguments
    let mut circuit_id = String::new();
    let mut private_json = String::new();
    let mut public_json = String::new();

    // parse arguments
    let mut i = 0;
    let  prover = Prover::new();
   
while i < args.len() {
    match args[i].as_str() {
        "--circuit" => {
            if i + 1 < args.len() {
                circuit_id = args[i + 1].clone();
                i += 2;
            } else {
                i += 1;
            }
        }
        "--private" => {
            if i + 1 < args.len() {
                let raw_val = args[i + 1].clone();
                if Path::new(&raw_val).exists() {
                    private_json = fs::read_to_string(&raw_val)
                        .expect("Failed to read private inputs file");
                } else {
                    private_json = raw_val.trim_matches('\'').to_string();

                }
                i += 2;
            } else {
                i += 1;
            }
        }
        "--public" => {
            if i + 1 < args.len() {
                let raw_val = args[i + 1].clone();
                if Path::new(&raw_val).exists() {
                    public_json = fs::read_to_string(&raw_val)
                        .expect("Failed to read public inputs file");
                } else {
                    public_json = raw_val.trim_matches('\'').to_string();
                }
                i += 2;
            } else {
                i += 1;
            }
        }
        _ => i += 1, // ← this was missing, causes compiler error without it
    }
}

    // validate inputs from the cli command
    if circuit_id.is_empty() || private_json.is_empty() || public_json.is_empty() {
        eprintln!("Error: Missing reuired arguments");
        return;
    }

    // Create proof requiest 
    let request = ProofRequest {
       // Around line 175: Clone it so ownership stays with the variable for later use
        circuit_id:circuit_id.clone(),

        private_inputs:match serde_json::from_str(&private_json) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Invalid private inputs JSON:{}",e);
                return;
            }
        },
        public_inputs:match serde_json::from_str(&public_json) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Invlaid public inputs JSON:{}",e);
                return;

            }
        },
        metadata: None,
    };
    //Generate proof
    let mut prover = Prover::new();
    if let Err(e) = prover.load_default_circuits() {
        eprintln!("Error loading circuits: {}", e);
        return;
    }
  
    

    match prover.generate_proof(request) {
        Ok(proof) => match serde_json::to_string_pretty(&proof) {
         Ok(json) => println!("{}",json),
         Err(e) => eprintln!("Serialization error : {}",e),

        },
        Err(e) => eprintln!("Proof generation failed:{}",e),
    }


}


fn cmd_verify(args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: zkp-cli verify --proof '<json>' [--max-age <seconds>]");
        return;
    }

    let mut proof_json = String::new();
    let mut max_age: Option<u64> = None;

    // Parse arguments
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--proof" => {
                if i + 1 < args.len() {
                    proof_json = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--max-age" => {
                if i + 1 < args.len() {
                    max_age = args[i + 1].parse().ok();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }

    // Parse proof
    let proof: ZkProof = match serde_json::from_str(&proof_json) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Invalid proof JSON: {}", e);
            return;
        }
    };

    // Create verification request
    let request = VerificationRequest {
        proof,
        expected_signals: None,
        max_age,
    };

    // Verify proof
    let mut verifier = Verifier::new();
    // Replace lines 269-272 with this:
   let circuits = verifier.get_circuits();


    match verifier.verify_proof(request) {
        Ok(result) => match serde_json::to_string_pretty(&result) {
            Ok(json) => println!("{}", json),
            Err(e) => eprintln!("Serialization error: {}", e),
        },
        Err(e) => eprintln!("Verification failed: {}", e),
    }
}

fn cmd_encode_qr(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: zkp-cli encode-qr <proof-json>");
        return;
    }

    match serde_json::from_str::<ZkProof>(&args[0]) {
        Ok(proof) => {
            match zkp_exchange_network::exchange::ProofExchange::encode_for_qr(&proof) {
                Ok(encoded) => println!("QR Data:\n{}", encoded),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Err(e) => eprintln!("Invalid proof JSON: {}", e),
    }
}

fn cmd_decode_qr(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: zkp-cli decode-qr <qr-data>");
        return;
    }

    match zkp_exchange_network::exchange::ProofExchange::decode_from_qr(&args[0]) {
        Ok(proof) => match serde_json::to_string_pretty(&proof) {
            Ok(json) => println!("Decoded Proof:\n{}", json),
            Err(e) => eprintln!("Serialization error: {}", e),
        },
        Err(e) => eprintln!("Error: {}", e),
    }
}
