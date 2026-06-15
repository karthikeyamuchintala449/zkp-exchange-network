//! Command line interface for zkp exchange network

use zkp_exchange_network::{
    circuits::CircuitManager,keys::KeyManager,
    prover::Prover,types::*,verifier::Verifier,

};

use std::env;

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


fn cmd_prove(_args: &[String]) {
    println!("Proof generation requires compiled circuits and proving keys.");
    println!("This is a placeholder for the actual implementation.");
    println!();
    println!("In production, this would:");
    println!("  1. Load the circuit and proving key");
    println!("  2. Create a witness from your private inputs");
    println!("  3. Run the zk-SNARK prover (e.g., Groth16)");
    println!("  4. Output the proof and public signals");
}


fn cmd_verify(_args: &[String]) {
    println!("Proof verification requires compiled circuits and verification keys.");
    println!("This is a placeholder for the actual implementation.");
    println!();
    println!("In production, this would:");
    println!("  1. Load the circuit and verification key");
    println!("  2. Load the proof and public inputs");
    println!("  3. Run the verification algorithm");
    println!("  4. Output true/false");
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
