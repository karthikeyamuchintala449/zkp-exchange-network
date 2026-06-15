// OwnershipProof Circuit
// Proves ownership of a secret key without revealing it 
// private input:secret_key (ex:a secret member)
// public input; hash_of_key (hash of  the secret)

pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

template OwnershipProof() {
    // Inputs
    signal input secret_key; // Private: the secret to prove ownership of 
    signal input hash_of_key[256]; // public: SHA256 hash of the secret (bit representation)

    // Intermediate signals 
    signal secret_bits[256];
    signal computed_hash[256];


    // Verify the secret matches the hash 
    component hasher  = Sha256(256);


    // Convert secret to bits
    component secret_num_to_bits = Num2Bits(256);
    secret_num_to_bits.in <== secret_key;
       for(var i = 0;i<256;i++) {
        hasher.in[i] <== secret_num_to_bits.out[i];
      }
    // Connect bits to hasher 
    for(var i = 0;i<256;i++) {
       
        computed_hash[i] <== hasher.out[i];
        computed_hash[i] === hash_of_key[i];

    }
}

component main  = OwnershipProof();
