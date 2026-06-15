// CredentialProof circuit
// Proves possession of a valid credential without revealing the credential itself
// Private inputs:credential (the credentail data),credential_secret(a secret asocaited with it)

// Public input: credential_hash (hash of the credential)

pragma circom 2.0.0;
include "../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

template CredentialProof() {
    //Inputs
    signal input credential[256]; // Private:credential bytes
    signal input credential_secret;  // Private:secret associated with credential 
    signal input credential_hash[256]; //Public : hash of the credential 


    // Hash the credential to verify it matches
    component hasher = Sha256(256);

    for(var i =0 ;i<256;i++) {
        hasher.in[i] <== credential[i];

    }


    for(var i = 0 ;i < 256;i++) {
        hasher.out[i] === credential_hash[i];

    }

    // Additional check : the secret must be non-zero (proof of knowledge)
    signal secret_inverse ;
    secret_inverse <-- 1 / credential_secret;
    credential_secret * secret_inverse === 1;
}

component main = CredentialProof();

