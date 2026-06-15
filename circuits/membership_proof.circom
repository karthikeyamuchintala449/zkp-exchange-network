// MembershipProof Circuit
// Proves memebership ina set  (represented as Merle tree root) without revealing which member
// private inputs: member(the member value),mekle_path(path through tree),merkle_siblings(sibling nodes)
// Public input:merkle_root(root of the tree)


pragma circom 2.0;

include "../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../node_modules/circomlib/circuits/bitify.circom";


template MerkleProof(n_levels) {
    // Inputs
    signals input member // private: the member to prove inclusion of 
    signal input merkle_siblings[n_levels]; //Private sibling nodes along the path 
    signal input merkle_root; // Public the Merkle tree root

    // Compute the leaf hash
    component leaf_hasher = Sha256(256);


    // Conver member to bits
    component member_bits = Num2Bits(256);
    member_bits.in <== member;

    for(var i = 0 ;i<256;i++) {

      lead_hasher.in[i] <== member_bits.out[i];

    }

    // Verify path from leaf to root 
    var cur_hash[256];
    for(var i = 0 ;i<256;i++) {
        cur_hash[i] = leaf_hasher.out[i];

    }

    for(var level = 0 ; level < n_levels;level++) {
        component level_handler = Sha256(512);

        // Combine current hash with sibling 
        for(var i = 0;i<256;i++) {
            level_handler.in[i] <== cur_hash[i];
            level_handler.in[256+i] <== merkle_siblings[level];

        }

        for(var i = 0;i<256;i++) {
            cur_hash[i] = level_hasher.out[i];

        }
    }

    // Verify final hash matches root
    var computed_root = 0;
    for(var i = 0;i < 256 ; i++) {
        computed_root = computed_root + cur_hash[i] * (2**i);

    }
    computed_root === merle_root;
}

component main  = MerkleProof(8); // 8-level tree,supports 2^8 = 256 members