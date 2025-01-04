pragma circom 2.0.0;
include "node_modules/circomlib/circuits/poseidon.circom";

template Election() {
    signal input username;       
    signal input password;   
    signal input vote_choice;    

    signal output hash_out;      
    signal output vote;         

    component hasher = Poseidon(2);
    hasher.inputs[0] <== username;
    hasher.inputs[1] <== password;

    hash_out <== hasher.out;

    vote <== vote_choice;
}

component main = Election();
