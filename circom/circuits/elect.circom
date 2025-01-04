pragma circom 2.0.0;
include "node_modules/circomlib/circuits/poseidon.circom";

template Election() {
    signal input username;       // ID của cử tri
    signal input password;   // Bí mật cử tri (đảm bảo tính duy nhất)
    signal input vote_choice;    // Lựa chọn của cử tri (1, 2, 3,...)

    signal output hash_out;      // Hash tính toán lại
    signal output vote;          // Phiếu bầu

    component hasher = Poseidon(2);
    hasher.inputs[0] <== username;
    hasher.inputs[1] <== password;

    hash_out <== hasher.out;

    // Đầu ra phiếu bầu
    vote <== vote_choice;
}

component main = Election();
