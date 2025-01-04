pragma circom 2.0.0;
include "node_modules/circomlib/circuits/poseidon.circom";

template Login() {
    signal input password;     // Mật khẩu người dùng
    signal input hash_server;  // Hash mật khẩu lưu trên server

    signal output computed_hash;

    component poseidon = Poseidon(1); // Sử dụng Poseidon hash
    poseidon.inputs[0] <== password;
    computed_hash <== poseidon.out;

    computed_hash === hash_server;
}

component main = Login();