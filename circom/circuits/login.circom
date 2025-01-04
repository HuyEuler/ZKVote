pragma circom 2.0.0;
include "node_modules/circomlib/circuits/poseidon.circom";

template Login() {
    signal input password;     
    signal input hash_server;  // Hash mật khẩu lưu trên server
    signal input counter; // counter chống replay attackattack

    signal output computed_hash;
    signal output counter_out;

    component poseidon = Poseidon(1); // Sử dụng Poseidon hash
    poseidon.inputs[0] <== password;
    computed_hash <== poseidon.out;
    counter_out <== counter;

    computed_hash === hash_server;
}

component main = Login();