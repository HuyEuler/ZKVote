// import * as snarkjs from 'snarkjs';
// import * as circomlibjs from 'circomlibjs';

async function register() {
    event.preventDefault();
    const username = document.getElementById('reg-username').value;
    const password = document.getElementById('reg-password').value;
    const name = document.getElementById('reg-name').value;

    // const hashPassword = password;

    
    const response = await fetch('http://localhost:3000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, name, password})
    });
    console.log("So dumb");
    const result = await response.json();
    alert(result.message);

    window.location.href = './login';
}

async function login() {
    event.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    // // Tạo proof bằng mật khẩu và counter
    // const counter = await fetch(`http://localhost:3000/get-counter/${username}`).then(res => res.json());
    // console.log("counter : " + counter.counter);
    // const proof = await generateProof(password, counter);
    // console.log("proof : ")
    // console.log(proof.proof);

    // Gửi proof lên server để xác thực
    const response = await fetch('http://localhost:3000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });

    const result = await response.json();
    console.log(result);
    if (result.success) {
        localStorage.setItem('welcomeMessage', result.message);
        localStorage.setItem('username', result.username);
        localStorage.setItem('password', result.password);
        window.location.href = 'http://127.0.0.1:5500/frontend/voting';
    } else {
        alert(result.message);
    }
}

// Hàm hash mật khẩu
async function hash(password) {
    // Tạo hash của mật khẩu
    const poseidon = await circomlibjs.buildPoseidon();
    const hash = poseidon([BigInt(password)]);

    // Kết quả là một BigInt, chuyển thành chuỗi nếu cần
    // console.log("Hash result (BigInt):", hash);
    // console.log("Hash result (Hex):", poseidon.F.toString(hash, 16)); // Chuyển sang hex

    return poseidon.F.toString(hash, 16);
}

// Hàm tạo proof
async function generateProofLogin(password, hashPassword) {
    // Tính toán proof trên trình duyệt bằng SnarkJS
    const passwordBigInt  = BigInt(password);
    const hashPasswordBigInt = BigInt("0x" + hashPassword);
    console.log(passwordBigInt);
    console.log(hashPasswordBigInt);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve({ password:passwordBigInt, hash_server: hashPasswordBigInt}, 
        path.join(__dirname, '../circom/build/login/login_js/login.wasm'), 
        path.join(__dirname, '../circom/build/login/login_0001.zkey'));
    return { proof, publicSignals };
}
