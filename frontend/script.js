// import * as snarkjs from 'snarkjs';
// import * as circomlibjs from 'circomlibjs';

async function register() {
    event.preventDefault();
    const username = document.getElementById('reg-username').value;
    const password = document.getElementById('reg-password').value;
    const name = document.getElementById('reg-name').value;

    const hashPassword = await hash1(password);
    const hashUnamePass = await hash2(username, password)
    const voter = BigInt("0x" + hashUnamePass); // hash username and password

    console.log("hash password : " + hashPassword);
    console.log("hash uname pass : " + hashUnamePass);
    console.log("voter : " + voter);
    
    const response = await fetch('http://localhost:3000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, name, hashPassword, hashUnamePass})
    });
    const result = await response.json();
    alert(result.message);

    window.location.href = './login';
}

async function login() {
    event.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    // Lưu lại username password cho phiên sau 
    localStorage.setItem('username', username);
    localStorage.setItem('password', password);

    // // Tạo proof bằng mật khẩu và counter
    // const counter = await fetch(`http://localhost:3000/get-counter/${username}`).then(res => res.json());
    // console.log("counter : " + counter.counter);
    
    const hashPassword = await hash1(password);
    const {proof, publicSignals} = await generateProofLogin(password, hashPassword);
    
      
    const jsonData = JSON.stringify({
        username,
        proof: proof,
        publicSignals: publicSignals
    });

    console.log(jsonData);

    // Send proof and public signals to server
    const response = await fetch('http://localhost:3000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: jsonData
    });

    const result = await response.json();
    console.log(result);
    if (result.success) {
        localStorage.setItem('welcomeMessage', result.message);
        window.location.href = 'http://127.0.0.1:5500/frontend/voting';
    } else {
        alert(result.message);
    }
}

// Hàm hash mật khẩu
async function hash1(password) {
    // convert password to int ...
    const passwordBigInt = BigInt(parseInt(password, 36));

    const poseidon = await circomlibjs.buildPoseidon();
    const hash = poseidon([passwordBigInt]);

    // console.log("Hash result (BigInt):", hash);
    // console.log("Hash result (Hex):", poseidon.F.toString(hash, 16)); // Chuyển sang hex

    return poseidon.F.toString(hash, 16);
}

// Hàm tạo proof login
async function generateProofLogin(password, hashPassword) {
    // convert password to number ...

    const passwordBigInt = BigInt(parseInt(password, 36));
    const hashPasswordBigInt = BigInt("0x" + hashPassword);
    console.log(passwordBigInt);
    console.log(hashPasswordBigInt);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve({ password:passwordBigInt, hash_server: hashPasswordBigInt}, 
        '../circom/build/login/login_js/login.wasm',
        '../circom/build/login/login_0001.zkey');
    // console.log(publicSignals);
    // console.log(proof);
    return { proof, publicSignals };
}

// Hàm hash username và password
async function hash2(username, password) {
    // Chuyển đổi username và password thành BigInt
    const usernameBigInt = BigInt(parseInt(username, 36)); // Chuyển username sang dạng số từ chuỗi
    const passwordBigInt = BigInt(parseInt(password, 36)); // Tương tự cho password

    const poseidon = await circomlibjs.buildPoseidon();

    // Hash mảng đầu vào
    const hash = poseidon([usernameBigInt, passwordBigInt]);

    // Kết quả dưới dạng hex
    const hashHex = poseidon.F.toString(hash, 16); 
    console.log("Hash result (Hex):", hashHex);

    return hashHex;
}

// Hàm tạo proof elect
async function generateProofElect(username, password, voteChoice) {
    // convert username to number ... 
    const usernameBigInt = BigInt(parseInt(username, 36)); // Chuyển username sang dạng số từ chuỗi
    const passwordBigInt = BigInt(parseInt(password, 36)); // Tương tự cho password

    const { proof, publicSignals } = await snarkjs.groth16.fullProve({username: usernameBigInt, password: passwordBigInt, vote_choice: voteChoice}, 
        '../circom/build/elect/elect_js/elect.wasm',
        '../circom/build/elect/elect_0001.zkey');
    console.log(publicSignals);
    return { proof, publicSignals };
}
