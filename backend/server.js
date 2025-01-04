const express = require('express');
const snarkjs = require('snarkjs');
const circomlibjs = require('circomlibjs');
const fs = require('fs');
const app = express();
const path = require('path');
const cors = require('cors');

app.use(express.json());
app.use(cors());
// Đọc database từ file JSON
const dbUserPath = path.join(__dirname, './database/db_users.json');

// Hàm hash mật khẩu
async function hash(password) {
    const poseidon = await circomlibjs.buildPoseidon();
    const hash = poseidon([BigInt(password)]);

    // console.log("Hash result (BigInt):", hash);
    // console.log("Hash result (Hex):", poseidon.F.toString(hash, 16)); // Chuyển sang hex

    return poseidon.F.toString(hash, 16);
}

// Hàm tạo proof login
async function generateProofLogin(password, hashPassword) {
    const passwordBigInt  = BigInt(password);
    const hashPasswordBigInt = BigInt("0x" + hashPassword);
    console.log(passwordBigInt);
    console.log(hashPasswordBigInt);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve({ password:passwordBigInt, hash_server: hashPasswordBigInt}, 
        path.join(__dirname, '../circom/build/login/login_js/login.wasm'), 
        path.join(__dirname, '../circom/build/login/login_0001.zkey'));
    return { proof, publicSignals };
}

// Hàm hash username password
async function hash2(username, password) {
    // convert username to number ... 

    const poseidon = await circomlibjs.buildPoseidon();
    const hash = poseidon(BigInt[username], [BigInt(password)]);

    // console.log("Hash result (BigInt):", hash);
    console.log("Hash result (Hex):", poseidon.F.toString(hash, 16)); // Chuyển sang hex

    return poseidon.F.toString(hash, 16);
}

// Hàm tạo proof elect
async function generateProofElect(username, password, voteChoice) {
    // convert username to number ... 


    const { proof, publicSignals } = await snarkjs.groth16.fullProve({username: username, password: password, vote_choice: voteChoice}, 
        path.join(__dirname, '../circom/build/elect/elect_js/elect.wasm'), 
        path.join(__dirname, '../circom/build/elect/elect_0001.zkey'));
    console.log(publicSignals);
    return { proof, publicSignals };
}


function readDatabase() {
    try {
        const data = fs.readFileSync(dbUserPath, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        return {}; 
    }
}

function saveDatabase(db) {
    try {
        fs.writeFileSync(dbUserPath, JSON.stringify(db, null, 2));
    } catch (err) {
        console.error('Error saving database:', err);
    }
}

// Đăng ký người dùng
app.post('/register', async (req, res) => {
    var { username, name, hashPassword } = req.body;

    const db = readDatabase();

    if (db[username]) {
        return res.status(400).json({ message: 'Username already exists!' });
    }

    // *** FRONTEND
    hashPassword = await hash(hashPassword)
    //////

    db[username] = { name, hashPassword, counter: 0 };
    saveDatabase(db);

    res.json({ message: 'User registered successfully!' });
});

// Đăng nhập và xác thực bằng ZKP
app.post('/login', async (req, res) => {
    const { username, password} = req.body;

    const db = readDatabase();

    if (!db[username]) {
        return res.status(404).json({ message: 'User not found!' });
    }

    const user = db[username];

    // *** FRONTEND
    const hashPassword = await hash(password);
    const {proof, publicSignals} = await generateProofLogin(password, hashPassword);
    /////
    const verificationKey = JSON.parse(fs.readFileSync(path.join(__dirname, '../circom/build/login/verification_key.json')));
    const isValid = await snarkjs.groth16.verify(verificationKey, publicSignals, proof);
    const hashServerBigInt = BigInt("0x" + user.hashPassword);
    const authen = (publicSignals[0] == hashServerBigInt);
    console.log(isValid + " " + authen);

    if (isValid && authen) {
        user.counter += 1;
        saveDatabase(db); 
        res.json({ message: `Hello ${user.name}`, success: true, username: username, password:password });
    } else {
        res.status(401).json({ message: 'Nhập sai mật khẩu' });
    }
});

app.post('/vote', async (req, res) => {
    // *** FRONTEND
    const {username, password, vote } = req.body;
    const {proof, publicSignals} = generateProofElect(username, password, vote);

    ///////

    const verificationKey = JSON.parse(fs.readFileSync(path.join(__dirname, '../circom/build/elect/verification_key.json')));
    const isValid = await snarkjs.groth16.verify(verificationKey, publicSignals, proof);
    if (!isValid || !vote || !['0', '1'].includes(vote)) {
        return res.status(400).json({ success: false, message: 'Invalid vote option.' });
    }

    // Cập nhật kết quả bầu cử
    votingResults[vote] += 1;

    res.json({
        success: true,
        message: 'Vote recorded successfully.',
        votingResults, // Trả về kết quả hiện tại
    });
});

// Lấy counter 
app.get('/get-counter/:username', (req, res) => {
    const { username } = req.params;

    const db = readDatabase();

    if (!db[username]) {
        return res.status(404).json({ message: 'User not found!' });
    }

    const user = db[username];
    res.json({ counter: user.counter });
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));

// generateProofLogin(1, hash(1));
console.log("Hello");
generateProofElect(123, 456, 0);