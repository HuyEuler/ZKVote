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
const dbVoterPath = path.join(__dirname, './database/db_voters.json');
const dbVoteResultPath = path.join(__dirname, './database/db_vote_result.json');

function readDatabase(path) {
    try {
        const data = fs.readFileSync(path, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        return {}; 
    }
}

function saveDatabase(path, db) {
    try {
        fs.writeFileSync(path, JSON.stringify(db, null, 2));
    } catch (err) {
        console.error('Error saving database:', err);
    }
}

const dbUsers = readDatabase(dbUserPath);
const dbVoters = readDatabase(dbVoterPath);
const dbVoteResult = readDatabase(dbVoteResultPath);

// Đăng ký người dùng
app.post('/register', async (req, res) => {
    const { username, name, password } = req.body;

    if (dbUsers[username]) {
        return res.status(400).json({ message: 'Username already exists!' });
    }

    // *** FRONTEND
    const hashPassword = await hash1(password);
    const hashUnamePass = await hash2(username, password)
    const voter = await BigInt("0x" + hashUnamePass); // hash username and password
    //////

    dbUsers[username] = { name, hashPassword, counter: 0 };
    saveDatabase(dbUserPath, dbUsers);

    dbVoters[voter] = 1;
    saveDatabase(dbVoterPath, dbVoters);

    res.json({ message: 'User registered successfully!' });
});

// Đăng nhập và xác thực bằng ZKP
app.post('/login', async (req, res) => {
    const { username, password} = req.body;

    if (!dbUsers[username]) {
        return res.status(404).json({ message: 'User not found!' });
    }

    const user = dbUsers[username];

    // *** FRONTEND
    const hashPassword = await hash1(password);
    const {proof, publicSignals} = await generateProofLogin(password, hashPassword);
    /////
    const verificationKey = JSON.parse(fs.readFileSync(path.join(__dirname, '../circom/build/login/verification_key.json')));
    const isValid = await snarkjs.groth16.verify(verificationKey, publicSignals, proof);
    const hashServerBigInt = BigInt("0x" + user.hashPassword);
    const authen = (publicSignals[0] == hashServerBigInt);
    // console.log(isValid + " " + authen);

    if (isValid && authen) {
        user.counter += 1;
        saveDatabase(dbUserPath, dbUsers); 
        res.json({ message: `Hello ${user.name}`, success: true, username: username, password:password });
    } else {
        res.status(401).json({ message: 'Nhập sai mật khẩu' });
    }
});

app.post('/vote', async (req, res) => {
    // *** FRONTEND
    const {username, password, vote } = req.body;
    const {proof, publicSignals} = await generateProofElect(username, password, vote);
    console.log("elect");
    console.log(publicSignals);

    ///////

    const verificationKey = JSON.parse(fs.readFileSync(path.join(__dirname, '../circom/build/elect/verification_key.json')));
    const isValid = await snarkjs.groth16.verify(verificationKey, publicSignals, proof);
    console.log(isValid);
    if (!isValid || !['0', '1'].includes(vote) || !dbVoters[publicSignals[0]]) {
        return res.status(400).json({ success: false, message: 'Invalid vote' });
    }

    if(dbVoters[publicSignals[0]] == -1){
        return res.status(400).json({ success: false, message: 'You have voted, you cannot submit your ballot twice.' });
    }

    // Cập nhật kết quả bầu cử
    dbVoteResult[vote]++;
    saveDatabase(dbVoteResultPath, dbVoteResult);

    dbVoters[publicSignals[0]] = -1;
    saveDatabase(dbVoterPath, dbVoters);

    res.json({
        success: true,
        message: 'Vote recorded successfully.',
        voteFor0: dbVoteResult['0'],
        voteFor1: dbVoteResult['1']
    });
});

app.get('/getResult', (req, res) =>{
    res.json({
        success: true,
        message: 'Vote recorded successfully.',
        voteFor0: dbVoteResult['0'],
        voteFor1: dbVoteResult['1']
    });
});

// Lấy counter 
app.get('/get-counter/:username', (req, res) => {
    const { username } = req.params;

    if (!dbUsers[username]) {
        return res.status(404).json({ message: 'User not found!' });
    }

    const user = dbUsers[username];
    res.json({ counter: user.counter });
});

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
        path.join(__dirname, '../circom/build/login/login_js/login.wasm'), 
        path.join(__dirname, '../circom/build/login/login_0001.zkey'));
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
        path.join(__dirname, '../circom/build/elect/elect_js/elect.wasm'), 
        path.join(__dirname, '../circom/build/elect/elect_0001.zkey'));
    console.log(publicSignals);
    return { proof, publicSignals };
}

app.listen(3000, () => console.log('Server running on http://localhost:3000'));

// generateProofLogin(1, hash(1));
// console.log("Hello");
// generateProofElect('123', '456', '0');

// hash2('123', '456');

// const string = "uasn";
// console.log(parseInt(string, 36));
