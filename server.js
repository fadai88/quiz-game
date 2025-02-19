const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
require('dotenv').config();
const moment = require('moment');
const nodemailer = require('nodemailer'); // Import Nodemailer
const crypto = require('crypto'); // For generating verification tokens
const User = require('./models/User');
const axios = require('axios'); // Add this line at the top with other imports
// const { Connection, PublicKey, SystemProgram, Token, TOKEN_PROGRAM_ID } = require('@solana/web3.js');
const { Connection, PublicKey, SystemProgram, Transaction, sendAndConfirmTransaction, Keypair } = require('@solana/web3.js');

const { 
    createAssociatedTokenAccountInstruction, 
    getAssociatedTokenAddress, 
    createTransferCheckedInstruction,
    TOKEN_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID
} = require('@solana/spl-token');
const { Program } = require('@project-serum/anchor');
const bs58 = require('bs58');
const nacl = require('tweetnacl');
const { Token: SPLToken } = require('@solana/spl-token');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Could not connect to MongoDB', err));

const Quiz = mongoose.model('Quiz', new mongoose.Schema({
    question: String,
    options: [String],
    correctAnswer: Number
}));

const gameRooms = new Map();

// Configure Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail', // or your email service
    auth: {
        user: process.env.EMAIL_USER, // Your email address
        pass: process.env.EMAIL_PASS, // Your app password or email password
    },
});


// Initialize config
const config = {
    USDC_MINT: new PublicKey('Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr'),
    TREASURY_WALLET: new PublicKey('GN6uUVKuijj15ULm3X954mQTKEzur9jxXdRRuLeMqmgH'),
    TREASURY_KEYPAIR: Keypair.fromSecretKey(
        Buffer.from(JSON.parse(process.env.TREASURY_SECRET_KEY))
    ),
    HOUSE_FEE_PERCENT: 2.5,
    MIN_BET_AMOUNT: 1,
    MAX_BET_AMOUNT: 100,
    connection: new Connection('https://api.devnet.solana.com', 'confirmed')
};

// Initialize connection
const connection = config.connection;

// Initialize programId
let programId;
if (process.env.PROGRAM_ID) {
    programId = new PublicKey(process.env.PROGRAM_ID);
} else {
    console.warn('Warning: PROGRAM_ID not set in environment variables');
    // Use SystemProgram.programId instead of string
    programId = SystemProgram.programId;
}

// Add the verification function
const verifyUSDCTransaction = async (transactionSignature, expectedAmount, senderAddress, recipientAddress) => {
    try {
        const connection = new Connection(process.env.SOLANA_RPC_URL, 'confirmed');
        
        // Get transaction details
        const transaction = await connection.getTransaction(transactionSignature);
        if (!transaction) {
            console.error('Transaction not found');
            return false;
        }

        // Find the token transfer instruction
        const transferInstruction = transaction.transaction.message.instructions.find(
            ix => ix.programId.equals(TOKEN_PROGRAM_ID)
        );

        if (!transferInstruction) {
            console.error('No token transfer instruction found');
            return false;
        }

        // Decode the transfer instruction
        const decodedInstruction = SPLToken.decodeTransferInstruction(transferInstruction);
        
        // Get amount in USDC (convert from raw amount)
        const amount = decodedInstruction.amount.toNumber() / Math.pow(10, 6);

        // Verify amount and addresses
        const amountMatches = Math.abs(amount - expectedAmount) < 0.01; // Allow small rounding differences
        const senderMatches = decodedInstruction.source.equals(new PublicKey(senderAddress));
        const recipientMatches = decodedInstruction.destination.equals(new PublicKey(recipientAddress));

        console.log('Transaction verification:', {
            amountMatches,
            senderMatches,
            recipientMatches,
            expectedAmount,
            actualAmount: amount
        });

        return amountMatches && senderMatches && recipientMatches;
    } catch (error) {
        console.error('Error verifying USDC transaction:', error);
        return false;
    }
};

io.on('connection', (socket) => {
    console.log('New client connected:', socket.id);

    socket.on('walletLogin', async ({ walletAddress, signature, message }) => {
        try {
            console.log('Wallet login attempt:', { walletAddress, message });
            
            // Create public key from wallet address
            const publicKey = new PublicKey(walletAddress);
            
            // Convert base64 signature back to Uint8Array
            const signatureBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
            const messageBytes = new TextEncoder().encode(message);
            
            // Verify using nacl
            const verified = nacl.sign.detached.verify(
                messageBytes,
                signatureBytes,
                publicKey.toBytes()
            );

            if (!verified) {
                console.log('Signature verification failed');
                return socket.emit('loginFailure', 'Invalid signature');
            }

            // Find or create user with only walletAddress
            let user = await User.findOne({ walletAddress });
            if (!user) {
                console.log('Creating new user for wallet:', walletAddress);
                user = await User.create({ walletAddress });
            }

            console.log('Login successful for wallet:', walletAddress);
            socket.emit('loginSuccess', {
                walletAddress: user.walletAddress,
                virtualBalance: user.virtualBalance
            });
        } catch (error) {
            console.error('Login error:', error);
            socket.emit('loginFailure', error.message);
        }
    });

    socket.on('walletReconnect', async (walletAddress) => {
        try {
            const user = await User.findOne({ walletAddress });
            if (user) {
                socket.emit('loginSuccess', {
                    walletAddress: user.walletAddress,
                    virtualBalance: user.virtualBalance
                });
            } else {
                socket.emit('loginFailure', 'Wallet not found');
            }
        } catch (error) {
            socket.emit('loginFailure', error.message);
        }
    });

    socket.on('joinGame', async (data) => {
        try {
            const { walletAddress, betAmount, transactionSignature } = data;
            console.log('Join game request:', { walletAddress, betAmount, transactionSignature });
    
            // Verify the transaction with retries
            let transaction = null;
            let retries = 5;
            while (retries > 0 && !transaction) {
                try {
                    transaction = await connection.getTransaction(transactionSignature, {
                        commitment: 'confirmed',
                        maxSupportedTransactionVersion: 0
                    });
                    if (transaction) break;
                } catch (error) {
                    console.log(`Retry ${6 - retries}: Transaction not found yet`);
                    retries--;
                    await new Promise(resolve => setTimeout(resolve, 1000));
                }
            }
    
            if (!transaction) {
                throw new Error('Transaction verification failed after retries');
            }
    
            // Verify transaction success
            if (transaction.meta.err) {
                throw new Error('Transaction failed on chain');
            }
    
            // Verify amount (if needed)
            const postTokenBalances = transaction.meta.postTokenBalances;
            const preTokenBalances = transaction.meta.preTokenBalances;
    
            if (!postTokenBalances || !preTokenBalances) {
                throw new Error('Transaction token balances not found');
            }
    
            // Find treasury token account changes
            const treasuryPostBalance = postTokenBalances.find(b => 
                b.owner === config.TREASURY_WALLET.toString()
            );
    
            const treasuryPreBalance = preTokenBalances.find(b => 
                b.owner === config.TREASURY_WALLET.toString()
            );
    
            if (!treasuryPostBalance || !treasuryPreBalance) {
                throw new Error('Treasury balance change not found in transaction');
            }
    
            const balanceChange = (treasuryPostBalance.uiTokenAmount.uiAmount || 0) -
                                (treasuryPreBalance.uiTokenAmount.uiAmount || 0);
    
            if (Math.abs(balanceChange - betAmount) > 0.001) {
                throw new Error('Transaction amount mismatch');
            }
    
            console.log('Transaction verified successfully');
    
            // Create or join game room
            let roomId;
            let joinedExistingRoom = false;
    
            // Look for an existing room with same bet amount
            for (const [id, room] of gameRooms.entries()) {
                if (room.players.length < 2 && room.betAmount === betAmount) {
                    roomId = id;
                    joinedExistingRoom = true;
                    break;
                }
            }
    
            if (!roomId) {
                roomId = generateRoomId();
                gameRooms.set(roomId, {
                    players: [],
                    questions: [],
                    currentQuestionIndex: 0,
                    answersReceived: 0,
                    betAmount: betAmount,
                    waitingTimeout: setTimeout(async () => {
                        const room = gameRooms.get(roomId);
                        if (room && room.players.length === 1) {
                            await startSinglePlayerGame(roomId);
                        }
                    }, 30000)
                });
            }
    
            const room = gameRooms.get(roomId);
            room.players.push({
                id: socket.id,
                username: walletAddress,
                score: 0,
                totalResponseTime: 0
            });
    
            socket.join(roomId);
            socket.emit('gameJoined', roomId);
    
            if (room.players.length === 2) {
                clearTimeout(room.waitingTimeout);
                startGame(roomId);
            } else if (joinedExistingRoom) {
                socket.to(roomId).emit('playerJoined', walletAddress);
            }
    
        } catch (error) {
            console.error('Join game error:', error);
            socket.emit('joinGameFailure', error.message);
        }
    });

    socket.on('submitAnswer', async ({ roomId, answer, responseTime, username }) => {
        const room = gameRooms.get(roomId);
        if (!room) return;

        const player = room.players.find(p => p.username === username);
        if (!player) return;

        player.totalResponseTime = (player.totalResponseTime || 0) + responseTime;
        player.lastAnswer = answer; // Store the player's answer

        const currentQuestion = room.questions[room.currentQuestionIndex];
        const isCorrect = answer === currentQuestion.correctAnswer;

        if (isCorrect) {
            player.score += 1;
            try {
                await User.findOneAndUpdate(
                    { username },
                    { 
                        $inc: { 
                            correctAnswers: 1,
                            totalPoints: 1
                        } 
                    }
                );
            } catch (error) {
                console.error('Error updating user stats:', error);
            }
        }

        player.answered = true;

        // Send result only to the player who answered
        socket.emit('answerResult', {
            username: player.username,
            isCorrect,
            correctAnswer: currentQuestion.correctAnswer
        });

        if (room.players.every(p => p.answered)) {
            // When all players have answered, send the complete results to everyone
            io.to(roomId).emit('roundComplete', {
                correctAnswer: currentQuestion.correctAnswer,
                playerResults: room.players.map(p => ({
                    username: p.username,
                    isCorrect: p.lastAnswer === currentQuestion.correctAnswer,
                    answer: p.lastAnswer
                }))
            });
            await completeQuestion(roomId);
        } else {
            // Just update that a player has answered without revealing the answer
            socket.to(roomId).emit('playerAnswered', username);
        }
    });

    socket.on('getLeaderboard', async () => {
        try {
            const leaderboard = await User.find({}, 'username correctAnswers gamesPlayed totalPoints')
                .sort({ totalPoints: -1 })
                .limit(10);
            socket.emit('leaderboardData', leaderboard);
        } catch (error) {
            console.error('Error fetching leaderboard:', error);
            socket.emit('leaderboardError', 'Failed to fetch leaderboard data');
        }
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
        for (const [roomId, room] of gameRooms.entries()) {
            const playerIndex = room.players.findIndex(p => p.id === socket.id);
            if (playerIndex !== -1) {
                const disconnectedPlayer = room.players[playerIndex];
                room.players.splice(playerIndex, 1);
                console.log(`Player ${disconnectedPlayer.username} left room ${roomId}`);
                if (room.players.length === 0) {
                    console.log(`Deleting empty room ${roomId}`);
                    gameRooms.delete(roomId);
                } else {
                    console.log(`Notifying remaining player in room ${roomId}`);
                    io.to(roomId).emit('playerLeft', disconnectedPlayer.username);
                }
                break;
            }
        }
    });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (user && await user.matchPassword(password)) {
            res.json({ 
                success: true, 
                message: 'Login successful', 
                username: user.username,
                virtualBalance: user.virtualBalance
            });
        } else {
            res.json({ success: false, message: 'Invalid credentials' });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/balance/:wallet', async (req, res) => {
    try {
        const user = await User.findOne({ walletAddress: req.params.wallet });
        if (user) {
            res.json({ balance: user.virtualBalance });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/topup/:wallet', async (req, res) => {
    try {
        const user = await User.findOneAndUpdate(
            { walletAddress: req.params.wallet },
            { $inc: { virtualBalance: 10 } },
            { new: true }
        );
        if (user) {
            res.json({ success: true, newBalance: user.virtualBalance });
        } else {
            res.status(404).json({ success: false, message: 'User not found' });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

async function startGame(roomId) {
    console.log(`Attempting to start game in room ${roomId}`);
    const room = gameRooms.get(roomId);
    if (!room) {
        console.log(`Room ${roomId} not found when trying to start game`);
        return;
    }

    room.players.forEach(player => player.score = 0);

    try {
        // Fetch 7 random questions from MongoDB
        room.questions = await Quiz.aggregate([{ $sample: { size: 7 } }]);
        console.log(`Fetched ${room.questions.length} questions for room ${roomId}`);
        io.to(roomId).emit('gameStart', { players: room.players, questionCount: room.questions.length });
        startNextQuestion(roomId);
    } catch (error) {
        console.error('Error starting game:', error);
        io.to(roomId).emit('gameError', 'Failed to start the game. Please try again.');
    }
}

function startNextQuestion(roomId) {
    const room = gameRooms.get(roomId);
    if (!room) {
        console.log(`Room ${roomId} not found when trying to start next question`);
        return;
    }

    const currentQuestion = room.questions[room.currentQuestionIndex];
    const questionStartTime = moment();

    io.to(roomId).emit('nextQuestion', {
        question: currentQuestion.question,
        options: currentQuestion.options,
        questionNumber: room.currentQuestionIndex + 1,
        totalQuestions: room.questions.length,
        questionStartTime: questionStartTime.valueOf(),
        correctAnswerIndex: currentQuestion.correctAnswer
    });

    room.questionStartTime = questionStartTime;
    room.answersReceived = 0;

    // Clear any existing timeout
    if (room.questionTimeout) {
        clearTimeout(room.questionTimeout);
    }

    // Set a new timeout for this question
    room.questionTimeout = setTimeout(async () => {
        await completeQuestion(roomId);
    }, 10000); // 10 seconds for each question
}

async function completeQuestion(roomId) {
    const room = gameRooms.get(roomId);
    if (!room) return;

    // Reset answered status for next question
    room.players.forEach(player => {
        player.answered = false;
    });

    io.to(roomId).emit('updateScores', room.players.map(p => ({ 
        username: p.username, 
        score: p.score, 
        totalResponseTime: p.totalResponseTime || 0
    })));

    if (room.questionTimeout) {
        clearTimeout(room.questionTimeout);
    }

    room.currentQuestionIndex += 1;
    room.answersReceived = 0;

    if (room.currentQuestionIndex < room.questions.length) {
        setTimeout(() => {
            startNextQuestion(roomId);
        }, 1000);
    } else {
        console.log(`Game over in room ${roomId}`);
        const isSinglePlayer = room.players.length === 1;
        let winner = null;

        if (isSinglePlayer) {
            const player = room.players[0];
            winner = player.score >= 5 ? player.username : null;
            console.log(`Single player game ended. Player ${player.username} scored ${player.score}/7 ${winner ? '(WIN)' : '(LOSS)'}`);
        } else {
            const sortedPlayers = [...room.players].sort((a, b) => {
                if (b.score !== a.score) {
                    return b.score - a.score;
                }
                return (a.totalResponseTime || 0) - (b.totalResponseTime || 0);
            });

            // Log detailed game results
            console.log('Game Results:');
            sortedPlayers.forEach(player => {
                console.log(`Player ${player.username}: ${player.score} correct answers, Response time: ${player.totalResponseTime}ms`);
            });

            if (sortedPlayers[0].score > sortedPlayers[1].score) {
                winner = sortedPlayers[0].username;
                console.log(`Winner by score: ${winner} (${sortedPlayers[0].score} vs ${sortedPlayers[1].score})`);
            } else if (sortedPlayers[0].score === sortedPlayers[1].score) {
                winner = sortedPlayers[0].totalResponseTime <= sortedPlayers[1].totalResponseTime ? 
                    sortedPlayers[0].username : sortedPlayers[1].username;
                console.log(`Tie on score (${sortedPlayers[0].score}), Winner by response time: ${winner}`);
                console.log(`Response times: ${sortedPlayers[0].username}: ${sortedPlayers[0].totalResponseTime}ms, ${sortedPlayers[1].username}: ${sortedPlayers[1].totalResponseTime}ms`);
            }
        }

        // Update winner's balance if there is a winner
        if (winner) {
            try {
                const payoutSignature = await sendWinnings(winner, room.betAmount);
                io.to(roomId).emit('gameOver', {
                    players: room.players.map(p => ({ 
                        username: p.username, 
                        score: p.score, 
                        totalResponseTime: p.totalResponseTime || 0
                    })),
                    winner: winner,
                    betAmount: room.betAmount,
                    payoutSignature,
                    singlePlayerMode: isSinglePlayer
                });
            } catch (error) {
                console.error('Error processing payout:', error);
                io.to(roomId).emit('gameOver', {
                    error: 'Error processing payout. Please contact support.',
                    players: room.players.map(p => ({ 
                        username: p.username, 
                        score: p.score, 
                        totalResponseTime: p.totalResponseTime || 0
                    })),
                    winner: winner,
                    betAmount: room.betAmount,
                    singlePlayerMode: isSinglePlayer
                });
            }
        } else {
            io.to(roomId).emit('gameOver', {
                players: room.players.map(p => ({ 
                    username: p.username, 
                    score: p.score, 
                    totalResponseTime: p.totalResponseTime || 0
                })),
                winner: null,
                betAmount: room.betAmount,
                singlePlayerMode: isSinglePlayer
            });
        }

        gameRooms.delete(roomId);
    }
}
/*
// Remove or simplify the determineWinner function since the logic is now in completeQuestion
function determineWinner(players) {
    const sortedPlayers = [...players].sort((a, b) => {
        if (b.score !== a.score) {
            return b.score - a.score;
        }
        return (a.totalResponseTime || 0) - (b.totalResponseTime || 0);
    });

    return sortedPlayers[0].username;
}
*/

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// Function to generate a unique room ID
function generateRoomId() {
    return Math.random().toString(36).substring(7);
}


// Email verification endpoint
app.get('/verify-email', async (req, res) => {
    const { token } = req.query;

    try {
        const user = await User.findOne({ verificationToken: token });
        if (!user) {
            return res.status(400).send('Invalid verification token');
        }

        user.isVerified = true;
        user.verificationToken = undefined; // Clear the token
        await user.save();

        console.log(`User verified successfully: ${user.username}`); // Log verification
        res.send('Email verified successfully! You can now join the game.');
    } catch (error) {
        res.status(500).send('Error verifying email');
    }
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const verificationToken = crypto.randomBytes(32).toString('hex'); // Generate token
        const user = new User({ username, email, password, verificationToken, isVerified: false }); // Save user with verificationToken
        await user.save();

        // Send verification email
        const verificationUrl = `${process.env.BASE_URL}/verify-email?token=${verificationToken}`;
        await transporter.sendMail({
            to: email,
            subject: 'Email Verification',
            html: `Please verify your email by clicking <a href="${verificationUrl}">here</a>`,
        });

        console.log(`User registered: ${username}, pending verification`); // Log registration
        res.status(201).json({ success: true, message: 'Registration successful! Please check your email to verify your account.' });
    } catch (error) {
        res.status(400).json({ success: false, message: error.message });
    }
});

// Function to verify reCAPTCHA token
async function verifyRecaptcha(token) {
    const secretKey = process.env.RECAPTCHA_SECRET_KEY; // Ensure this is set correctly
    const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, {
        params: {
            secret: secretKey,
            response: token
        }
    });
    console.log('reCAPTCHA verification response:', response.data); // Log the verification response
    return response.data;
}

// Add new function for single player mode
async function startSinglePlayerGame(roomId) {
    const room = gameRooms.get(roomId);
    if (!room) return;

    try {
        room.questions = await Quiz.aggregate([{ $sample: { size: 7 } }]);
        const player = room.players[0];
        
        io.to(roomId).emit('gameStart', { 
            players: room.players, 
            questionCount: room.questions.length,
            singlePlayerMode: true 
        });

        startNextQuestion(roomId);
    } catch (error) {
        console.error('Error starting single player game:', error);
        io.to(roomId).emit('gameError', 'Failed to start the game. Please try again.');
    }
}

// Add helper functions if they don't exist
function findAvailableRoom(betAmount) {
    for (const [roomId, room] of gameRooms.entries()) {
        if (room.players.length < 2 && room.betAmount === betAmount) {
            return roomId;
        }
    }
    return null;
}

function createGameRoom(roomId, betAmount) {
    gameRooms.set(roomId, {
        players: [],
        betAmount,
        questions: [],
        currentQuestionIndex: 0,
        answersReceived: 0
    });
}

function addPlayerToRoom(roomId, socketId, walletAddress) {
    const room = gameRooms.get(roomId);
    if (room) {
        room.players.push({
            id: socketId,
            walletAddress,
            score: 0
        });
    }
}

async function sendWinnings(winnerAddress, betAmount) {
    try {
        const winnerPublicKey = new PublicKey(winnerAddress);
        
        // Calculate winnings (80% profit)
        const winningAmount = betAmount * 1.8;
        
        // Get token accounts
        const treasuryTokenAccount = await findAssociatedTokenAddress(
            config.TREASURY_WALLET,
            config.USDC_MINT
        );

        const winnerTokenAccount = await findAssociatedTokenAddress(
            winnerPublicKey,
            config.USDC_MINT
        );

        // Create transfer instruction
        const transferIx = createTransferCheckedInstruction(
            treasuryTokenAccount,
            config.USDC_MINT,
            winnerTokenAccount,
            config.TREASURY_WALLET,
            Math.floor(winningAmount * Math.pow(10, 6)), // Convert to USDC decimals
            6
        );

        // Create and send transaction
        const transaction = new Transaction().add(transferIx);
        transaction.feePayer = config.TREASURY_WALLET;
        transaction.recentBlockhash = (await config.connection.getRecentBlockhash()).blockhash;

        // Sign and send transaction
        const signature = await sendAndConfirmTransaction(
            config.connection,
            transaction,
            [config.TREASURY_KEYPAIR] // Use the treasury keypair for signing
        );

        console.log('Payout successful:', signature);
        return signature;
    } catch (error) {
        console.error('Error sending winnings:', error);
        throw error;
    }
}

async function verifyPayout(signature, expectedAmount, recipientAddress) {
    try {
        const transaction = await connection.getTransaction(signature, {
            commitment: 'confirmed'
        });

        if (!transaction || transaction.meta.err) {
            return false;
        }

        const postBalances = transaction.meta.postTokenBalances;
        const recipientBalance = postBalances.find(b => 
            b.owner === recipientAddress
        );

        if (!recipientBalance) {
            return false;
        }

        const receivedAmount = recipientBalance.uiTokenAmount.uiAmount;
        return Math.abs(receivedAmount - expectedAmount) < 0.001;
    } catch (error) {
        console.error('Error verifying payout:', error);
        return false;
    }
}

async function findAssociatedTokenAddress(walletAddress, tokenMintAddress) {
    return await getAssociatedTokenAddress(
        tokenMintAddress,
        walletAddress,
        false,
        TOKEN_PROGRAM_ID,
        ASSOCIATED_TOKEN_PROGRAM_ID
    );
}