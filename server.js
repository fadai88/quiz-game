const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();
const moment = require('moment');
const crypto = require('crypto'); // For generating verification tokens
const User = require('./models/User');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
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

// LOOKT AT THIS FUNCTION AGAIN WHEN THE GAME IS LIVE!!!
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(async () => {
        console.log('Connected to MongoDB');
        
        // Drop both problematic indexes
        try {
            const collections = await mongoose.connection.db.collections();
            const usersCollection = collections.find(c => c.collectionName === 'users');
            
            if (usersCollection) {
                // Drop both username and email indexes
                const indexes = await usersCollection.indexes();
                
                for (const index of indexes) {
                    // Only drop the single-field unique indexes for username and email
                    if (index.name === 'username_1' || index.name === 'email_1') {
                        console.log(`Dropping index: ${index.name}`);
                        await usersCollection.dropIndex(index.name);
                    }
                }
                
                console.log('Successfully dropped problematic indexes');
            }
        } catch (error) {
            console.error('Error dropping indexes:', error);
            // Continue anyway - the indexes might not exist
        }
    })
    .catch(err => console.error('Could not connect to MongoDB', err));

const Quiz = mongoose.model('Quiz', new mongoose.Schema({
    question: String,
    options: [String],
    correctAnswer: Number
}));

const gameRooms = new Map();


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

const Redis = require('ioredis');
let redisClient;

try {
    redisClient = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
    console.log('Redis connected for rate limiting');
} catch (error) {
    console.warn('Redis not available, using in-memory rate limiting');
    // Simple in-memory storage for rate limiting if Redis isn't available
    redisClient = {
        rateLimits: {},
        async get(key) {
            return this.rateLimits[key] || 0;
        },
        async set(key, value, expType, expValue) {
            this.rateLimits[key] = value;
            // Simple expiration
            if (expType === 'EX') {
                setTimeout(() => {
                    delete this.rateLimits[key];
                }, expValue * 1000);
            }
        }
    };
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

const BOT_LEVELS = {
    MEDIUM: { correctRate: 0.6, responseTimeRange: [1500, 4000] },  // 60% correct, 1.5-4 seconds
    HARD: { correctRate: 0.8, responseTimeRange: [1000, 3000] }     // 80% correct, 1-3 seconds
};

// Bot player class
class TriviaBot {
    constructor(botName = 'BrainyBot', difficulty = 'MEDIUM') {
        this.id = `bot-${Date.now()}`;
        this.username = botName;
        this.score = 0;
        this.totalResponseTime = 0;
        this.difficulty = BOT_LEVELS[difficulty] || BOT_LEVELS.MEDIUM;
        this.currentQuestionIndex = 0;
        this.answersGiven = [];
        this.isBot = true;
    }

    async answerQuestion(question, options, correctAnswer) {
        // Determine if the bot will answer correctly based on difficulty
        const willAnswerCorrectly = Math.random() < this.difficulty.correctRate;
        
        // Choose answer
        let botAnswer;
        if (willAnswerCorrectly) {
            botAnswer = correctAnswer;
        } else {
            // Select a random incorrect answer
            const incorrectOptions = Array.from(Array(options.length).keys())
                .filter(index => index !== correctAnswer);
            botAnswer = incorrectOptions[Math.floor(Math.random() * incorrectOptions.length)];
        }
        
        // Determine response time within the difficulty's range
        const [minTime, maxTime] = this.difficulty.responseTimeRange;
        const responseTime = Math.floor(Math.random() * (maxTime - minTime)) + minTime;
        
        // Simulate "thinking" time
        await new Promise(resolve => setTimeout(resolve, responseTime));
        
        // Update bot stats
        this.totalResponseTime += responseTime;
        if (botAnswer === correctAnswer) {
            this.score += 1;
        }
        
        this.answersGiven.push({
            questionIndex: this.currentQuestionIndex++,
            answer: botAnswer,
            isCorrect: botAnswer === correctAnswer,
            responseTime
        });
        
        return {
            answer: botAnswer,
            responseTime,
            isCorrect: botAnswer === correctAnswer
        };
    }
    
    // For analytics and fun facts
    getStats() {
        return {
            totalQuestionsAnswered: this.answersGiven.length,
            correctAnswers: this.score,
            averageResponseTime: this.totalResponseTime / Math.max(1, this.answersGiven.length),
            answersGiven: this.answersGiven
        };
    }
}

io.on('connection', (socket) => {
    console.log('New client connected:', socket.id);
    
    // Track connection data
    const connectionData = {
        ip: socket.handshake.headers['x-forwarded-for'] || socket.handshake.address,
        userAgent: socket.handshake.headers['user-agent'],
        timestamp: new Date(),
        sessionId: socket.id
    };
    
    // Check if IP is in blocklist
    if (redisClient) {  // Add check for redisClient existence
        (async () => {
            try {
                const isBlocked = await redisClient.get(`blocklist:${connectionData.ip}`);
                if (isBlocked) {
                    console.warn(`Blocked IP attempting to connect: ${connectionData.ip}`);
                    socket.disconnect();
                }
            } catch (error) {
                console.error('Error checking IP blocklist:', error);
            }
        })();
    }

    socket.on('walletLogin', async ({ walletAddress, signature, message, recaptchaToken, clientData }) => {
        try {
            console.log('Wallet login attempt:', { walletAddress, message });
            
            // 1. Rate limiting check
            if (redisClient) {
                const clientIP = connectionData.ip;
                const loginLimitKey = `login:${clientIP}`;
                try {
                    const loginAttempts = await redisClient.get(loginLimitKey) || 0;
                            // DECREASE THE THRESHOLD WHEN THE GAME IS LIVE!!!
                    if (loginAttempts > 100) {
                        console.warn(`Rate limit exceeded for IP ${clientIP}`);
                        return socket.emit('loginFailure', 'Too many login attempts. Please try again later.');
                    }
                    
                    await redisClient.set(loginLimitKey, parseInt(loginAttempts) + 1, 'EX', 3600);
                } catch (error) {
                    console.error('Redis rate limiting error:', error);
                }
            }
            
            // 2. reCAPTCHA verification (if enabled)
            if (process.env.ENABLE_RECAPTCHA && recaptchaToken) {
                try {
                    const recaptchaResult = await verifyRecaptcha(recaptchaToken);
                    if (!recaptchaResult.success) {
                        console.warn(`reCAPTCHA verification failed for wallet ${walletAddress}`);
                        return socket.emit('loginFailure', 'Verification failed. Please try again.');
                    }
                } catch (error) {
                    console.error('reCAPTCHA verification error:', error);
                    return socket.emit('loginFailure', 'Verification service unavailable. Please try again later.');
                }
            }
            
            // 3. Signature verification
            try {
                const publicKey = new PublicKey(walletAddress);
                const signatureBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
                const messageBytes = new TextEncoder().encode(message);
                
                const verified = nacl.sign.detached.verify(
                    messageBytes,
                    signatureBytes,
                    publicKey.toBytes()
                );

                if (!verified) {
                    console.warn(`Invalid signature for wallet ${walletAddress}`);
                    return socket.emit('loginFailure', 'Invalid signature');
                }
            } catch (error) {
                console.error('Signature verification error:', error);
                return socket.emit('loginFailure', 'Invalid wallet credentials');
            }

            // 4. Find or create user
            try {
                let user = await User.findOne({ walletAddress });
                if (!user) {
                    console.log('Creating new user for wallet:', walletAddress);
                    user = await User.create({ 
                        walletAddress,
                        registrationIP: connectionData.ip,
                        registrationDate: new Date(),
                        lastLoginIP: connectionData.ip,
                        lastLoginDate: new Date(),
                        userAgent: connectionData.userAgent
                    });
                } else {
                    // Update login information
                    user.lastLoginIP = connectionData.ip;
                    user.lastLoginDate = new Date();
                    user.userAgent = connectionData.userAgent;
                    await user.save();
                }

                // Log successful login
                console.log('Login successful for wallet:', walletAddress);
                
                // Emit success response with minimal user data
                socket.emit('loginSuccess', {
                    walletAddress: user.walletAddress,
                    virtualBalance: user.virtualBalance
                });
            } catch (error) {
                console.error('Database error during login:', error);
                socket.emit('loginFailure', 'Server error during login. Please try again.');
            }
        } catch (error) {
            console.error('Unexpected login error:', error);
            socket.emit('loginFailure', 'An unexpected error occurred. Please try again.');
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
                    waitingTimeout: null,
                    gameStarted: false // Flag to track if game has started
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
    
            if (joinedExistingRoom) {
                socket.to(roomId).emit('playerJoined', walletAddress);
            }
    
        } catch (error) {
            console.error('Join game error:', error);
            socket.emit('joinGameFailure', error.message);
        }
    });

    socket.on('playerReady', ({ roomId }) => {
        console.log(`Player ${socket.id} ready in room ${roomId}`);
        const room = gameRooms.get(roomId);
        
        if (!room) {
            return socket.emit('gameError', 'Room not found');
        }
        
        // Only start the game if there are 2 players and game hasn't started yet
        if (room.players.length === 2 && !room.gameStarted) {
            room.gameStarted = true;
            startGame(roomId);
        }
    });

    socket.on('requestBotGame', async ({ roomId }) => {
        console.log(`Bot game requested for room ${roomId}`);
        const room = gameRooms.get(roomId);
        
        if (!room) {
            socket.emit('gameError', 'Room not found');
            return;
        }
        
        // Clear any existing timeout
        if (room.waitingTimeout) {
            clearTimeout(room.waitingTimeout);
        }
        
        // Start single player game with bot
        await startSinglePlayerGame(roomId);
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

app.get('/login.html', (req, res) => {
    // Read the file
    let loginHtml = fs.readFileSync(path.join(__dirname, 'public', 'login.html'), 'utf8');
    
    // Inject the reCAPTCHA setting
    const recaptchaEnabled = process.env.ENABLE_RECAPTCHA === 'true';
    const recaptchaSiteKey = process.env.RECAPTCHA_SITE_KEY || '';
    
    // Replace both the site key and add the enabled flag
    loginHtml = loginHtml.replace('YOUR_SITE_KEY', recaptchaSiteKey);
    loginHtml = loginHtml.replace(
        '<script>',
        `<script>
        window.recaptchaEnabled = ${recaptchaEnabled};
        window.recaptchaSiteKey = "${recaptchaSiteKey}";`
    );
    
    // Send the modified HTML
    res.send(loginHtml);
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

    // Send question to human players
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

    // If room has a bot, get their answer
    const bot = room.players.find(p => p.isBot);
    if (bot) {
        // Bot will answer according to its difficulty
        bot.answerQuestion(
            currentQuestion.question, 
            currentQuestion.options, 
            currentQuestion.correctAnswer
        ).then(botAnswer => {
            // Emit that bot has answered
            io.to(roomId).emit('playerAnswered', bot.username);
            
            // Check if both players have answered
            const humanPlayer = room.players.find(p => !p.isBot);
            if (humanPlayer.answered) {
                io.to(roomId).emit('roundComplete', {
                    correctAnswer: currentQuestion.correctAnswer,
                    playerResults: room.players.map(p => ({
                        username: p.username,
                        isCorrect: p === bot ? 
                            botAnswer.isCorrect : 
                            p.lastAnswer === currentQuestion.correctAnswer,
                        answer: p === bot ? botAnswer.answer : p.lastAnswer
                    }))
                });
                completeQuestion(roomId);
            }
        });
    }

    // Set a timeout for this question
    room.questionTimeout = setTimeout(async () => {
        // If time's up and the human player hasn't answered,
        // mark as incorrect and proceed
        room.players.forEach(player => {
            if (!player.isBot && !player.answered) {
                player.answered = true;
                player.lastAnswer = -1; // Invalid answer
                io.to(roomId).emit('playerAnswered', player.username);
            }
        });
        
        await completeQuestion(roomId);
    }, 10000); // 10 seconds for each question
}

// Helper function to handle bot answers
async function handleBotAnswer(room, bot, currentQuestion) {
    try {
        const botAnswer = await bot.answerQuestion(
            currentQuestion.question, 
            currentQuestion.options, 
            currentQuestion.correctAnswer
        );

        // Store bot's answer
        bot.answered = true;
        bot.lastAnswer = botAnswer.answer;
        
        // Emit bot's answer event
        io.to(room.id).emit('playerAnswered', {
            username: bot.username,
            isBot: true,
            responseTime: botAnswer.responseTime
        });
        
        // Check if round is complete
        const humanPlayer = room.players.find(p => !p.isBot);
        if (humanPlayer.answered) {
            emitRoundComplete(room, currentQuestion.correctAnswer, botAnswer);
        }
    } catch (error) {
        console.error('Error handling bot answer:', error);
        // Handle bot error gracefully - maybe give it a wrong answer
        bot.answered = true;
        bot.lastAnswer = -1;
    }
}

// Helper function to handle question timeout
async function handleQuestionTimeout(room, roomId) {
    const unansweredPlayers = room.players.filter(player => !player.answered && !player.isBot);
    
    unansweredPlayers.forEach(player => {
        player.answered = true;
        player.lastAnswer = -1;
        io.to(roomId).emit('playerAnswered', {
            username: player.username,
            isBot: false,
            timedOut: true
        });
    });

    if (unansweredPlayers.length > 0) {
        await completeQuestion(roomId);
    }
}

// Helper function to emit round completion
function emitRoundComplete(room, correctAnswer, botAnswer) {
    io.to(room.id).emit('roundComplete', {
        correctAnswer: correctAnswer,
        playerResults: room.players.map(p => ({
            username: p.username,
            isCorrect: p.isBot ? 
                botAnswer.isCorrect : 
                p.lastAnswer === correctAnswer,
            answer: p.isBot ? botAnswer.answer : p.lastAnswer,
            responseTime: p.isBot ? botAnswer.responseTime : p.responseTime,
            isBot: p.isBot || false
        }))
    });
    
    completeQuestion(room.id);
}

function chooseBotName() {
    const botNames = [
        'BrainyBot', 'QuizMaster', 'Trivia Titan', 'FactFinder', 
        'QuestionQueen', 'KnowledgeKing', 'TriviaWhiz', 'WisdomBot',
        'FactBot', 'QuizGenius', 'BrainiacBot', 'TriviaLegend'
    ];
    return botNames[Math.floor(Math.random() * botNames.length)];
}

// Determine bot difficulty based on player stats or other factors
async function determineBotDifficulty(playerUsername) {
    try {
        const player = await User.findOne({ walletAddress: playerUsername });
        
        if (!player || player.gamesPlayed < 3) {
            return 'MEDIUM';
        }
        
        const winRate = player.wins / player.gamesPlayed;
        return winRate < 0.4 ? 'MEDIUM' : 'HARD';
    } catch (error) {
        console.error('Error determining bot difficulty:', error);
        return 'HARD';
    }
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
        totalResponseTime: p.totalResponseTime || 0,
        isBot: p.isBot || false
    })));

    if (room.questionTimeout) {
        clearTimeout(room.questionTimeout);
    }

    room.currentQuestionIndex += 1;
    room.answersReceived = 0;

    if (room.currentQuestionIndex < room.questions.length) {
        setTimeout(() => {
            startNextQuestion(roomId);
        }, 2000); // Slightly longer pause between questions for better UX
    } else {
        // Game over logic remains similar, just ensure bot is properly included
        console.log(`Game over in room ${roomId}`);
        const sortedPlayers = [...room.players].sort((a, b) => {
            if (b.score !== a.score) {
                return b.score - a.score;
            }
            return (a.totalResponseTime || 0) - (b.totalResponseTime || 0);
        });

        // Log detailed game results
        console.log('Game Results:');
        sortedPlayers.forEach(player => {
            console.log(`Player ${player.username}${player.isBot ? ' (BOT)' : ''}: ${player.score} correct answers, Response time: ${player.totalResponseTime}ms`);
        });

        // Determine winner
        let winner = null;
        if (sortedPlayers[0].score > sortedPlayers[1].score) {
            winner = sortedPlayers[0].username;
        } else if (sortedPlayers[0].score === sortedPlayers[1].score) {
            winner = sortedPlayers[0].totalResponseTime <= sortedPlayers[1].totalResponseTime ? 
                sortedPlayers[0].username : sortedPlayers[1].username;
        }

        // If human player won, process payout
        if (winner && !sortedPlayers.find(p => p.username === winner)?.isBot) {
            try {
                const botOpponent = room.players.some(p => p.isBot);
                const payoutSignature = await sendWinnings(winner, room.betAmount, botOpponent);
                io.to(roomId).emit('gameOver', {
                    players: room.players.map(p => ({ 
                        username: p.username, 
                        score: p.score, 
                        totalResponseTime: p.totalResponseTime || 0,
                        isBot: p.isBot || false
                    })),
                    winner: winner,
                    betAmount: room.betAmount,
                    payoutSignature,
                    botOpponent: botOpponent
                });
            } catch (error) {
                console.error('Error processing payout:', error);
                io.to(roomId).emit('gameOver', {
                    error: 'Error processing payout. Please contact support.',
                    players: room.players.map(p => ({ 
                        username: p.username, 
                        score: p.score, 
                        totalResponseTime: p.totalResponseTime || 0,
                        isBot: p.isBot || false
                    })),
                    winner: winner,
                    betAmount: room.betAmount,
                    botOpponent: room.hasBot
                });
            }
        } else {
            // No payout if bot won
            io.to(roomId).emit('gameOver', {
                players: room.players.map(p => ({ 
                    username: p.username, 
                    score: p.score, 
                    totalResponseTime: p.totalResponseTime || 0,
                    isBot: p.isBot || false
                })),
                winner: winner,
                betAmount: room.betAmount,
                botOpponent: room.hasBot
            });
        }

        gameRooms.delete(roomId);
    }
}

// Helper function to handle game over logic
async function handleGameOver(room, roomId) {
    console.log(`Game over in room ${roomId}`);
    
    const sortedPlayers = [...room.players].sort((a, b) => {
        if (b.score !== a.score) return b.score - a.score;
        return (a.totalResponseTime || 0) - (b.totalResponseTime || 0);
    });

    // Log detailed results
    console.log('Game Results:');
    sortedPlayers.forEach(player => {
        console.log(`Player ${player.username}${player.isBot ? ' (BOT)' : ''}: ${player.score} correct answers, Response time: ${player.totalResponseTime || 0}ms`);
    });

    // Determine winner
    const winner = determineWinner(sortedPlayers);

    // Handle payout and emit game over event
    await handleGameOverEmit(room, sortedPlayers, winner, roomId);

    // Cleanup
    gameRooms.delete(roomId);
}


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


// Function to verify reCAPTCHA token
async function verifyRecaptcha(token) {
    if (process.env.ENABLE_RECAPTCHA !== 'true') {
        console.log('reCAPTCHA verification skipped (disabled in config)');
        return { success: true, score: 1.0 };
    }
    try {
        const secretKey = process.env.RECAPTCHA_SECRET_KEY;
        if (!secretKey) {
            console.warn('reCAPTCHA secret key not configured, skipping verification');
            return { success: true, score: 1.0 }; // Default to success in development
        }
        
        const response = await axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
            params: {
                secret: secretKey,
                response: token
            }
        });
        
        console.log('reCAPTCHA verification response:', response.data);
        
        // Add proper validation
        if (!response.data.success) {
            console.warn('reCAPTCHA verification failed:', response.data['error-codes']);
            return { success: false, error: response.data['error-codes'] };
        }
        
        // Validate score for v3 (threshold 0.5 is recommended by Google)
        if (response.data.score !== undefined && response.data.score < 0.5) {
            console.warn(`reCAPTCHA score too low: ${response.data.score}`);
            return { success: false, score: response.data.score, error: 'Bot activity suspected' };
        }
        
        return { success: true, score: response.data.score };
    } catch (error) {
        console.error('reCAPTCHA verification error:', error);
        return { success: false, error: 'Verification service error' };
    }
}

const suspiciousActivity = {
    ips: {},
    wallets: {}
};

// Add new function for single player mode
async function startSinglePlayerGame(roomId) {
    console.log('Starting single player game with bot for room:', roomId);
    const room = gameRooms.get(roomId);
    if (!room) {
        console.log('Room not found for bot creation');
        return;
    }

    try {
        // Get questions
        room.questions = await Quiz.aggregate([{ $sample: { size: 7 } }]);
        const humanPlayer = room.players[0];
        console.log('Human player:', humanPlayer.username);
        
        // Create a bot and add it to the room
        const difficulty = await determineBotDifficulty(humanPlayer.username);
        const botName = chooseBotName();
        console.log('Creating bot with name:', botName, 'and difficulty:', difficulty);
        
        const bot = new TriviaBot(botName, difficulty);
        room.players.push(bot);
        room.hasBot = true;
        console.log('Bot added to room. Total players:', room.players.length);
        
        // Send specific bot ready event to the client
        io.to(roomId).emit('botGameReady', {
            botName: bot.username,
            difficulty: difficulty
        });
        
        // Then start the game like before
        io.to(roomId).emit('gameStart', { 
            players: room.players.map(p => ({
                username: p.username,
                score: p.score,
                isBot: p.isBot || false,
                difficulty: p.isBot ? difficulty : undefined
            })),
            questionCount: room.questions.length,
            singlePlayerMode: false,
            botOpponent: bot.username
        });

        startNextQuestion(roomId);
    } catch (error) {
        console.error('Error starting single player game with bot:', error);
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

async function sendWinnings(winnerAddress, betAmount, botOpponent = false) {
    try {
        const winnerPublicKey = new PublicKey(winnerAddress);
        const multiplier = botOpponent ? 1.5 : 1.8;
        const winningAmount = betAmount * multiplier;
        
        console.log(`Sending winnings: ${winningAmount} USDC to ${winnerAddress} (vs bot: ${botOpponent})`);
        
        const treasuryTokenAccount = await findAssociatedTokenAddress(
            config.TREASURY_WALLET,
            config.USDC_MINT
        );

        const winnerTokenAccount = await findAssociatedTokenAddress(
            winnerPublicKey,
            config.USDC_MINT
        );

        const transferIx = createTransferCheckedInstruction(
            treasuryTokenAccount,
            config.USDC_MINT,
            winnerTokenAccount,
            config.TREASURY_WALLET,
            Math.floor(winningAmount * Math.pow(10, 6)),
            6
        );

        const transaction = new Transaction().add(transferIx);
        transaction.feePayer = config.TREASURY_WALLET;
        transaction.recentBlockhash = (await config.connection.getRecentBlockhash()).blockhash;

        const signature = await sendAndConfirmTransaction(
            config.connection,
            transaction,
            [config.TREASURY_KEYPAIR]
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

app.get('/api/tokens.json', (req, res) => {
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.warn(`Potential bot detected accessing honeypot: ${clientIP}`);
    redisClient.set(`blocklist:${clientIP}`, 1, 'EX', 86400); // Block for 24 hours
    
    // Return fake data
    res.json({ status: "success", data: { tokens: [] } });
});

app.get('/admin', (req, res) => {
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.warn(`Potential bot detected accessing admin honeypot: ${clientIP}`);
    redisClient.set(`blocklist:${clientIP}`, 1, 'EX', 86400);
    
    // Redirect to home
    res.redirect('/');
});

// Add suspicious wallet detection during game play
async function detectSuspiciousWalletActivity(walletAddress) {
    // Check for too many games in short period
    const recentGames = await Game.countDocuments({
        'players.walletAddress': walletAddress,
        createdAt: { $gte: new Date(Date.now() - 1000 * 60 * 60) } // Last hour
    });
    
    if (recentGames > 20) {
        console.warn(`Suspicious activity: Wallet ${walletAddress} played ${recentGames} games in the last hour`);
        return true;
    }
    
    // Check win rate (if abnormally high)
    const stats = await User.findOne({ walletAddress });
    if (stats && stats.gamesPlayed > 10 && (stats.wins / stats.gamesPlayed > 0.8)) {
        console.warn(`Suspicious activity: Wallet ${walletAddress} has ${stats.wins}/${stats.gamesPlayed} wins`);
        return true;
    }
    
    return false;
}

function determineWinner(players) {
    if (!players || players.length === 0) {
      return null;
    }
    
    if (players.length === 1) {
      // Single player mode - win if score is 5 or more (or use your threshold logic)
      return players[0].score >= 5 ? players[0].username : null;
    }
    
    // For multiplayer (including bot play)
    if (players[0].score > players[1].score) {
      // Clear winner by score
      return players[0].username;
    } else if (players[0].score === players[1].score) {
      // Tie on score, use response time as tiebreaker
      return players[0].totalResponseTime <= players[1].totalResponseTime ? 
        players[0].username : players[1].username;
    }
    
    // Should never reach here if players are sorted properly
    return null;
  }

// Helper function to handle game over emit logic
async function handleGameOverEmit(room, players, winner, roomId) {
    try {
      const isSinglePlayer = room.players.length === 1;
      const hasBot = room.players.some(p => p.isBot);
      
      // If there's a winner and they're not a bot, send winnings
      if (winner && !players.find(p => p.username === winner)?.isBot) {
        try {
          const payoutSignature = await sendWinnings(winner, room.betAmount, hasBot);
          io.to(roomId).emit('gameOver', {
            players: players.map(p => ({ 
              username: p.username, 
              score: p.score, 
              totalResponseTime: p.totalResponseTime || 0,
              isBot: p.isBot || false
            })),
            winner: winner,
            betAmount: room.betAmount,
            payoutSignature,
            singlePlayerMode: isSinglePlayer,
            botOpponent: hasBot
          });
        } catch (error) {
          console.error('Error processing payout:', error);
          io.to(roomId).emit('gameOver', {
            error: 'Error processing payout. Please contact support.',
            players: players.map(p => ({ 
              username: p.username, 
              score: p.score, 
              totalResponseTime: p.totalResponseTime || 0,
              isBot: p.isBot || false
            })),
            winner: winner,
            betAmount: room.betAmount,
            singlePlayerMode: isSinglePlayer,
            botOpponent: hasBot
          });
        }
      } else {
        // No payout (no winner or bot won)
        io.to(roomId).emit('gameOver', {
          players: players.map(p => ({ 
            username: p.username, 
            score: p.score, 
            totalResponseTime: p.totalResponseTime || 0,
            isBot: p.isBot || false
          })),
          winner: winner,
          betAmount: room.betAmount,
          singlePlayerMode: isSinglePlayer,
          botOpponent: hasBot
        });
      }
    } catch (error) {
      console.error('Error in handleGameOverEmit:', error);
      io.to(roomId).emit('gameError', 'An error occurred while ending the game.');
    }
  }