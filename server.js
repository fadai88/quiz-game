const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();
const moment = require('moment');
const User = require('./models/User');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { Connection, PublicKey, SystemProgram, Transaction, sendAndConfirmTransaction, Keypair } = require('@solana/web3.js');
const Joi = require('joi');

const transactionSchema = Joi.object({
    walletAddress: Joi.string().required(),
    betAmount: Joi.number().min(1).max(100).required(),
    transactionSignature: Joi.string().required(),
    gameMode: Joi.string().optional()
});

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
const matchmakingPools = {
    human: new Map() // Map of betAmount -> array of waiting players
};


// Initialize config
const config = {
    USDC_MINT: new PublicKey('Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr'),
    TREASURY_WALLET: new PublicKey('GN6uUVKuijj15ULm3X954mQTKEzur9jxXdRRuLeMqmgH'),
    TREASURY_KEYPAIR: Keypair.fromSecretKey(
        Buffer.from(JSON.parse(process.env.TREASURY_SECRET_KEY))
    ),
    connection: new Connection(process.env.SOLANA_RPC_URL, 'confirmed')
};


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

async function initializeRedis() {
    try {
        redisClient = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
        redisClient.on('connect', () => {
            console.log('Redis connected successfully');
        });
        redisClient.on('error', (err) => {
            console.error('Redis connection error:', err);
        });
        // Test Redis connection
        await redisClient.set('test', '1', 'EX', 60);
        const testValue = await redisClient.get('test');
        console.log(`Redis test: ${testValue}`); // Should log "Redis test: 1"
    } catch (error) {
        console.error('Failed to initialize Redis:', error);
        throw new Error('Redis is required for transaction replay protection');
    }
}

initializeRedis().catch((err) => {
    console.error(err.message);
    process.exit(1); // Exit if Redis is unavailable
});

const verifyUSDCTransaction = async (transactionSignature, expectedAmount, senderAddress, recipientAddress) => {
    try {
        const connection = new Connection(process.env.SOLANA_RPC_URL, 'confirmed');
        
        const transaction = await connection.getTransaction(transactionSignature, {
            commitment: 'confirmed',
            maxSupportedTransactionVersion: 0 // Support legacy and versioned transactions
        });
        
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

async function verifyAndValidateTransaction(signature, expectedAmount, senderAddress, recipientAddress, maxRetries = 3, retryDelay = 500) {
    console.log(`Verifying transaction ${signature} for ${expectedAmount} USDC from ${senderAddress} to ${recipientAddress}`);

    // Check for transaction reuse
    const key = `tx:${signature}`;
    const exists = await redisClient.get(key);
    console.log(`Checked Redis for ${key}: ${exists ? 'Found' : 'Not found'}`);
    if (exists) {
        console.error(`Transaction ${signature} already used`);
        throw new Error('This transaction has already been used');
    }

    let transaction;
    try {
        transaction = await verifyTransactionWithStatus(signature, maxRetries, retryDelay);
    } catch (error) {
        if (error.message.includes('Invalid param: Invalid')) {
            console.error(`Invalid transaction signature: ${signature}`);
            throw new Error('Invalid transaction signature');
        }
        console.error(`Error verifying transaction ${signature}: ${error.message}`);
        throw new Error('Failed to verify transaction');
    }

    if (!transaction) {
        console.error(`Transaction ${signature} not found after ${maxRetries} retries`);
        throw new Error('Transaction could not be verified');
    }
    if (transaction.meta.err) {
        console.error(`Transaction ${signature} failed on chain: ${JSON.stringify(transaction.meta.err)}`);
        throw new Error('Transaction failed on the blockchain');
    }

    const postTokenBalances = transaction.meta.postTokenBalances;
    const preTokenBalances = transaction.meta.preTokenBalances;
    if (!postTokenBalances || !preTokenBalances) {
        console.error(`Transaction ${signature} missing token balances`);
        throw new Error('Transaction missing required balance information');
    }

    const treasuryPostBalance = postTokenBalances.find(b => b.owner === recipientAddress);
    const treasuryPreBalance = preTokenBalances.find(b => b.owner === recipientAddress);
    if (!treasuryPostBalance || !treasuryPreBalance) {
        console.error(`Transaction ${signature} missing treasury balance change`);
        throw new Error('Transaction does not include treasury balance change');
    }

    const balanceChange = (treasuryPostBalance.uiTokenAmount.uiAmount || 0) - (treasuryPreBalance.uiTokenAmount.uiAmount || 0);
    if (Math.abs(balanceChange - expectedAmount) > 0.001) {
        console.error(`Transaction ${signature} amount mismatch: expected ${expectedAmount}, got ${balanceChange}`);
        throw new Error('Transaction amount does not match the expected bet');
    }

    await redisClient.set(key, 1, 'EX', 86400);
    console.log(`Stored transaction signature ${signature} in Redis`);
    console.log(`Transaction ${signature} verified successfully`);
    return transaction;
}

async function verifyTransactionWithStatus(signature, maxRetries = 3, retryDelay = 500) {
    for (let i = 0; i < maxRetries; i++) {
        console.log(`Attempt ${i + 1} to verify transaction ${signature}`);
        const statuses = await connection.getSignatureStatuses([signature], { searchTransactionHistory: true });
        const status = statuses.value[0];
        if (status && status.confirmationStatus === 'confirmed') {
            console.log(`Transaction ${signature} confirmed`);
            return await connection.getTransaction(signature, { maxSupportedTransactionVersion: 0 });
        }
        console.log(`Transaction ${signature} not confirmed yet, retrying in ${retryDelay}ms`);
        await new Promise(resolve => setTimeout(resolve, retryDelay));
    }
    console.log(`Transaction ${signature} verification failed after ${maxRetries} retries`);
    return null;
}

async function rateLimitEvent(walletAddress, eventName, maxRequests = 5, windowSeconds = 60) {
    const key = `rate:${walletAddress}:${eventName}`;
    const count = await redisClient.get(key) || 0;
    if (count >= maxRequests) {
        throw new Error(`Too many ${eventName} requests`);
    }
    await redisClient.set(key, parseInt(count) + 1, 'EX', windowSeconds);
}

const BOT_LEVELS = {
    MEDIUM: { correctRate: 0.4, responseTimeRange: [1500, 4000] },  // 70% correct, 1.5-4 seconds
    HARD: { correctRate: 0.6, responseTimeRange: [1000, 3000] }     // 90% correct, 1-3 seconds
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
            console.log('Wallet login attempt:', { walletAddress, recaptchaToken: !!recaptchaToken });
            
            // Rate limiting check
            if (redisClient) {
                const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                const loginLimitKey = `login:${clientIP}`;
                const loginAttempts = await redisClient.get(loginLimitKey) || 0;
                
                if (loginAttempts > 100) {
                    console.warn(`Rate limit exceeded for IP ${clientIP}`);
                    return socket.emit('loginFailure', 'Too many login attempts. Please try again later.');
                }
                await redisClient.set(loginLimitKey, parseInt(loginAttempts) + 1, 'EX', 3600);
            }
            
            // reCAPTCHA verification
            if (process.env.ENABLE_RECAPTCHA && recaptchaToken) {
                console.log('reCAPTCHA enabled, attempting verification');
                try {
                    const recaptchaResult = await verifyRecaptcha(recaptchaToken);
                    console.log('reCAPTCHA verification result:', recaptchaResult);
                    if (!recaptchaResult.success) {
                        console.warn(`reCAPTCHA verification failed for wallet ${walletAddress}`);
                        return socket.emit('loginFailure', 'Verification failed. Please try again.');
                    }
                } catch (error) {
                    console.error('reCAPTCHA verification error:', error);
                    return socket.emit('loginFailure', 'Verification service unavailable. Please try again later.');
                }
            } else {
                console.log('reCAPTCHA disabled or token missing', { 
                    enabled: process.env.ENABLE_RECAPTCHA === 'true', 
                    tokenProvided: !!recaptchaToken 
                });
            }

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

    socket.on('joinGame', (data) => {
        try {
            const { walletAddress, betAmount } = data;
            console.log('Join game request:', { walletAddress, betAmount });
    
            // Validate input
            if (!walletAddress || typeof betAmount !== 'number' || betAmount <= 0) {
                throw new Error('Invalid join game request');
            }
    
            // Create a temporary room
            const roomId = generateRoomId();
            gameRooms.set(roomId, {
                mode: 'waiting',
                gameStarted: false,
                betAmount,
                players: [{ username: walletAddress, score: 0, totalResponseTime: 0 }],
                questions: [],
                currentQuestionIndex: 0
            });
    
            socket.join(roomId);
            console.log(`Player ${walletAddress} joined temporary room ${roomId}`);
            socket.emit('gameJoined', roomId);
    
            logGameRoomsState();
        } catch (error) {
            console.error('Join game error:', error);
            socket.emit('joinGameFailure', error.message);
        }
    });

    socket.on('playerReady', ({ roomId, preferredMode }) => {
        console.log(`Player ${socket.id} ready in room ${roomId}, preferred mode: ${preferredMode || 'not specified'}`);
        const room = gameRooms.get(roomId);
        
        if (!room) {
            console.error(`Room ${roomId} not found when player ${socket.id} marked ready`);
            return socket.emit('gameError', 'Room not found');
        }
        
        if (room.roomMode === 'bot') {
            console.log(`Room ${roomId} is set for bot play, not starting regular game`);
            return;
        }
        
        // Set preferred game mode if specified
        if (preferredMode === 'human') {
            room.roomMode = 'human';
            console.log(`Room ${roomId} marked for human vs human play`);
            
            if (room.players.length === 1) {
                let matchFound = false;
                
                for (const [otherRoomId, otherRoom] of gameRooms.entries()) {
                    // Skip current room and invalid matches
                    if (otherRoomId === roomId || 
                        otherRoom.roomMode !== 'human' || 
                        otherRoom.gameStarted || 
                        otherRoom.betAmount !== room.betAmount ||
                        otherRoom.players.length !== 1) {
                        continue;
                    }
                    
                    // Found a match! Move the current player to the other room
                    console.log(`Found matching room ${otherRoomId} for player in room ${roomId}`);
                    
                    const player = room.players[0]; // The current player
                    
                    otherRoom.players.push(player);
                    socket.leave(roomId);
                    socket.join(otherRoomId);
                    
                    socket.emit('matchFound', { newRoomId: otherRoomId });
                    io.to(otherRoomId).emit('playerJoined', player.username);
                    
                    otherRoom.gameStarted = true;
                    startGame(otherRoomId);
                    
                    gameRooms.delete(roomId);
                    
                    matchFound = true;
                    break;
                }
                
                if (!matchFound) {
                    console.log(`No match found for player in room ${roomId}, waiting for others`);
                }
            }
        }
        
        // Handle the case where there are already 2 players in the room
        if (room.players.length === 2 && !room.gameStarted) {
            console.log(`Starting multiplayer game in room ${roomId} with 2 players`);
            room.gameStarted = true;
            room.roomMode = 'multiplayer'; // Explicitly mark as multiplayer mode
            startGame(roomId);
        } else {
            console.log(`Room ${roomId} has ${room.players.length} players, waiting for more to join`);
        }
        
        // Log room state
        console.log('Current room state:');
        logGameRoomsState();
    });

    socket.on('joinHumanMatchmaking', async (data) => {
        try {
            /*
            await rateLimitEvent(data.walletAddress, 'joinGame');
            const { error } = transactionSchema.validate(data);
                if (error) {
                    console.error('Validation error:', error.message);
                    socket.emit('joinGameFailure', error.message);
                    return;
                }
            */
            const { walletAddress, betAmount, transactionSignature, gameMode } = data;
            console.log('Human matchmaking request:', { walletAddress, betAmount, gameMode });
    
            // Use environment variables for retries and delay
            const maxRetries = parseInt(process.env.TRANSACTION_RETRIES) || 3;
            const retryDelay = parseInt(process.env.TRANSACTION_RETRY_DELAY) || 500;
    
            // Verify and validate transaction
            const transaction = await verifyAndValidateTransaction(
                transactionSignature,
                betAmount,
                walletAddress,
                config.TREASURY_WALLET.toString(),
                maxRetries,
                retryDelay
            );
    
            console.log('Transaction verified successfully');

            for (const [roomId, room] of gameRooms.entries()) {
                const playerIndex = room.players.findIndex(p => p.username === walletAddress);
                if (playerIndex !== -1) {
                    room.players.splice(playerIndex, 1);
                    socket.leave(roomId);
                    console.log(`Player ${walletAddress} left room ${roomId} for matchmaking`);
                    if (room.players.length === 0) {
                        gameRooms.delete(roomId);
                        console.log(`Deleted empty room ${roomId}`);
                    }
                    break;
                }
            }
    
            // Create or access the matchmaking pool for this bet amount
            if (!matchmakingPools.human.has(betAmount)) {
                matchmakingPools.human.set(betAmount, []);
            }
    
            const pool = matchmakingPools.human.get(betAmount);
    
            // Check if this player is already in the pool
            const existingPlayer = pool.find(p => p.walletAddress === walletAddress);
            if (existingPlayer) {
                console.log(`Player ${walletAddress} is already in matchmaking pool for ${betAmount}`);
                socket.emit('matchmakingError', { message: 'You are already in matchmaking' });
                return;
            }
    
            // Check for an available match
            if (pool.length > 0) {
                const opponent = pool.shift();
                
                const roomId = generateRoomId();
                console.log(`Creating game room ${roomId} for matched players ${walletAddress} and ${opponent.walletAddress}`);
                
                gameRooms.set(roomId, {
                    players: [
                        {
                            id: socket.id,
                            username: walletAddress,
                            score: 0,
                            totalResponseTime: 0
                        },
                        {
                            id: opponent.socketId,
                            username: opponent.walletAddress,
                            score: 0,
                            totalResponseTime: 0
                        }
                    ],
                    questions: [],
                    currentQuestionIndex: 0,
                    answersReceived: 0,
                    betAmount: betAmount,
                    gameStarted: false,
                    roomMode: 'multiplayer'
                });
                
                socket.join(roomId);
                const opponentSocket = io.sockets.sockets.get(opponent.socketId);
                if (opponentSocket) {
                    opponentSocket.join(roomId);
                }
                
                io.to(roomId).emit('matchFound', { 
                    gameRoomId: roomId, 
                    players: [walletAddress, opponent.walletAddress]
                });
                
                await startGame(roomId);
            } else {
                console.log(`Adding player ${walletAddress} to matchmaking pool for ${betAmount}`);
                
                pool.push({
                    socketId: socket.id,
                    walletAddress,
                    joinTime: Date.now(),
                    transactionSignature
                });
                
                socket.emit('matchmakingJoined', { 
                    waitingRoomId: `matchmaking-${betAmount}`, 
                    position: pool.length 
                });
            }
    
            logMatchmakingState();
    
        } catch (error) {
            console.error('Error joining human matchmaking:', error);
            socket.emit('matchmakingError', { message: error.message });
        }
    });
    
    // Handler for bot games
    socket.on('joinBotGame', async (data) => {
        try {
            /*
            await rateLimitEvent(data.walletAddress, 'joinGame');
            const { error } = transactionSchema.validate(data);
                if (error) {
                    console.error('Validation error:', error.message);
                    socket.emit('joinGameFailure', error.message);
                    return;
                }
            */
            const { walletAddress, betAmount, transactionSignature, gameMode } = data;
            console.log('Bot game request:', { walletAddress, betAmount, gameMode });
    
            // Use environment variables for retries and delay
            const maxRetries = parseInt(process.env.TRANSACTION_RETRIES) || 3;
            const retryDelay = parseInt(process.env.TRANSACTION_RETRY_DELAY) || 500;
    
            // Verify and validate transaction
            const transaction = await verifyAndValidateTransaction(
                transactionSignature,
                betAmount,
                walletAddress,
                config.TREASURY_WALLET.toString(),
                maxRetries,
                retryDelay
            );
    
            console.log('Transaction verified successfully');

            for (const [roomId, room] of gameRooms.entries()) {
                const playerIndex = room.players.findIndex(p => p.username === walletAddress);
                if (playerIndex !== -1) {
                    room.players.splice(playerIndex, 1);
                    socket.leave(roomId);
                    console.log(`Player ${walletAddress} left room ${roomId} for matchmaking`);
                    if (room.players.length === 0) {
                        gameRooms.delete(roomId);
                        console.log(`Deleted empty room ${roomId}`);
                    }
                    break;
                }
            }
    
            // Create a game room with the player
            const roomId = generateRoomId();
            console.log(`Creating bot game room ${roomId} for player ${walletAddress}`);
            
            gameRooms.set(roomId, {
                players: [
                    {
                        id: socket.id,
                        username: walletAddress,
                        score: 0,
                        totalResponseTime: 0
                    }
                ],
                questions: [],
                currentQuestionIndex: 0,
                answersReceived: 0,
                betAmount: betAmount,
                gameStarted: false,
                roomMode: 'bot'
            });
            
            socket.join(roomId);
            
            const botName = chooseBotName();
            socket.emit('botGameCreated', { 
                gameRoomId: roomId, 
                botName 
            });
            
            await startSinglePlayerGame(roomId);
            
            logGameRoomsState();
    
        } catch (error) {
            console.error('Error creating bot game:', error);
            socket.emit('matchmakingError', { message: error.message });
        }
    });

    socket.on('switchToBot', async ({ roomId }) => {
        console.log(`Player ${socket.id} wants to switch from matchmaking to bot game`);
        
        // Find this player in the matchmaking pools
        let playerFound = false;
        let playerData = null;
        
        for (const [betAmount, pool] of matchmakingPools.human.entries()) {
            const playerIndex = pool.findIndex(p => p.socketId === socket.id);
            if (playerIndex !== -1) {
                playerData = pool[playerIndex];
                pool.splice(playerIndex, 1); // Remove from matchmaking
                playerFound = true;
                console.log(`Removed player ${playerData.walletAddress} from matchmaking pool for ${betAmount}`);
                break;
            }
        }
        
        if (!playerFound || !playerData) {
            console.error(`Player ${socket.id} not found in any matchmaking pool`);
            socket.emit('matchmakingError', { message: 'Not found in matchmaking' });
            return;
        }
        
        // Create a new bot game room
        const newRoomId = generateRoomId();
        console.log(`Creating bot game room ${newRoomId} for player ${playerData.walletAddress}`);
        
        gameRooms.set(newRoomId, {
            players: [
                {
                    id: socket.id,
                    username: playerData.walletAddress,
                    score: 0,
                    totalResponseTime: 0,
                    answered: false,
                    lastAnswer: null
                }
            ],
            questions: [],
            currentQuestionIndex: 0,
            answersReceived: 0,
            betAmount: parseInt(playerData.betAmount),
            gameStarted: false,
            roomMode: 'bot'
        });
        
        // Join the socket to the new room
        socket.join(newRoomId);
        
        // Notify the player
        const botName = chooseBotName();
        socket.emit('botGameCreated', { 
            gameRoomId: newRoomId, 
            botName 
        });
        
        // Start the single player game with a bot
        await startSinglePlayerGame(newRoomId);
    });
    

    socket.on('matchFound', ({ newRoomId }) => {
        console.log(`Match found, player ${socket.id} moved to room ${newRoomId}`);
        currentRoomId = newRoomId;
        // Additional handling if needed
    });

    socket.on('leaveRoom', ({ roomId }) => {
        console.log(`Player ${socket.id} requested to leave room ${roomId}`);
        
        const room = gameRooms.get(roomId);
        if (!room) {
            console.log(`Room ${roomId} not found when player tried to leave`);
            socket.emit('leftRoom', { roomId });
            return;
        }
        
        // If the game has already started, handle as a disconnect/forfeit
        if (room.gameStarted) {
            console.log(`Game already started in room ${roomId}, handling as disconnect`);
            // The existing disconnect handler will take care of this
            return;
        }
        
        // Remove the player from the room
        const playerIndex = room.players.findIndex(p => p.id === socket.id);
        if (playerIndex !== -1) {
            const player = room.players[playerIndex];
            console.log(`Removing player ${player.username} from room ${roomId}`);
            room.players.splice(playerIndex, 1);
            
            // Leave the socket.io room
            socket.leave(roomId);
            
            // If the room is now empty, delete it
            if (room.players.length === 0) {
                console.log(`Room ${roomId} is now empty, deleting it`);
                gameRooms.delete(roomId);
            } else {
                // Notify remaining players
                console.log(`Notifying remaining players in room ${roomId}`);
                io.to(roomId).emit('playerLeft', player.username);
            }
        }
        
        // Confirm to the client they've left
        socket.emit('leftRoom', { roomId });
    });
    
    socket.on('requestBotRoom', async ({ walletAddress, betAmount }) => {
        console.log(`Player ${walletAddress} requesting dedicated bot room with bet ${betAmount}`);
        
        // Create a new room specifically for this player and a bot
        const roomId = generateRoomId();
        console.log(`Creating new bot room ${roomId} for ${walletAddress}`);
        
        gameRooms.set(roomId, {
            players: [{
                id: socket.id,
                username: walletAddress,
                score: 0,
                totalResponseTime: 0
            }],
            questions: [],
            currentQuestionIndex: 0,
            answersReceived: 0,
            betAmount: betAmount,
            waitingTimeout: null,
            gameStarted: false,
            roomMode: 'bot' // Mark as bot mode from the start
        });
        
        // Join the socket to this room
        socket.join(roomId);
        
        // Notify the client
        socket.emit('botRoomCreated', roomId);
        
        // Log the state
        logGameRoomsState();
    });

    socket.on('requestBotGame', async ({ roomId }) => {
        console.log(`Bot game requested for room ${roomId}`);
        
        // Log game rooms state before bot request
        console.log('Game rooms state BEFORE bot request:');
        logGameRoomsState();
        
        const room = gameRooms.get(roomId);
        
        if (!room) {
            console.error(`Room ${roomId} not found when requesting bot game`);
            socket.emit('gameError', 'Room not found');
            return;
        }
        
        // Clear any existing timeout
        if (room.waitingTimeout) {
            clearTimeout(room.waitingTimeout);
        }
        
        // Check if room already has multiple human players
        const humanPlayers = room.players.filter(p => !p.isBot);
        
        if (humanPlayers.length > 1) {
            console.error(`Room ${roomId} already has ${humanPlayers.length} human players, can't add bot`);
            socket.emit('gameError', 'Cannot add bot to a room with multiple players');
            return;
        }
        
        // Check if this player is actually in this room
        const playerInRoom = room.players.find(p => p.id === socket.id);
        if (!playerInRoom) {
            console.error(`Player ${socket.id} not found in room ${roomId}`);
            socket.emit('gameError', 'You are not in this room');
            return;
        }
        
        console.log(`Setting room ${roomId} to bot mode`);
        room.roomMode = 'bot';
        
        await startSinglePlayerGame(roomId);
        
        console.log('Game rooms state AFTER bot request:');
        logGameRoomsState();
    });

    socket.on('submitAnswer', async ({ roomId, answer, responseTime, username }) => {
        console.log(`Received answer from ${username} in room ${roomId}:`, { answer, responseTime });
        
        const room = gameRooms.get(roomId);
        if (!room) {
            console.error(`Room ${roomId} not found for answer submission`);
            return;
        }
    
        const player = room.players.find(p => p.username === username && !p.isBot);
        if (!player) {
            console.error(`Player ${username} not found in room ${roomId} or is a bot`);
            return;
        }
    
        player.totalResponseTime = (player.totalResponseTime || 0) + responseTime;
        player.lastAnswer = answer;
        player.answered = true;
    
        const currentQuestion = room.questions[room.currentQuestionIndex];
        const isCorrect = answer === currentQuestion.correctAnswer;
    
        if (isCorrect) {
            player.score = (player.score || 0) + 1;
            console.log(`Correct answer from ${username}. New score: ${player.score}`);
            try {
                await User.findOneAndUpdate(
                    { walletAddress: username },
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
        } else {
            console.log(`Incorrect answer from ${username}. Score unchanged: ${player.score}`);
        }
    
        // Send result only to the player who answered
        socket.emit('answerResult', {
            username: player.username,
            isCorrect,
            correctAnswer: currentQuestion.correctAnswer
        });
    
        // Check if all players (human and bot) have answered
        if (room.players.every(p => p.answered)) {
            console.log(`All players answered in room ${roomId}`);
            // When all players have answered, send the complete results to everyone
            io.to(roomId).emit('roundComplete', {
                correctAnswer: currentQuestion.correctAnswer,
                playerResults: room.players.map(p => ({
                    username: p.username,
                    isCorrect: p.lastAnswer === currentQuestion.correctAnswer,
                    answer: p.lastAnswer,
                    isBot: p.isBot || false
                }))
            });
            await completeQuestion(roomId);
        } else {
            // Just update that a player has answered without revealing the answer
            socket.to(roomId).emit('playerAnswered', {
                username,
                isBot: false,
                responseTime
            });
        }
    });

    socket.on('getLeaderboard', async () => {
        try {
            const leaderboard = await User.find({})
                .select('walletAddress gamesPlayed totalWinnings wins correctAnswers')
                .sort({ totalWinnings: -1 })
                .limit(20);
            
            socket.emit('leaderboardData', leaderboard);
        } catch (error) {
            console.error('Error fetching leaderboard:', error);
            socket.emit('leaderboardError', 'Failed to fetch leaderboard data');
        }
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
        
        // Check if player is in a matchmaking pool
        for (const [betAmount, pool] of matchmakingPools.human.entries()) {
            const playerIndex = pool.findIndex(p => p.socketId === socket.id);
            if (playerIndex !== -1) {
                console.log(`Removing player ${pool[playerIndex].walletAddress} from matchmaking pool`);
                pool.splice(playerIndex, 1);
                break;
            }
        }
        
        for (const [roomId, room] of gameRooms.entries()) {
            const playerIndex = room.players.findIndex(p => p.id === socket.id);
            if (playerIndex !== -1) {
                const disconnectedPlayer = room.players[playerIndex];
                console.log(`Player ${disconnectedPlayer.username} left room ${roomId}`);
                
                room.players.splice(playerIndex, 1);
                room.playerLeft = true;
                
                if (room.questionTimeout) {
                    clearTimeout(room.questionTimeout);
                }
                
                // Handle bot game specially
                if (room.roomMode === 'bot') {
                    console.log(`Player left bot game in room ${roomId}`);
                    // Update stats for human player (bot doesn't get stats)
                    const humanPlayer = room.players.find(p => !p.isBot) || disconnectedPlayer;
                    const allPlayers = [
                        {
                            username: humanPlayer.username,
                            score: humanPlayer.score || 0,
                            isBot: false
                        }
                    ];
                    
                    updatePlayerStats(allPlayers, {
                        winner: null, // Bot wins, but we don't award winnings
                        botOpponent: true,
                        betAmount: room.betAmount
                    });
                    
                    // Emit game over event to client (if they're still connected)
                    io.to(roomId).emit('gameOverForfeit', {
                        winner: 'Bot', // Bot wins by default
                        disconnectedPlayer: disconnectedPlayer.username,
                        betAmount: room.betAmount,
                        message: `You left the game. The bot wins by default.`
                    });
                    
                    // Clean up the room
                    gameRooms.delete(roomId);
                    return;
                }
                
                // Handle human vs. human game
                if (room.players.length > 0) {
                    const remainingPlayer = room.players[0];
                    
                    // Don't proceed if the remaining player is a bot
                    if (remainingPlayer.isBot) {
                        console.log(`Only a bot remained in room ${roomId} - cleaning up`);
                        gameRooms.delete(roomId);
                        return;
                    }
                    
                    console.log(`Player ${disconnectedPlayer.username} left during game. Declaring ${remainingPlayer.username} the winner.`);
                    
                    // Create players array with both remaining and disconnected player
                    const allPlayers = [
                        {
                            username: remainingPlayer.username,
                            score: remainingPlayer.score || 0,
                            isBot: false
                        },
                        {
                            username: disconnectedPlayer.username,
                            score: disconnectedPlayer.score || 0,
                            isBot: false
                        }
                    ];
                    
                    // Process the win and update stats
                    handlePlayerLeftWin(roomId, remainingPlayer, disconnectedPlayer, room.betAmount, false, allPlayers);
                } else {
                    // If no players left, delete the room
                    console.log(`Deleting empty room ${roomId}`);
                    gameRooms.delete(roomId);
                }
                break;
            }
        }
    });
});


app.get('/login.html', (req, res) => {
    // Read the file
    let loginHtml = fs.readFileSync(path.join(__dirname, 'public', 'login.html'), 'utf8');
    
    // Inject the reCAPTCHA setting
    const recaptchaEnabled = process.env.ENABLE_RECAPTCHA === 'true';
    const recaptchaSiteKey = process.env.RECAPTCHA_SITE_KEY || '';
    
    // Replace the site key placeholder
    loginHtml = loginHtml.replace('YOUR_SITE_KEY', recaptchaSiteKey);
    
    // Add a custom script tag with the reCAPTCHA configuration
    const recaptchaConfigScript = `<script>
    // reCAPTCHA configuration 
    window.recaptchaEnabled = ${recaptchaEnabled};
    window.recaptchaSiteKey = "${recaptchaSiteKey}";
    console.log("reCAPTCHA config loaded:", { enabled: window.recaptchaEnabled, siteKey: window.recaptchaSiteKey });
    </script>`;
    
    // Insert the script right before the closing </head> tag
    loginHtml = loginHtml.replace('</head>', `${recaptchaConfigScript}\n</head>`);
    
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

    room.questionTimeout = setTimeout(async () => {
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

    // Check if any player has left mid-game
    if (room.playerLeft) {
        console.log(`Game in room ${roomId} ending early because a player left`);
        await handleGameOver(room, roomId);
        return;
    }

    if (room.currentQuestionIndex < room.questions.length) {
        setTimeout(() => {
            startNextQuestion(roomId);
        }, 2000); // Slightly longer pause between questions for better UX
    } else {
        // Game over logic
        console.log(`Game over in room ${roomId}`);
        await handleGameOver(room, roomId);
    }
}

// Helper function to handle game over logic
async function handleGameOver(room, roomId) {
    const sortedPlayers = [...room.players].sort((a, b) => {
        if (b.score !== a.score) {
            return b.score - a.score;
        }
        return (a.totalResponseTime || 0) - (b.totalResponseTime || 0);
    });

    let winner = null;
    const botOpponent = room.players.some(p => p.isBot);
    const isSinglePlayer = room.players.length === 1;

    if (botOpponent && sortedPlayers.length === 2) {
        const humanPlayer = sortedPlayers.find(p => !p.isBot);
        const botPlayer = sortedPlayers.find(p => p.isBot);
        if (humanPlayer && botPlayer) {
            if (humanPlayer.score > botPlayer.score) {
                winner = humanPlayer.username;
            } else if (humanPlayer.score === botPlayer.score) {
                winner = humanPlayer.totalResponseTime <= botPlayer.totalResponseTime ? 
                    humanPlayer.username : botPlayer.username;
            }
        }
    } else if (sortedPlayers.length === 1) {
        winner = sortedPlayers[0].username;
    } else if (sortedPlayers.length > 1) {
        if (sortedPlayers[0].score > sortedPlayers[1].score) {
            winner = sortedPlayers[0].username;
        } else if (sortedPlayers[0].score === sortedPlayers[1].score) {
            winner = sortedPlayers[0].totalResponseTime <= sortedPlayers[1].totalResponseTime ? 
                sortedPlayers[0].username : sortedPlayers[1].username;
        }
    }

    try {
        await updatePlayerStats(room.players, {
            winner: winner,
            botOpponent: botOpponent,
            betAmount: room.betAmount
        });
        
        if (winner && !sortedPlayers.find(p => p.username === winner)?.isBot) {
            try {
                const payoutSignature = await sendWinnings(winner, room.betAmount, botOpponent);
                io.to(roomId).emit('gameOver', {
                    players: sortedPlayers.map(p => ({ 
                        username: p.username, 
                        score: p.score, 
                        totalResponseTime: p.totalResponseTime || 0,
                        isBot: p.isBot || false
                    })),
                    winner: winner,
                    betAmount: room.betAmount,
                    payoutSignature,
                    singlePlayerMode: isSinglePlayer,
                    botOpponent: botOpponent
                });
            } catch (error) {
                console.error('Error processing payout:', error);
                io.to(roomId).emit('gameOver', {
                    error: 'Error processing payout. Please contact support.',
                    players: sortedPlayers.map(p => ({ 
                        username: p.username, 
                        score: p.score, 
                        totalResponseTime: p.totalResponseTime || 0,
                        isBot: p.isBot || false
                    })),
                    winner: winner,
                    betAmount: room.betAmount,
                    singlePlayerMode: isSinglePlayer,
                    botOpponent: botOpponent
                });
            }
        } else {
            io.to(roomId).emit('gameOver', {
                players: sortedPlayers.map(p => ({ 
                    username: p.username, 
                    score: p.score, 
                    totalResponseTime: p.totalResponseTime || 0,
                    isBot: p.isBot || false
                })),
                winner: winner,
                betAmount: room.betAmount,
                singlePlayerMode: isSinglePlayer,
                botOpponent: botOpponent
            });
        }

        gameRooms.delete(roomId);
    } catch (error) {
        console.error('Error handling game over:', error);
        io.to(roomId).emit('gameError', 'An error occurred while ending the game.');
        gameRooms.delete(roomId);
    }
}


const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// Function to generate a unique room ID
function generateRoomId() {
    return Math.random().toString(36).substring(7);
}



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

async function startSinglePlayerGame(roomId) {
    console.log('Starting single player game with bot for room:', roomId);
    const room = gameRooms.get(roomId);
    if (!room) {
        console.log('Room not found for bot creation');
        return;
    }
    
    if (room.roomMode !== 'bot') {
        console.log(`Room ${roomId} is no longer in bot mode, not adding bot`);
        return;
    }

    try {
        // Get questions
        room.questions = await Quiz.aggregate([{ $sample: { size: 7 } }]);
        
        // Count human players
        const humanPlayers = room.players.filter(p => !p.isBot);
        
        // Make sure there's exactly one human player to play against the bot
        if (humanPlayers.length !== 1) {
            console.log(`Room ${roomId} has ${humanPlayers.length} human players, expected exactly 1`);
            if (humanPlayers.length === 0) {
                // No players, delete the room
                gameRooms.delete(roomId);
            } else {
                // Multiple human players, switch to multiplayer mode
                room.roomMode = 'multiplayer';
                io.to(roomId).emit('gameStart', { 
                    players: room.players,
                    questionCount: room.questions.length,
                    singlePlayerMode: false
                });
                room.gameStarted = true;
                startNextQuestion(roomId);
            }
            return;
        }
        
        const humanPlayer = humanPlayers[0];
        console.log('Human player:', humanPlayer.username);
        
        // Ensure human player's state is properly initialized
        humanPlayer.score = 0;
        humanPlayer.totalResponseTime = 0;
        humanPlayer.answered = false;
        humanPlayer.lastAnswer = null;
        
        // Check if there's already a bot (shouldn't happen, but just in case)
        if (room.players.some(p => p.isBot)) {
            console.log(`Room ${roomId} already has a bot player`);
            if (!room.gameStarted) {
                room.gameStarted = true;
                startNextQuestion(roomId);
            }
            return;
        }
        
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
        
        // Then start the game
        io.to(roomId).emit('gameStart', { 
            players: room.players.map(p => ({
                username: p.username,
                score: p.score,
                isBot: p.isBot || false,
                difficulty: p.isBot ? difficulty : undefined
            })),
            questionCount: room.questions.length,
            singlePlayerMode: true, // Indicate single player mode
            botOpponent: bot.username
        });

        room.gameStarted = true;
        startNextQuestion(roomId);
    } catch (error) {
        console.error('Error starting single player game with bot:', error);
        io.to(roomId).emit('gameError', 'Failed to start the game. Please try again.');
    }
}

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
        
        // Handle the blockchain transaction
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
        
        // Use getLatestBlockhash instead of getRecentBlockhash
        const { blockhash, lastValidBlockHeight } = await config.connection.getLatestBlockhash('confirmed');
        transaction.recentBlockhash = blockhash;
        transaction.lastValidBlockHeight = lastValidBlockHeight;

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
            commitment: 'confirmed',
            maxSupportedTransactionVersion: 0
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
    /*
    if (players.length === 1) {
      // Single player mode - win if score is 5 or more (or use your threshold logic)
      return players[0].score >= 5 ? players[0].username : null;
    }
    */
    if (players[0].score > players[1].score) {
      return players[0].username;
    } else if (players[0].score === players[1].score) {
      return players[0].totalResponseTime <= players[1].totalResponseTime ? 
        players[0].username : players[1].username;
    }
    
    // Should never reach here if players are sorted properly
    return null;
  }

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

  async function handlePlayerLeftWin(roomId, remainingPlayer, disconnectedPlayer, betAmount, botOpponent, allPlayers) {
    try {
        // Calculate winnings using the appropriate multiplier
        const multiplier = botOpponent ? 1.5 : 1.8;
        const winningAmount = betAmount * multiplier;
        
        // Process payout for the remaining player - transaction only
        let payoutSignature = null;
        if (!botOpponent) {
            payoutSignature = await sendWinnings(remainingPlayer.username, betAmount, botOpponent);
        }
        
        // Emit game over event with forfeit information
        io.to(roomId).emit('gameOverForfeit', {
            winner: remainingPlayer.username,
            disconnectedPlayer: disconnectedPlayer.username,
            betAmount: betAmount,
            payoutSignature,
            botOpponent,
            message: `${disconnectedPlayer.username} left the game. ${remainingPlayer.username} wins by forfeit!`
        });
        
        // Update stats for all players
        await updatePlayerStats(allPlayers, {
            winner: remainingPlayer.username,
            botOpponent: botOpponent,
            betAmount: betAmount
        });
        
        // Clean up the room
        gameRooms.delete(roomId);
    } catch (error) {
        console.error('Error processing player left win:', error);
        io.to(roomId).emit('gameError', 'Error processing win after player left. Please contact support.');
        gameRooms.delete(roomId);
    }
 }

function logGameRoomsState() {
    console.log('Current game rooms state:');
    console.log(`Total rooms: ${gameRooms.size}`);
    
    gameRooms.forEach((room, roomId) => {
        console.log(`Room ID: ${roomId}`);
        console.log(`  Mode: ${room.roomMode}`);
        console.log(`  Game started: ${room.gameStarted}`);
        console.log(`  Bet amount: ${room.betAmount}`);
        console.log(`  Players (${room.players.length}):`);
        
        room.players.forEach(player => {
            console.log(`    - ${player.username}${player.isBot ? ' (BOT)' : ''}`);
        });
        
        console.log(`  Questions: ${room.questions?.length || 0}`);
        console.log(`  Current question index: ${room.currentQuestionIndex}`);
        console.log('-------------------');
    });
}

function logMatchmakingState() {
    console.log('Current Matchmaking State:');
    
    console.log('Human Matchmaking Pools:');
    for (const [betAmount, pool] of matchmakingPools.human.entries()) {
        console.log(`  Bet Amount ${betAmount}: ${pool.length} players waiting`);
        if (pool.length > 0) {
            pool.forEach((player, index) => {
                const waitTime = Math.round((Date.now() - player.joinTime) / 1000);
                console.log(`    - ${player.walletAddress} (waiting for ${waitTime}s)`);
            });
        }
    }
    
    console.log('Game Rooms:');
    logGameRoomsState();
}

setInterval(() => {
    const now = Date.now();
    const MAX_WAIT_TIME = 5 * 60 * 1000; // 5 minutes
    
    for (const [betAmount, pool] of matchmakingPools.human.entries()) {
        const expiredPlayers = pool.filter(player => (now - player.joinTime) > MAX_WAIT_TIME);
        
        if (expiredPlayers.length > 0) {
            console.log(`Removing ${expiredPlayers.length} expired players from matchmaking pool for ${betAmount}`);
            
            expiredPlayers.forEach(player => {
                const playerSocket = io.sockets.sockets.get(player.socketId);
                if (playerSocket) {
                    playerSocket.emit('matchmakingExpired', { 
                        message: 'Your matchmaking request has expired' 
                    });
                }
            });
            
            // Remove expired players
            matchmakingPools.human.set(
                betAmount, 
                pool.filter(player => (now - player.joinTime) <= MAX_WAIT_TIME)
            );
        }
    }
}, 60000); // Run every minute

async function updatePlayerStats(players, roomData) {
    console.log('Updating stats for all players:', players);
    const winner = roomData.winner;
    const multiplier = roomData.botOpponent ? 1.5 : 1.8;
    const winningAmount = roomData.betAmount * multiplier;
    
    console.log(`Game stats: winner=${winner}, betAmount=${roomData.betAmount}, winnings=${winningAmount}`);
    
    try {
        for (const player of players) {
            if (player.isBot) {
                console.log(`Skipping stats update for bot: ${player.username}`);
                continue;
            }
            
            if (!player.username) {
                console.log(`Skipping player with no username:`, player);
                continue;
            }
            
            const isWinner = player.username === winner;
            console.log(`Updating stats for player: ${player.username} (winner: ${isWinner})`);
            
            try {
                const updateObj = {
                    $inc: {
                        gamesPlayed: 1,
                        correctAnswers: player.score || 0
                    }
                };
                
                if (isWinner) {
                    updateObj.$inc.wins = 1;
                    updateObj.$inc.totalWinnings = winningAmount;
                }
                
                console.log(`Update for ${player.username}:`, JSON.stringify(updateObj));
                
                const result = await User.findOneAndUpdate(
                    { walletAddress: player.username },
                    updateObj,
                    { upsert: true, new: true }
                );
                
                console.log(`Stats updated for ${player.username}:`, {
                    gamesPlayed: result.gamesPlayed,
                    correctAnswers: result.correctAnswers,
                    wins: result.wins,
                    totalWinnings: result.totalWinnings
                });
            } catch (error) {
                console.error(`Error updating player ${player.username} stats:`, error);
            }
        }
    } catch (error) {
        console.error('Error in updatePlayerStats:', error);
    }
}