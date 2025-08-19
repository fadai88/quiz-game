const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const { createAdapter } = require('@socket.io/redis-adapter');
const mongoose = require('mongoose');
const Redis = require('ioredis');
const cors = require('cors');
require('dotenv').config();
const moment = require('moment');
const { v4: uuidv4 } = require('uuid');
const User = require('./models/User');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { Connection, PublicKey, SystemProgram, Transaction, sendAndConfirmTransaction, Keypair } = require('@solana/web3.js');
const Joi = require('joi');

const PaymentQueue = require('./models/PaymentQueue');
// const Transaction = require('./models/Transaction');  // Optional if merging
const PaymentProcessor = require('./services/PaymentProcessor');

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


const config = {
    USDC_MINT: new PublicKey('Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr'),
    TREASURY_WALLET: new PublicKey('GN6uUVKuijj15ULm3X954mQTKEzur9jxXdRRuLeMqmgH'),
    TREASURY_KEYPAIR: Keypair.fromSecretKey(
        Buffer.from(JSON.parse(process.env.TREASURY_SECRET_KEY))
    ),
    connection: new Connection(process.env.SOLANA_RPC_URL, 'confirmed'),
    rpcEndpoints: [
        process.env.SOLANA_RPC_URL,
        'https://api.devnet.solana.com',  // Backup public RPC
    ],
    io: io  // Pass your Socket.io instance
};


const connection = config.connection;

let programId;
if (process.env.PROGRAM_ID) {
    programId = new PublicKey(process.env.PROGRAM_ID);
} else {
    console.warn('Warning: PROGRAM_ID not set in environment variables');
    // Use SystemProgram.programId instead of string
    programId = SystemProgram.programId;
}

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

// Configure Socket.IO Redis Adapter
const pubClient = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const subClient = pubClient.duplicate();
io.adapter(createAdapter(pubClient, subClient));
console.log('Socket.IO configured with Redis adapter');

// Initialize and start payment processor
const paymentProcessor = new PaymentProcessor(config);
paymentProcessor.startProcessing(30000);  // Process every 30 seconds

// Graceful shutdown
process.on('SIGTERM', () => {
    paymentProcessor.stopProcessing();
    // ... other cleanup
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

function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

// Helper function to get a game room from Redis
async function getGameRoom(roomId) {
    try {
        const roomData = await redisClient.hget('gameRooms', roomId);
        if (!roomData) return null;
        let room = JSON.parse(roomData);
        room.questionIdMap = new Map(Object.entries(room.questionIdMap || {}));

        // Reconstruct bot players with proper properties
        room.players = room.players.map(player => {
            if (player.isBot) {
                const bot = new TriviaBot(player.username, player.difficultyLevelString);
                // Restore ALL bot properties including response times
                bot.score = player.score || 0;
                bot.totalResponseTime = player.totalResponseTime || 0;
                bot.currentQuestionIndex = player.currentQuestionIndex || 0;
                bot.answersGiven = player.answersGiven || [];
                bot.id = player.id;
                bot.answered = player.answered || false;
                bot.lastAnswer = player.lastAnswer;
                bot.lastRoundResponseTime = player.lastRoundResponseTime || 0;
                
                // Restore the difficulty setting object properly
                bot.difficultySetting = BOT_LEVELS[player.difficultyLevelString] || BOT_LEVELS.MEDIUM;
                
                console.log(`Reconstructed bot ${bot.username} with totalResponseTime: ${bot.totalResponseTime}ms`);
                return bot;
            }
            return player;
        });

        return room;
    } catch (error) {
        console.error(`Error getting game room ${roomId} from Redis:`, error);
        return null;
    }
}

// Helper function to set a game room in Redis
async function setGameRoom(roomId, room) {
    try {
        const serializedRoom = {
            ...room,
            questionIdMap: Object.fromEntries(room.questionIdMap || new Map()),
            // Make sure bot properties are properly serialized
            players: room.players.map(player => {
                if (player.isBot) {
                    return {
                        id: player.id,
                        username: player.username,
                        score: player.score || 0,
                        totalResponseTime: player.totalResponseTime || 0,
                        currentQuestionIndex: player.currentQuestionIndex || 0,
                        answersGiven: player.answersGiven || [],
                        answered: player.answered || false,
                        lastAnswer: player.lastAnswer,
                        lastRoundResponseTime: player.lastRoundResponseTime || 0,
                        isBot: true,
                        difficultyLevelString: player.difficultyLevelString,
                        difficultySetting: player.difficultySetting
                    };
                }
                return player;
            })
        };
        await redisClient.hset('gameRooms', roomId, JSON.stringify(serializedRoom));
        await redisClient.sadd('activeGameRooms', roomId);
        // Set a 24-hour expiration on the room
        await redisClient.expire(`gameRooms:${roomId}`, 24 * 60 * 60);
    } catch (error) {
        console.error(`Error setting game room ${roomId} in Redis:`, error);
        throw error;
    }
}

// Helper function to delete a game room from Redis
async function deleteGameRoom(roomId) {
    try {
        await redisClient.hdel('gameRooms', roomId);
        await redisClient.srem('activeGameRooms', roomId);
    } catch (error) {
        console.error(`Error deleting game room ${roomId} from Redis:`, error);
        throw error;
    }
}

// Helper function to get all active game room IDs
async function getActiveGameRooms() {
    try {
        return await redisClient.smembers('activeGameRooms');
    } catch (error) {
        console.error('Error getting active game rooms from Redis:', error);
        return [];
    }
}

// Helper function to add a player to a matchmaking pool
async function addToMatchmakingPool(betAmount, playerData) {
    try {
        const poolKey = `matchmakingPool:${betAmount}`;
        await redisClient.lpush(poolKey, JSON.stringify(playerData));
    } catch (error) {
        console.error(`Error adding player to matchmaking pool ${betAmount}:`, error);
        throw error;
    }
}

// Helper function to remove a player from a matchmaking pool
async function removeFromMatchmakingPool(betAmount, socketId) {
    try {
        const poolKey = `matchmakingPool:${betAmount}`;
        const pool = await redisClient.lrange(poolKey, 0, -1);
        const playerIndex = pool.findIndex(p => {
            const player = JSON.parse(p);
            return player.socketId === socketId;
        });
        if (playerIndex !== -1) {
            await redisClient.lrem(poolKey, 1, pool[playerIndex]);
            return JSON.parse(pool[playerIndex]);
        }
        return null;
    } catch (error) {
        console.error(`Error removing player from matchmaking pool ${betAmount}:`, error);
        throw error;
    }
}

// Helper function to get a matchmaking pool
async function getMatchmakingPool(betAmount) {
    try {
        const poolKey = `matchmakingPool:${betAmount}`;
        const pool = await redisClient.lrange(poolKey, 0, -1);
        return pool.map(p => JSON.parse(p));
    } catch (error) {
        console.error(`Error getting matchmaking pool ${betAmount}:`, error);
        return [];
    }
}

// Helper function to pop a player from a matchmaking pool
async function popFromMatchmakingPool(betAmount) {
    try {
        const poolKey = `matchmakingPool:${betAmount}`;
        const playerData = await redisClient.rpop(poolKey);
        return playerData ? JSON.parse(playerData) : null;
    } catch (error) {
        console.error(`Error popping player from matchmaking pool ${betAmount}:`, error);
        return null;
    }
}

const BOT_LEVELS = {
    MEDIUM: { correctRate: 0.4, responseTimeRange: [1500, 4000] },  // 70% correct, 1.5-4 seconds
    HARD: { correctRate: 0.6, responseTimeRange: [1000, 3000] }     // 90% correct, 1-3 seconds
};

// Bot player class
class TriviaBot {
    constructor(botName = 'BrainyBot', difficultyString = 'MEDIUM') {
        this.id = `bot-${Date.now()}`;
        this.username = botName;
        this.score = 0;
        this.totalResponseTime = 0;
        this.difficultySetting = BOT_LEVELS[difficultyString] || BOT_LEVELS.MEDIUM;
        this.difficultyLevelString = difficultyString;
        this.currentQuestionIndex = 0;
        this.answersGiven = [];
        this.isBot = true;
        this.answered = false;
        this.lastAnswer = null;
        this.lastRoundResponseTime = 0;
    }

    async answerQuestion(question, options, correctAnswer) {
        const willAnswerCorrectly = Math.random() < this.difficultySetting.correctRate;
        
        let botAnswer;

        if (willAnswerCorrectly) {
            botAnswer = correctAnswer;
        } else {
            const incorrectIndices = [];
            if (Array.isArray(options) && typeof correctAnswer === 'number' && correctAnswer >= 0 && correctAnswer < options.length) {
                for (let i = 0; i < options.length; i++) {
                    if (i !== correctAnswer) {
                        incorrectIndices.push(i);
                    }
                }
            } else {
                console.warn(`TriviaBot: Invalid options or correctAnswer. Options: ${JSON.stringify(options)}, CorrectAnswer: ${correctAnswer}. Question: ${question}`);
                if (Array.isArray(options) && options.length > 0) {
                    botAnswer = Math.floor(Math.random() * options.length);
                } else {
                    botAnswer = 0;
                }
            }

            if (botAnswer === undefined) {
                if (incorrectIndices.length > 0) {
                    botAnswer = incorrectIndices[Math.floor(Math.random() * incorrectIndices.length)];
                } else {
                    if (Array.isArray(options) && options.length > 0) {
                        if (typeof correctAnswer === 'number' && correctAnswer >= 0 && correctAnswer < options.length) {
                            botAnswer = correctAnswer;
                        } else {
                            botAnswer = Math.floor(Math.random() * options.length);
                        }
                    } else {
                        console.error(`TriviaBot: Options array is problematic for question "${question}". Defaulting bot answer to 0.`);
                        botAnswer = 0; 
                    }
                }
            }
        }
        
        // Determine response time within the difficulty's range
        const [minTime, maxTime] = this.difficultySetting.responseTimeRange;
        const responseTime = Math.floor(Math.random() * (maxTime - minTime)) + minTime;
        
        // Simulate thinking time
        await new Promise(resolve => setTimeout(resolve, responseTime));
        
        // Update bot's internal state
        this.totalResponseTime += responseTime;
        this.lastRoundResponseTime = responseTime;
        
        const isActuallyCorrect = (
            typeof botAnswer === 'number' &&
            Array.isArray(options) &&
            typeof correctAnswer === 'number' &&
            correctAnswer >= 0 && correctAnswer < options.length &&
            botAnswer === correctAnswer
        );

        if (isActuallyCorrect) {
            this.score += 1;
        }
        
        this.answersGiven.push({
            questionIndex: this.currentQuestionIndex++,
            answer: botAnswer,
            isCorrect: isActuallyCorrect,
            responseTime
        });
        
        console.log(`Bot ${this.username} answered in ${responseTime}ms. Total response time: ${this.totalResponseTime}ms`);
        
        return {
            answer: botAnswer,
            responseTime,
            isCorrect: isActuallyCorrect
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

    socket.on('joinGame', async (data) => {
        try {
            await rateLimitEvent(data.walletAddress, 'joinGame', 5, 60);
            const { error } = transactionSchema.validate(data);
            if (error) {
                console.error('Validation error:', error.message);
                socket.emit('joinGameFailure', error.message);
                return;
            }
            const { walletAddress, betAmount } = data;

            console.log('Join game request:', { walletAddress, betAmount });

            // Validate input
            if (!walletAddress || typeof betAmount !== 'number' || betAmount <= 0) {
                throw new Error('Invalid join game request');
            }

            // Create a temporary room
            const roomId = generateRoomId();
            await createGameRoom(roomId, betAmount, 'waiting');
            const room = await getGameRoom(roomId);
            room.players.push({ username: walletAddress, score: 0, totalResponseTime: 0 });
            await setGameRoom(roomId, room);

            socket.join(roomId);
            console.log(`Player ${walletAddress} joined temporary room ${roomId}`);
            socket.emit('gameJoined', roomId);

            await logGameRoomsState();
        } catch (error) {
            console.error('Join game error:', error);
            socket.emit('joinGameFailure', error.message);
        }
    });

    socket.on('playerReady', async ({ roomId, preferredMode }) => {
        console.log(`Player ${socket.id} ready in room ${roomId}, preferred mode: ${preferredMode || 'not specified'}`);
        const room = await getGameRoom(roomId);

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

                const activeRooms = await getActiveGameRooms();
                for (const otherRoomId of activeRooms) {
                    if (otherRoomId === roomId) continue;
                    const otherRoom = await getGameRoom(otherRoomId);
                    if (!otherRoom ||
                        otherRoom.roomMode !== 'human' ||
                        otherRoom.gameStarted ||
                        otherRoom.betAmount !== room.betAmount ||
                        otherRoom.players.length !== 1) {
                        continue;
                    }

                    console.log(`Found matching room ${otherRoomId} for player in room ${roomId}`);

                    const player = room.players[0];
                    otherRoom.players.push(player);
                    await setGameRoom(otherRoomId, otherRoom);

                    socket.leave(roomId);
                    socket.join(otherRoomId);

                    socket.emit('matchFound', { newRoomId: otherRoomId });
                    io.to(otherRoomId).emit('playerJoined', player.username);

                    otherRoom.gameStarted = true;
                    await setGameRoom(otherRoomId, otherRoom);
                    await startGame(otherRoomId);

                    await deleteGameRoom(roomId);

                    matchFound = true;
                    break;
                }

                if (!matchFound) {
                    console.log(`No match found for player in room ${roomId}, waiting for others`);
                    await setGameRoom(roomId, room);
                }
            }
        }

        if (room.players.length === 2 && !room.gameStarted) {
            console.log(`Starting multiplayer game in room ${roomId} with 2 players`);
            room.gameStarted = true;
            room.roomMode = 'multiplayer';
            await setGameRoom(roomId, room);
            await startGame(roomId);
        } else {
            console.log(`Room ${roomId} has ${room.players.length} players, waiting for more to join`);
            await setGameRoom(roomId, room);
        }

        await logGameRoomsState();
    });

    socket.on('joinHumanMatchmaking', async (data) => {
        try {
            await rateLimitEvent(data.walletAddress, 'joinHumanMatchmaking');
            const { error } = transactionSchema.validate(data);
            if (error) {
                console.error('Validation error:', error.message);
                socket.emit('joinGameFailure', error.message);
                return;
            }

            const { walletAddress, betAmount, transactionSignature, gameMode } = data;
            console.log('Human matchmaking request:', { walletAddress, betAmount, gameMode });

            const maxRetries = parseInt(process.env.TRANSACTION_RETRIES) || 3;
            const retryDelay = parseInt(process.env.TRANSACTION_RETRY_DELAY) || 500;

            const transaction = await verifyAndValidateTransaction(
                transactionSignature,
                betAmount,
                walletAddress,
                config.TREASURY_WALLET.toString(),
                maxRetries,
                retryDelay
            );

            console.log('Transaction verified successfully');

            // Remove player from any existing rooms
            const activeRooms = await getActiveGameRooms();
            for (const roomId of activeRooms) {
                const room = await getGameRoom(roomId);
                if (!room) continue;
                const playerIndex = room.players.findIndex(p => p.username === walletAddress);
                if (playerIndex !== -1) {
                    room.players.splice(playerIndex, 1);
                    socket.leave(roomId);
                    console.log(`Player ${walletAddress} left room ${roomId} for matchmaking`);
                    if (room.players.length === 0) {
                        await deleteGameRoom(roomId);
                        console.log(`Deleted empty room ${roomId}`);
                    } else {
                        await setGameRoom(roomId, room);
                    }
                }
            }

            const pool = await getMatchmakingPool(betAmount);

            // Check if player is already in the pool
            const existingPlayer = pool.find(p => p.walletAddress === walletAddress);
            if (existingPlayer) {
                console.log(`Player ${walletAddress} is already in matchmaking pool for ${betAmount}`);
                socket.emit('matchmakingError', { message: 'You are already in matchmaking' });
                return;
            }

            // Check for an available match
            if (pool.length > 0) {
                const opponent = await popFromMatchmakingPool(betAmount);

                const roomId = generateRoomId();
                console.log(`Creating game room ${roomId} for matched players ${walletAddress} and ${opponent.walletAddress}`);

                await createGameRoom(roomId, betAmount, 'multiplayer');
                const room = await getGameRoom(roomId);
                room.players.push(
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
                );

                await setGameRoom(roomId, room);

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

                await addToMatchmakingPool(betAmount, {
                    socketId: socket.id,
                    walletAddress,
                    joinTime: Date.now(),
                    transactionSignature
                });

                socket.emit('matchmakingJoined', {
                    waitingRoomId: `matchmaking-${betAmount}`,
                    position: (await getMatchmakingPool(betAmount)).length
                });
            }

            await logMatchmakingState();
        } catch (error) {
            console.error('Error joining human matchmaking:', error);
            socket.emit('matchmakingError', { message: error.message });
        }
    });
    
    // Handler for bot games
    socket.on('joinBotGame', async (data) => {
        try {
            await rateLimitEvent(data.walletAddress, 'joinBotGame', 3, 60);
            const { error } = transactionSchema.validate(data);
            if (error) {
                console.error('Validation error:', error.message);
                socket.emit('joinGameFailure', error.message);
                return;
            }

            const { walletAddress, betAmount, transactionSignature, gameMode } = data;
            console.log('Bot game request:', { walletAddress, betAmount, gameMode });

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

            // Remove player from any existing rooms
            const activeRooms = await getActiveGameRooms();
            for (const roomId of activeRooms) {
                const room = await getGameRoom(roomId);
                if (!room) continue;
                const playerIndex = room.players.findIndex(p => p.username === walletAddress);
                if (playerIndex !== -1) {
                    room.players.splice(playerIndex, 1);
                    socket.leave(roomId);
                    console.log(`Player ${walletAddress} left room ${roomId} for bot game`);
                    if (room.players.length === 0) {
                        await deleteGameRoom(roomId);
                        console.log(`Deleted empty room ${roomId}`);
                    } else {
                        await setGameRoom(roomId, room);
                    }
                }
            }

            // Remove player from any matchmaking pools
            const betAmounts = await redisClient.keys('matchmakingPool:*');
            for (const poolKey of betAmounts) {
                const betAmount = poolKey.split(':')[1];
                const removedPlayer = await removeFromMatchmakingPool(betAmount, socket.id);
                if (removedPlayer) {
                    console.log(`Removed player ${walletAddress} from matchmaking pool for ${betAmount}`);
                }
            }

            // Create a new bot game room
            const roomId = generateRoomId();
            console.log(`Creating bot game room ${roomId} for player ${walletAddress}`);

            await createGameRoom(roomId, betAmount, 'bot');
            const room = await getGameRoom(roomId);
            room.players.push({
                id: socket.id,
                username: walletAddress,
                score: 0,
                totalResponseTime: 0,
                answered: false,
                lastAnswer: null
            });
            await setGameRoom(roomId, room);

            socket.join(roomId);

            const botName = chooseBotName();
            socket.emit('botGameCreated', {
                gameRoomId: roomId,
                botName
            });

            await startSinglePlayerGame(roomId);

            await logGameRoomsState();
        } catch (error) {
            console.error('Error creating bot game:', error);
            socket.emit('matchmakingError', { message: error.message });
        }
    });

    socket.on('switchToBot', async ({ roomId }) => {
        console.log(`Player ${socket.id} wants to switch from matchmaking to bot game`);

        let playerFound = false;
        let playerData = null;

        // Check all matchmaking pools
        const betAmounts = await redisClient.keys('matchmakingPool:*');
        for (const poolKey of betAmounts) {
            const betAmount = poolKey.split(':')[1];
            const pool = await getMatchmakingPool(betAmount);
            const playerIndex = pool.findIndex(p => p.socketId === socket.id);
            if (playerIndex !== -1) {
                playerData = await removeFromMatchmakingPool(betAmount, socket.id);
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

        await createGameRoom(newRoomId, parseInt(playerData.betAmount), 'bot');
        const room = await getGameRoom(newRoomId);
        room.players.push({
            id: socket.id,
            username: playerData.walletAddress,
            score: 0,
            totalResponseTime: 0,
            answered: false,
            lastAnswer: null
        });
        await setGameRoom(newRoomId, room);

        socket.join(newRoomId);

        const botName = chooseBotName();
        socket.emit('botGameCreated', {
            gameRoomId: newRoomId,
            botName
        });

        await startSinglePlayerGame(newRoomId);
        await logGameRoomsState();
    });
    

    socket.on('matchFound', ({ newRoomId }) => {
        console.log(`Match found, player ${socket.id} moved to room ${newRoomId}`);
        currentRoomId = newRoomId;
        // Additional handling if needed
    });

    socket.on('leaveRoom', async ({ roomId }) => {
        console.log(`Player ${socket.id} requested to leave room ${roomId}`);

        const room = await getGameRoom(roomId);
        if (!room) {
            console.log(`Room ${roomId} not found when player tried to leave`);
            socket.emit('leftRoom', { roomId });
            return;
        }

        if (room.gameStarted) {
            console.log(`Game already started in room ${roomId}, handling as disconnect`);
            return;
        }

        const playerIndex = room.players.findIndex(p => p.id === socket.id);
        if (playerIndex !== -1) {
            const player = room.players[playerIndex];
            console.log(`Removing player ${player.username} from room ${roomId}`);
            room.players.splice(playerIndex, 1);

            socket.leave(roomId);

            if (room.players.length === 0) {
                console.log(`Room ${roomId} is now empty, deleting it`);
                await deleteGameRoom(roomId);
            } else {
                await setGameRoom(roomId, room);
                console.log(`Notifying remaining players in room ${roomId}`);
                io.to(roomId).emit('playerLeft', player.username);
            }
        }

        socket.emit('leftRoom', { roomId });
        await logGameRoomsState();
    });
    
    socket.on('requestBotRoom', async ({ walletAddress, betAmount }) => {
        console.log(`Player ${walletAddress} requesting dedicated bot room with bet ${betAmount}`);

        const roomId = generateRoomId();
        console.log(`Creating new bot room ${roomId} for ${walletAddress}`);

        await createGameRoom(roomId, betAmount, 'bot');
        const room = await getGameRoom(roomId);
        room.players.push({
            id: socket.id,
            username: walletAddress,
            score: 0,
            totalResponseTime: 0
        });
        await setGameRoom(roomId, room);

        socket.join(roomId);
        socket.emit('botRoomCreated', roomId);
        await logGameRoomsState();
    });

    socket.on('requestBotGame', async ({ roomId }) => {
        console.log(`Bot game requested for room ${roomId}`);

        await logGameRoomsState();

        const room = await getGameRoom(roomId);
        if (!room) {
            console.error(`Room ${roomId} not found when requesting bot game`);
            socket.emit('gameError', 'Room not found');
            return;
        }

        if (room.waitingTimeout) {
            clearTimeout(room.waitingTimeout);
        }

        const humanPlayers = room.players.filter(p => !p.isBot);
        if (humanPlayers.length > 1) {
            console.error(`Room ${roomId} already has ${humanPlayers.length} human players, can't add bot`);
            socket.emit('gameError', 'Cannot add bot to a room with multiple players');
            return;
        }

        const playerInRoom = room.players.find(p => p.id === socket.id);
        if (!playerInRoom) {
            console.error(`Player ${socket.id} not found in room ${roomId}`);
            socket.emit('gameError', 'You are not in this room');
            return;
        }

        console.log(`Setting room ${roomId} to bot mode`);
        room.roomMode = 'bot';
        await setGameRoom(roomId, room);

        await startSinglePlayerGame(roomId);

        await logGameRoomsState();
    });

    // Fixed submitAnswer handler - don't complete round until ALL players answer or timeout
    socket.on('submitAnswer', async ({ roomId, questionId, answer, username }) => {
        try {
            await rateLimitEvent(username, 'submitAnswer', 20, 60);

            console.log(`Received answer from ${username} in room ${roomId} for question ${questionId}:`, { answer });

            const room = await getGameRoom(roomId);
            if (!room) {
                console.error(`Room ${roomId} not found for answer submission`);
                return;
            }

            const player = room.players.find(p => p.username === username && !p.isBot);
            if (!player) {
                console.error(`Player ${username} not found in room ${roomId} or is a bot`);
                return;
            }

            // Check if player already answered this question
            if (player.answered) {
                console.log(`Player ${username} already answered this question`);
                return;
            }

            const currentQuestion = room.questionIdMap.get(questionId);
            if (!currentQuestion) {
                console.error(`Question ${questionId} not found in room ${roomId}`);
                return;
            }

            const responseTime = moment().diff(room.questionStartTime, 'milliseconds');
            if (responseTime < 0 || responseTime > 10000) {
                console.error(`Invalid response time ${responseTime}ms from ${username}`);
                socket.emit('answerError', 'Invalid response time');
                return;
            }

            player.totalResponseTime = (player.totalResponseTime || 0) + responseTime;
            player.lastRoundResponseTime = responseTime;
            player.lastAnswer = answer;
            player.answered = true;

            // Use the stored shuffledCorrectAnswer from questionIdMap
            const isCorrect = answer === currentQuestion.shuffledCorrectAnswer;

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

            await setGameRoom(roomId, room);

            // Send individual answer result to the player who answered
            socket.emit('answerResult', {
                username: player.username,
                isCorrect,
                correctAnswer: currentQuestion.shuffledCorrectAnswer,
                responseTime
            });

            // Notify OTHER players that this player has answered (without revealing the answer)
            socket.to(roomId).emit('playerAnswered', {
                username,
                isBot: false,
                responseTime
            });

            // DO NOT complete the round immediately - always wait for the timer
            // This ensures all players get the full 10 seconds to see and answer
            console.log(`Player ${username} answered, but waiting for timer to complete the round`);
            
            // Note: The round will only complete when the 10-second timer expires
        } catch (error) {
            console.error('Rate limit error for submitAnswer:', error.message);
            socket.emit('answerError', 'Too many answer submissions. Please try again later.');
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

    socket.on('disconnect', async () => {
        console.log('Client disconnected:', socket.id);

        // Remove from matchmaking pools
        const betAmounts = await redisClient.keys('matchmakingPool:*');
        for (const poolKey of betAmounts) {
            const betAmount = poolKey.split(':')[1];
            const removedPlayer = await removeFromMatchmakingPool(betAmount, socket.id);
            if (removedPlayer) {
                console.log(`Player ${removedPlayer.walletAddress} (socket ${socket.id}) removed from matchmaking pool for ${betAmount}`);
                await logMatchmakingState();
            }
        }

        // Handle disconnection from active game rooms
        const activeRooms = await getActiveGameRooms();
        for (const roomId of activeRooms) {
            const room = await getGameRoom(roomId);
            if (!room) continue;

            const playerIndex = room.players.findIndex(p => p.id === socket.id);
            if (playerIndex !== -1) {
                const disconnectedPlayer = room.players[playerIndex];
                console.log(`Player ${disconnectedPlayer.username} (socket ${socket.id}) disconnected from room ${roomId}`);

                room.players.splice(playerIndex, 1);
                room.playerLeft = true;

                if (room.questionTimeout) {
                    clearTimeout(room.questionTimeout);
                    room.questionTimeout = null;
                }

                await setGameRoom(roomId, room);

                if (room.roomMode === 'bot') {
                    console.log(`Human player ${disconnectedPlayer.username} left bot game. Bot wins by forfeit.`);
                    const botPlayer = room.players.find(p => p.isBot);
                    if (botPlayer) {
                        const winnerName = botPlayer.username;
                        const allPlayersForStats = [
                            {
                                username: disconnectedPlayer.username,
                                score: disconnectedPlayer.score || 0,
                                totalResponseTime: disconnectedPlayer.totalResponseTime || 0,
                                isBot: false
                            },
                            {
                                username: botPlayer.username,
                                score: botPlayer.score || 0,
                                totalResponseTime: botPlayer.totalResponseTime || 0,
                                isBot: true
                            }
                        ];

                        console.log(`Calling updatePlayerStats for bot forfeit. Winner: ${winnerName}, Bet: ${room.betAmount}`);
                        await updatePlayerStats(allPlayersForStats, {
                            winner: winnerName,
                            botOpponent: true,
                            betAmount: room.betAmount
                        });

                        io.to(roomId).emit('gameOverForfeit', {
                            winner: winnerName,
                            disconnectedPlayer: disconnectedPlayer.username,
                            betAmount: room.betAmount,
                            botOpponent: true,
                            message: `${disconnectedPlayer.username} left the game. ${winnerName} wins by default.`
                        });

                        await deleteGameRoom(roomId);
                        await logGameRoomsState();
                        return;
                    } else {
                        console.error(`CRITICAL: Bot not found in bot game room ${roomId}`);
                        io.to(roomId).emit('gameError', 'An error occurred due to player disconnection.');
                        await deleteGameRoom(roomId);
                        await logGameRoomsState();
                        return;
                    }
                }

                if (room.players.length === 1 && !room.players[0].isBot) {
                    const remainingPlayer = room.players[0];
                    console.log(`Player ${disconnectedPlayer.username} left H2H game. ${remainingPlayer.username} wins by forfeit.`);

                    const allPlayersForStats = [
                        {
                            username: remainingPlayer.username,
                            score: remainingPlayer.score || 0,
                            totalResponseTime: remainingPlayer.totalResponseTime || 0,
                            isBot: false
                        },
                        {
                            username: disconnectedPlayer.username,
                            score: disconnectedPlayer.score || 0,
                            totalResponseTime: disconnectedPlayer.totalResponseTime || 0,
                            isBot: false
                        }
                    ];

                    await handlePlayerLeftWin(roomId, remainingPlayer, disconnectedPlayer, room.betAmount, false, allPlayersForStats);
                    await logGameRoomsState();
                    return;
                }

                if (room.players.length === 0) {
                    console.log(`Room ${roomId} is now empty after ${disconnectedPlayer.username} left. Deleting room.`);
                    await deleteGameRoom(roomId);
                    await logGameRoomsState();
                    return;
                }

                if (!room.gameStarted) {
                    io.to(roomId).emit('playerLeft', disconnectedPlayer.username);
                }

                await setGameRoom(roomId, room);
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
    const room = await getGameRoom(roomId);
    if (!room) {
        console.log(`Room ${roomId} not found when trying to start game`);
        return;
    }

    room.players.forEach(player => player.score = 0);

    try {
        // Fetch 7 random questions from MongoDB
        const rawQuestions = await Quiz.aggregate([{ $sample: { size: 7 } }]);
        console.log(`Fetched ${rawQuestions.length} questions for room ${roomId}`);

        // Generate temporary question IDs and store in room
        room.questions = rawQuestions.map((question, index) => {
            const tempId = `${roomId}-${uuidv4()}`;
            const questionData = {
                tempId,
                question: question.question,
                options: question.options,
                correctAnswer: question.correctAnswer
            };
            room.questionIdMap.set(tempId, questionData);
            return questionData;
        });

        await setGameRoom(roomId, room);

        io.to(roomId).emit('gameStart', {
            players: room.players.map(p => ({
                username: p.username,
                score: p.score,
                isBot: p.isBot || false,
                difficulty: p.isBot ? p.difficultyLevelString : undefined
            })),
            questionCount: room.questions.length
        });
        await startNextQuestion(roomId);
    } catch (error) {
        console.error('Error starting game:', error);
        io.to(roomId).emit('gameError', 'Failed to start the game. Please try again.');
    }
}

async function startNextQuestion(roomId) {
    const room = await getGameRoom(roomId);
    if (!room) {
        console.log(`Room ${roomId} not found when trying to start next question`);
        return;
    }

    const currentQuestion = room.questions[room.currentQuestionIndex];
    const questionStartTime = moment();

    // Shuffle options and determine new correct answer index
    const shuffledOptions = shuffleArray([...currentQuestion.options]);
    const shuffledCorrectAnswer = shuffledOptions.indexOf(currentQuestion.options[currentQuestion.correctAnswer]);
    
    // Store these in the questionIdMap so they persist through Redis serialization
    const questionData = room.questionIdMap.get(currentQuestion.tempId);
    if (questionData) {
        questionData.shuffledOptions = shuffledOptions;
        questionData.shuffledCorrectAnswer = shuffledCorrectAnswer;
        room.questionIdMap.set(currentQuestion.tempId, questionData);
    }

    // Reset player answered status for new question
    room.players.forEach(player => {
        player.answered = false;
        player.lastAnswer = null;
        player.lastRoundResponseTime = 0;
    });

    // Send temporary question ID and minimal data
    io.to(roomId).emit('nextQuestion', {
        questionId: currentQuestion.tempId,
        question: currentQuestion.question,
        options: shuffledOptions,
        questionNumber: room.currentQuestionIndex + 1,
        totalQuestions: room.questions.length,
        questionStartTime: questionStartTime.valueOf()
    });

    room.questionStartTime = questionStartTime;
    room.answersReceived = 0;

    // Clear any existing timeout
    if (room.questionTimeout) {
        clearTimeout(room.questionTimeout);
    }

    await setGameRoom(roomId, room);

    // Handle bot answer with a delay to give human player time to see the question
    const bot = room.players.find(p => p.isBot);
    if (bot) {
        // Add a minimum delay before bot starts "thinking" (2-3 seconds)
        const botStartDelay = 2000 + Math.random() * 1000; // 2-3 seconds
        
        setTimeout(async () => {
            try {
                const updatedRoom = await getGameRoom(roomId);
                if (!updatedRoom) {
                    console.log(`Room ${roomId} not found during bot answer delay`);
                    return;
                }

                const botAnswer = await bot.answerQuestion(
                    currentQuestion.question,
                    shuffledOptions,
                    shuffledCorrectAnswer
                );

                // Get the room again after bot answered (in case it was updated)
                const finalRoom = await getGameRoom(roomId);
                if (!finalRoom) {
                    console.log(`Room ${roomId} not found after bot answered`);
                    return;
                }

                // Update bot in the room
                const botInRoom = finalRoom.players.find(p => p.isBot && p.username === bot.username);
                if (botInRoom) {
                    botInRoom.answered = true;
                    botInRoom.lastAnswer = botAnswer.answer;
                    botInRoom.lastRoundResponseTime = botAnswer.responseTime;
                    botInRoom.totalResponseTime = (botInRoom.totalResponseTime || 0) + botAnswer.responseTime;
                    if (botAnswer.isCorrect) {
                        botInRoom.score = (botInRoom.score || 0) + 1;
                    }
                }

                await setGameRoom(roomId, finalRoom);

                io.to(roomId).emit('playerAnswered', {
                    username: bot.username,
                    isBot: true,
                    responseTime: botAnswer.responseTime
                });

                const humanPlayer = finalRoom.players.find(p => !p.isBot);
                if (!humanPlayer) {
                    console.log(`Human player disconnected from bot game in room ${roomId}`);
                    await handleBotGameForfeit(roomId, bot);
                    return;
                }

                // Check if all players have answered
                if (finalRoom.players.every(p => p.answered)) {
                    const questionData = finalRoom.questionIdMap.get(currentQuestion.tempId);
                    io.to(roomId).emit('roundComplete', {
                        questionId: currentQuestion.tempId,
                        correctAnswer: questionData.shuffledCorrectAnswer,
                        playerResults: finalRoom.players.map(p => ({
                            username: p.username,
                            isCorrect: p.lastAnswer === questionData.shuffledCorrectAnswer,
                            answer: p.lastAnswer,
                            responseTime: p.lastRoundResponseTime || 0,
                            isBot: p.isBot || false
                        }))
                    });
                    await completeQuestion(roomId);
                }
            } catch (error) {
                console.error(`Error processing bot answer in room ${roomId}:`, error);
                const errorRoom = await getGameRoom(roomId);
                if (errorRoom) {
                    io.to(roomId).emit('gameError', 'Error processing bot response. Game ended.');
                    await deleteGameRoom(roomId);
                }
            }
        }, botStartDelay);
    }

    // Set question timeout (10 seconds total)
    room.questionTimeout = setTimeout(async () => {
        const updatedRoom = await getGameRoom(roomId);
        if (!updatedRoom) return;

        let anyPlayerTimedOut = false;
        updatedRoom.players.forEach(player => {
            if (!player.isBot && !player.answered) {
                player.answered = true;
                player.lastAnswer = -1;
                player.lastRoundResponseTime = 10000; // Max time for timeout
                anyPlayerTimedOut = true;
                io.to(roomId).emit('playerAnswered', {
                    username: player.username,
                    isBot: false,
                    timedOut: true
                });
            }
        });

        if (anyPlayerTimedOut) {
            await setGameRoom(roomId, updatedRoom);
            
            // Check if all players have now answered
            if (updatedRoom.players.every(p => p.answered)) {
                await completeQuestion(roomId);
            }
        }
    }, 10000);
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
    const room = await getGameRoom(roomId);
    if (!room) {
        console.log(`Room ${roomId} not found in completeQuestion`);
        return;
    }

    // Reset answered status for next question
    room.players.forEach(player => {
        player.answered = false;
    });

    // Send score update with current response times
    io.to(roomId).emit('updateScores', room.players.map(p => ({
        username: p.username,
        score: p.score || 0,
        totalResponseTime: p.totalResponseTime || 0,
        isBot: p.isBot || false
    })));

    // Clear question timeout
    if (room.questionTimeout) {
        clearTimeout(room.questionTimeout);
        room.questionTimeout = null;
    }

    room.currentQuestionIndex += 1;
    room.answersReceived = 0;

    // Check if player left early
    if (room.playerLeft) {
        console.log(`Game in room ${roomId} ending early because a player left`);
        await handleGameOver(room, roomId);
        return;
    }

    await setGameRoom(roomId, room);

    // Check if there are more questions
    if (room.currentQuestionIndex < room.questions.length) {
        // Add a 2-second delay between questions to give players time to see results
        console.log(`Question ${room.currentQuestionIndex} of ${room.questions.length} completed, starting next question in 2 seconds`);
        setTimeout(async () => {
            const updatedRoom = await getGameRoom(roomId);
            if (updatedRoom) {
                await startNextQuestion(roomId);
            } else {
                console.log(`Room ${roomId} no longer exists when starting next question`);
            }
        }, 2000);
    } else {
        console.log(`Final question completed in room ${roomId} - showing final results before game over`);
        
        // For the final question, give players more time to see the results
        // Send a special "final round complete" message
        io.to(roomId).emit('finalRoundComplete', {
            message: 'All questions completed! Calculating final results...',
            finalScores: room.players.map(p => ({
                username: p.username,
                score: p.score || 0,
                totalResponseTime: p.totalResponseTime || 0,
                isBot: p.isBot || false
            }))
        });
        
        // Wait 4 seconds before showing game over (longer delay for final results)
        setTimeout(async () => {
            const finalRoom = await getGameRoom(roomId);
            if (finalRoom) {
                console.log(`Game over in room ${roomId} - all questions completed`);
                await handleGameOver(finalRoom, roomId);
            } else {
                console.log(`Room ${roomId} no longer exists when ending game`);
            }
        }, 4000);
    }
}

async function handleGameOver(room, roomId) {
    const sortedPlayers = [...room.players].sort((a, b) => {
        if (b.score !== a.score) {
            return b.score - a.score;
        }
        return (a.totalResponseTime || 0) - (b.totalResponseTime || 0);
    });

    let winner = null;
    const botOpponent = room.players.some(p => p.isBot);
    const isSinglePlayerEncounter = room.roomMode === 'bot' || (sortedPlayers.length === 1 && !botOpponent);

    if (botOpponent && sortedPlayers.length >= 1) {
        const humanPlayer = room.players.find(p => !p.isBot);
        const botPlayer = room.players.find(p => p.isBot);

        if (humanPlayer && botPlayer) {
            if (humanPlayer.score > botPlayer.score) {
                winner = humanPlayer.username;
            } else if (botPlayer.score > humanPlayer.score) {
                winner = botPlayer.username;
            } else {
                if ((humanPlayer.totalResponseTime || 0) <= (botPlayer.totalResponseTime || 0)) {
                    winner = humanPlayer.username;
                } else {
                    winner = botPlayer.username;
                }
            }
        } else if (botPlayer && !humanPlayer) {
            winner = botPlayer.username;
        } else if (humanPlayer && !botPlayer) {
            winner = humanPlayer.username;
        } else if (sortedPlayers.length > 0) {
            winner = sortedPlayers[0].username;
        }
    } else if (sortedPlayers.length === 1) {
        winner = sortedPlayers[0].username;
    } else if (sortedPlayers.length > 1 && !botOpponent) {
        winner = sortedPlayers[0].username;
    }

    let payoutSignature = null;

    try {
        await updatePlayerStats(room.players, {
            winner: winner,
            botOpponent: botOpponent,
            betAmount: room.betAmount
        });

        const winnerIsActuallyHuman = winner && !room.players.find(p => p.username === winner && p.isBot);

        if (winnerIsActuallyHuman) {
            const multiplier = botOpponent ? 1.5 : 1.8;
            const winningAmount = room.betAmount * multiplier;

            // Queue payment
            await paymentProcessor.queuePayment(
                winner,  // recipientWallet
                winningAmount,  // amount
                roomId,  // gameId (use roomId or generate a unique game ID)
                room.betAmount,  // betAmount
                {  // metadata
                    botOpponent,
                    players: room.players.map(p => p.username),
                    scores: room.players.map(p => p.score)
                }
            );

            io.to(roomId).emit('gameOver', {
                players: sortedPlayers.map(p => ({
                    username: p.username,
                    score: p.score || 0,
                    totalResponseTime: p.totalResponseTime || 0,
                    isBot: p.isBot || false
                })),
                winner: winner,
                betAmount: room.betAmount,
                payoutStatus: 'PROCESSING',
                singlePlayerMode: isSinglePlayerEncounter,
                botOpponent: botOpponent
            });

        } else {
            io.to(roomId).emit('gameOver', {
                players: sortedPlayers.map(p => ({
                    username: p.username,
                    score: p.score || 0,
                    totalResponseTime: p.totalResponseTime || 0,
                    isBot: p.isBot || false
                })),
                winner: winner,
                betAmount: room.betAmount,
                singlePlayerMode: isSinglePlayerEncounter,
                botOpponent: botOpponent
            });
        }

        await deleteGameRoom(roomId);
    } catch (error) {
        console.error('Error handling game over:', error);
        io.to(roomId).emit('gameError', 'An error occurred while ending the game.');
        await deleteGameRoom(roomId);
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
    const room = await getGameRoom(roomId);
    if (!room) {
        console.log('Room not found for bot creation');
        return;
    }
    
    if (room.roomMode !== 'bot') {
        console.log(`Room ${roomId} is no longer in bot mode, not adding bot`);
        return;
    }

    try {
        const rawQuestions = await Quiz.aggregate([{ $sample: { size: 7 } }]);
        room.questions = rawQuestions.map((question, index) => {
            const tempId = `${roomId}-${uuidv4()}`;
            const questionData = {
                tempId,
                question: question.question,
                options: question.options,
                correctAnswer: question.correctAnswer
            };
            room.questionIdMap.set(tempId, questionData);
            return questionData;
        });
        await setGameRoom(roomId, room);
        
        const humanPlayers = room.players.filter(p => !p.isBot);
        
        if (humanPlayers.length !== 1) {
            console.log(`Room ${roomId} has ${humanPlayers.length} human players, expected exactly 1`);
            if (humanPlayers.length === 0) {
                await deleteGameRoom(roomId);
            } else {
                room.roomMode = 'multiplayer';
                await setGameRoom(roomId, room);
                io.to(roomId).emit('gameStart', { 
                    players: room.players,
                    questionCount: room.questions.length,
                    singlePlayerMode: false
                });
                room.gameStarted = true;
                await setGameRoom(roomId, room);
                startNextQuestion(roomId);
            }
            return;
        }
        
        const humanPlayer = humanPlayers[0];
        console.log('Human player:', humanPlayer.username);
        
        humanPlayer.score = 0;
        humanPlayer.totalResponseTime = 0;
        humanPlayer.answered = false;
        humanPlayer.lastAnswer = null;
        await setGameRoom(roomId, room);
        
        if (room.players.some(p => p.isBot)) {
            console.log(`Room ${roomId} already has a bot player`);
            if (!room.gameStarted) {
                room.gameStarted = true;
                await setGameRoom(roomId, room);
                startNextQuestion(roomId);
            }
            return;
        }
        
        const difficultyString = await determineBotDifficulty(humanPlayer.username); // This is the string e.g. "HARD"
        const botName = chooseBotName();
        console.log('Creating bot with name:', botName, 'and difficulty:', difficultyString);
        
        const bot = new TriviaBot(botName, difficultyString);
        
        room.players.push(bot);
        room.hasBot = true;
        console.log('Bot added to room. Total players:', room.players.length);
        await setGameRoom(roomId, room);
        
        io.to(roomId).emit('botGameReady', {
            botName: bot.username,
            difficulty: bot.difficultyLevelString // Use the stored string for client
        });
        
        io.to(roomId).emit('gameStart', { 
            players: room.players.map(p => ({
                username: p.username,
                score: p.score,
                isBot: p.isBot || false,
                difficulty: p.isBot ? p.difficultyLevelString : undefined // Use the stored string for client
            })),
            questionCount: room.questions.length,
            singlePlayerMode: true,
            botOpponent: bot.username
        });

        room.gameStarted = true;
        await setGameRoom(roomId, room);
        startNextQuestion(roomId);
    } catch (error) {
        console.error('Error starting single player game with bot:', error);
        io.to(roomId).emit('gameError', 'Failed to start the game. Please try again.');
    }
}

async function findAvailableRoom(betAmount) {
    const activeRooms = await getActiveGameRooms();
    for (const roomId of activeRooms) {
        const room = await getGameRoom(roomId);
        if (room && room.players.length < 2 && room.betAmount === betAmount) {
            return roomId;
        }
    }
    return null;
}

async function createGameRoom(roomId, betAmount, roomMode = null) {
    const room = {
        players: [],
        betAmount,
        questions: [],
        questionIdMap: new Map(),
        currentQuestionIndex: 0,
        answersReceived: 0,
        gameStarted: false,
        roomMode: roomMode,
        waitingTimeout: null,
        questionTimeout: null,
        playerLeft: false,
        hasBot: false
    };
    await setGameRoom(roomId, room);
}

/*
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
*/

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

/*
function determineWinner(players) {
    if (!players || players.length === 0) {
      return null;
    }
    
    if (players.length === 1) {
      // Single player mode - win if score is 5 or more (or use your threshold logic)
      return players[0].score >= 5 ? players[0].username : null;
    }
    
    if (players[0].score > players[1].score) {
      return players[0].username;
    } else if (players[0].score === players[1].score) {
      return players[0].totalResponseTime <= players[1].totalResponseTime ? 
        players[0].username : players[1].username;
    }
    
    // Should never reach here if players are sorted properly
    return null;
  }
  */

  /*
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
*/

  async function handlePlayerLeftWin(roomId, remainingPlayer, disconnectedPlayer, betAmount, botOpponent, allPlayers) {
    try {
        const multiplier = botOpponent ? 1.5 : 1.8;
        const winningAmount = betAmount * multiplier;

        let payoutSignature = null;
        if (!botOpponent) {
            payoutSignature = await sendWinnings(remainingPlayer.username, betAmount, botOpponent);
        }

        io.to(roomId).emit('gameOverForfeit', {
            winner: remainingPlayer.username,
            disconnectedPlayer: disconnectedPlayer.username,
            betAmount: betAmount,
            payoutSignature,
            botOpponent,
            message: `${disconnectedPlayer.username} left the game. ${remainingPlayer.username} wins by forfeit!`
        });

        await updatePlayerStats(allPlayers, {
            winner: remainingPlayer.username,
            botOpponent: botOpponent,
            betAmount: betAmount
        });

        await deleteGameRoom(roomId);
    } catch (error) {
        console.error('Error processing player left win:', error);
        io.to(roomId).emit('gameError', 'Error processing win after player left. Please contact support.');
        await deleteGameRoom(roomId);
    }
}

async function handleBotGameForfeit(roomId, bot) {
    const room = await getGameRoom(roomId);
    if (!room) {
        console.log(`Room ${roomId} not found during bot game forfeit`);
        return;
    }

    console.log(`Handling bot game forfeit in room ${roomId}`);

    if (room.questionTimeout) {
        clearTimeout(room.questionTimeout);
    }

    const humanPlayer = {
        username: room.players.find(p => !p.isBot)?.username || 'Unknown',
        score: 0,
        isBot: false
    };

    const allPlayers = [
        {
            username: humanPlayer.username,
            score: 0,
            isBot: false
        },
        {
            username: bot.username,
            score: bot.score || 0,
            isBot: true
        }
    ];

    io.to(roomId).emit('gameOverForfeit', {
        winner: bot.username,
        disconnectedPlayer: humanPlayer.username,
        betAmount: room.betAmount,
        botOpponent: true,
        message: `You left the game. ${bot.username} wins by default.`
    });

    await updatePlayerStats(allPlayers, {
        winner: bot.username,
        botOpponent: true,
        betAmount: room.betAmount
    });

    await deleteGameRoom(roomId);
    console.log(`Bot game room ${roomId} cleaned up after forfeit`);
}

async function logGameRoomsState() {
    console.log('Current game rooms state:');
    const activeRooms = await getActiveGameRooms();
    console.log(`Total rooms: ${activeRooms.length}`);

    for (const roomId of activeRooms) {
        const room = await getGameRoom(roomId);
        if (!room) continue;
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
    }
}

async function logMatchmakingState() {
    console.log('Current Matchmaking State:');

    console.log('Human Matchmaking Pools:');
    const betAmounts = await redisClient.keys('matchmakingPool:*');
    for (const poolKey of betAmounts) {
        const betAmount = poolKey.split(':')[1];
        const pool = await getMatchmakingPool(betAmount);
        console.log(`  Bet Amount ${betAmount}: ${pool.length} players waiting`);
        if (pool.length > 0) {
            pool.forEach((player, index) => {
                const waitTime = Math.round((Date.now() - player.joinTime) / 1000);
                console.log(`    - ${player.walletAddress} (waiting for ${waitTime}s)`);
            });
        }
    }

    console.log('Game Rooms:');
    await logGameRoomsState();
}

setInterval(async () => {
    const now = Date.now();
    const MAX_WAIT_TIME = 5 * 60 * 1000; // 5 minutes

    const betAmounts = await redisClient.keys('matchmakingPool:*');
    for (const poolKey of betAmounts) {
        const betAmount = poolKey.split(':')[1];
        const pool = await getMatchmakingPool(betAmount);
        const expiredPlayers = pool.filter(player => (now - player.joinTime) > MAX_WAIT_TIME);

        if (expiredPlayers.length > 0) {
            console.log(`Removing ${expiredPlayers.length} expired players from matchmaking pool for ${betAmount}`);

            for (const player of expiredPlayers) {
                await removeFromMatchmakingPool(betAmount, player.socketId);
                const playerSocket = io.sockets.sockets.get(player.socketId);
                if (playerSocket) {
                    playerSocket.emit('matchmakingExpired', {
                        message: 'Your matchmaking request has expired'
                    });
                }
            }
        }
    }
}, 60000);

setInterval(async () => {
    const activeRooms = await getActiveGameRooms();
    for (const roomId of activeRooms) {
        const room = await getGameRoom(roomId);
        if (!room) {
            await deleteGameRoom(roomId);
            continue;
        }
        if (room.players.length === 0) {
            console.log(`Cleaning up empty room ${roomId}`);
            await deleteGameRoom(roomId);
        }
    }
}, 300000); // Run every 5 minutes

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