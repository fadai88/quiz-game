const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const { createAdapter } = require('@socket.io/redis-adapter'); // New: Redis adapter for scaling
const Redis = require('ioredis'); // Already present, but ensure >=4.0
const { RateLimiterRedis } = require('rate-limiter-flexible'); // For enhanced rate-limiting
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();
const { v4: uuidv4 } = require('uuid');
const User = require('./models/User');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { Connection, PublicKey, SystemProgram, Transaction, sendAndConfirmTransaction, Keypair } = require('@solana/web3.js');
const Joi = require('joi');
const BotDetector = require('./botDetector');
const crypto = require('crypto');

// NEW: Import PaymentQueue and PaymentProcessor for resilient payouts
const PaymentQueue = require('./models/PaymentQueue'); // Adjust path as needed
const PaymentProcessor = require('./services/PaymentProcessor'); // Adjust path as needed

// Validate critical configuration on startup
const ENVIRONMENT = process.env.NODE_ENV || 'development';

if (ENVIRONMENT === 'production') {
    console.log('🚀 Starting in PRODUCTION mode');
    
    // Enforce reCAPTCHA in production
    if (process.env.ENABLE_RECAPTCHA !== 'true') {
        console.error('❌ FATAL: ENABLE_RECAPTCHA must be "true" in production!');
        console.error('   Set ENABLE_RECAPTCHA=true in your .env file');
        process.exit(1); // Don't start server
    }
    
    if (!process.env.RECAPTCHA_SECRET_KEY) {
        console.error('❌ FATAL: RECAPTCHA_SECRET_KEY missing in production!');
        process.exit(1);
    }
    
    console.log('✅ reCAPTCHA properly configured for production');
} else {
    console.log('🔧 Starting in DEVELOPMENT mode');
    if (process.env.ENABLE_RECAPTCHA === 'true') {
        console.log('   reCAPTCHA: ENABLED (for testing)');
    } else {
        console.log('   reCAPTCHA: DISABLED (faster development)');
    }
}

const TransactionLog = mongoose.model('TransactionLog', new mongoose.Schema({
    signature: { 
        type: String, 
        required: true, 
        unique: true,  // ✅ Enforce at DB level
        index: true 
    },
    walletAddress: String,
    betAmount: Number,
    verifiedAt: { type: Date, default: Date.now },
    status: { type: String, enum: ['verified', 'replayed', 'failed'] }
}));

// NEW: Global flag for Redis health - critical for transaction processing
let redisHealthy = false;

// NEW: Reusable Joi custom validator for Solana public keys
const solanaPublicKey = Joi.string().required().custom((value, helpers) => {
    // Quick regex pre-check for base58 (32-44 chars, valid chars)
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)) {
        return helpers.error('any.invalid', { message: 'Invalid Solana public key format' });
    }
    try {
        new PublicKey(value);
        return value;
    } catch (err) {
        return helpers.error('any.invalid', { message: 'Invalid Solana public key' });
    }
}, 'Solana Public Key Validation');

// NEW: Nonce validator (UUID v4)
const nonceSchema = Joi.string().guid({ version: 'uuidv4' }).required();

const transactionSchema = Joi.object({
    walletAddress: solanaPublicKey,  // FIXED: Use custom validator
    betAmount: Joi.number().valid(3, 10, 15, 20, 30).required(),
    transactionSignature: Joi.string().required(),
    nonce: nonceSchema,  // NEW: Add nonce
    gameMode: Joi.string().optional(),
    recaptchaToken: Joi.string().required()
});

const submitAnswerSchema = Joi.object({
    roomId: Joi.string().required(),
    questionId: Joi.string().required(),
    answer: Joi.number().integer().min(-1).required(),
    recaptchaToken: Joi.string().allow(null, '').optional()  // username removed - will use socket.user.walletAddress
});

const playerReadySchema = Joi.object({
    roomId: Joi.string().required(),
    preferredMode: Joi.string().valid('human', 'bot').optional(),
    recaptchaToken: Joi.string().optional()
});

const switchToBotSchema = Joi.object({
    roomId: Joi.string().required()
});

const requestBotRoomSchema = Joi.object({
    walletAddress: solanaPublicKey,  // FIXED: Use custom validator
    betAmount: Joi.number().valid(3, 10, 15, 20, 30).required(),  // FIXED: Tightened to game options
    nonce: nonceSchema.optional()  // NEW: Add nonce (optional for non-transaction events)
});

const requestBotGameSchema = Joi.object({
    roomId: Joi.string().required()
});

const leaveRoomSchema = Joi.object({
    roomId: Joi.string().required()
});

const matchFoundSchema = Joi.object({
    newRoomId: Joi.string().required()
});

const { 
    createAssociatedTokenAccountInstruction, 
    getAssociatedTokenAddress, 
    createTransferCheckedInstruction,
    TOKEN_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID
} = require('@solana/spl-token');
const { Program } = require('@project-serum/anchor');
const nacl = require('tweetnacl');
const { Token: SPLToken } = require('@solana/spl-token');

const app = express();
const server = http.createServer(app);

// Restrict CORS: Replace "*" with your domain(s) e.g., ["https://yourgame.com", "http://localhost:3000"]
const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ["http://localhost:3000"];
app.use(cors({
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true
}));

const io = socketIo(server, {
    cors: {
        origin: allowedOrigins,
        methods: ["GET", "POST"]
    },
    // Enable maxHttpBufferSize to mitigate CVE-2023-32695 (packet DoS)
    maxHttpBufferSize: 1e6 // 1MB limit
});

// Enhanced rate-limiting: Per-socket, Redis-backed (install rate-limiter-flexible)
let socketRateLimiter;
async function initializeRateLimiter() {
    try {
        socketRateLimiter = new RateLimiterRedis({
            storeClient: redisClient,
            points: 200, // Max 100 events/min per socket
            duration: 60,
            keyPrefix: 'socket'
        });
        console.log('Socket rate-limiter initialized');
    } catch (error) {
        console.error('Failed to init rate-limiter:', error);
    }
}

// Auth middleware: Validate socket.user on events (post-login)
const authMiddleware = (socket, next) => {
    if (!socket.user || !socket.user.walletAddress) {
        next(new Error('Unauthorized: No valid session'));
    } else {
        next();
    }
};

app.use(express.json());
app.get('/game.html', (req, res) => {
    let gameHtml = fs.readFileSync(path.join(__dirname, 'public', 'game.html'), 'utf8');
    const recaptchaEnabled = process.env.ENABLE_RECAPTCHA === 'true';
    const recaptchaSiteKey = process.env.RECAPTCHA_SITE_KEY || '';
    gameHtml = gameHtml.replace('YOUR_SITE_KEY', recaptchaSiteKey);
    const recaptchaConfigScript = `<script>
        window.recaptchaEnabled = ${recaptchaEnabled};
        window.recaptchaSiteKey = "${recaptchaSiteKey}";
        console.log("Injection test: Globals set", { enabled: ${recaptchaEnabled}, key: "${recaptchaSiteKey}" });
    </script>`;
    gameHtml = gameHtml.replace('</head>', `${recaptchaConfigScript}</head>`);
    res.send(gameHtml);
});
app.use(express.static(path.join(__dirname, 'public')));

mongoose.connect(process.env.MONGODB_URI)  // <-- Remove options—modern default
    .then(async () => {
        console.log('Connected to MongoDB');
    })
    .catch(err => console.error('Could not connect to MongoDB', err));

const Quiz = mongoose.model('Quiz', new mongoose.Schema({
    question: String,
    options: [String],
    correctAnswer: Number
}));

const botDetector = new BotDetector();

const config = {
    USDC_MINT: new PublicKey('Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr'),
    TREASURY_WALLET: new PublicKey('GN6uUVKuijj15ULm3X954mQTKEzur9jxXdRRuLeMqmgH'),
    TREASURY_KEYPAIR: Keypair.fromSecretKey(
        Buffer.from(JSON.parse(process.env.TREASURY_SECRET_KEY))
    ),
    connection: new Connection(process.env.SOLANA_RPC_URL, 'confirmed'),
    // NEW: For PaymentProcessor - array of RPC endpoints for failover
    rpcEndpoints: [process.env.SOLANA_RPC_URL], // Add more for production failover
    io: io // Pass io for emitting events from processor
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

// NEW: Initialize PaymentProcessor after MongoDB connection
let paymentProcessor;
mongoose.connection.once('open', async () => {
    paymentProcessor = new PaymentProcessor(config);
    paymentProcessor.startProcessing(60000); // Process every 60s
    console.log('PaymentProcessor initialized and started');
});

async function initializeRedis() {
    try {
        redisClient = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
            // NEW: Robust retry configuration
            retryDelayOnFailover: 100,
            enableReadyCheck: true,
            maxRetriesPerRequest: 3,
            lazyConnect: true,
            connectTimeout: 10000,
            commandTimeout: 5000
        });
        
        // NEW: Health monitoring events
        redisClient.on('ready', () => {
            console.log('Redis ready');
            redisHealthy = true;
        });
        
        redisClient.on('connect', () => {
            console.log('Redis connected');
        });
        
        redisClient.on('error', (err) => {
            console.error('Redis error:', err);
            redisHealthy = false;
            // In prod, trigger health check failure/alert
        });
        
        redisClient.on('close', () => {
            console.warn('Redis connection closed');
            redisHealthy = false;
        });
        
        // Test Redis connection with ping
        await redisClient.ping();  // Simple health check
        await redisClient.set('test', '1', 'EX', 60);
        const testValue = await redisClient.get('test');
        console.log(`Redis test: ${testValue}`);
        redisHealthy = true;
        await initializeRateLimiter(); // Init after Redis
    } catch (error) {
        console.error('Failed to initialize Redis:', error);
        redisHealthy = false;
        // CRITICAL: Do not fallback; log and set unhealthy
        console.error('Redis unavailable - transaction processing disabled');
    }
}

initializeRedis().catch((err) => {
    console.error('Redis init failed:', err);
    redisHealthy = false;
});

// Socket.io Redis Adapter for scaling (pub/sub across processes)
let pubClient, subClient;
async function initializeSocketAdapter() {
    if (!redisHealthy) {
        console.warn('Skipping Socket.io Redis adapter - Redis unhealthy');
        return;
    }
    try {
        pubClient = redisClient.duplicate();
        subClient = redisClient.duplicate();
        io.adapter(createAdapter(pubClient, subClient));
        console.log('Socket.io Redis adapter initialized for scaling');
    } catch (error) {
        console.error('Failed to initialize Socket.io adapter:', error);
    }
}

if (redisHealthy) {
    initializeSocketAdapter().catch(console.error);
} else {
    console.warn('Socket.io adapter skipped due to Redis unhealthiness');
}

// SCAN-based helper: Replace KEYS for non-blocking iteration
async function scanKeys(pattern, batchSize = 100) {
    if (!redisHealthy) {
        throw new Error('Redis unavailable');
    }
    let cursor = '0';
    let keys = [];
    do {
        const result = await redisClient.scan(cursor, 'MATCH', pattern, 'COUNT', batchSize);
        cursor = result[0];
        keys = keys.concat(result[1]);
    } while (cursor !== '0');
    return keys;
}

// ✅ NEW: O(1) waiting room index management to replace O(N) room scans
async function addWaitingRoom(betAmount, roomId) {
    if (!redisHealthy) {
        console.warn('Cannot add waiting room - Redis unhealthy');
        return false;
    }
    try {
        await redisClient.zadd(`waiting_rooms:${betAmount}`, Date.now(), roomId);
        await redisClient.expire(`waiting_rooms:${betAmount}`, 3600);
        console.log(`Added room ${roomId} to waiting index for bet ${betAmount}`);
        return true;
    } catch (error) {
        console.error(`Error adding waiting room ${roomId}:`, error);
        return false;
    }
}

async function getWaitingRoom(betAmount) {
    if (!redisHealthy) {
        console.warn('Cannot get waiting room - Redis unhealthy');
        return null;
    }
    try {
        const roomIds = await redisClient.zrange(`waiting_rooms:${betAmount}`, 0, 0);
        return roomIds.length > 0 ? roomIds[0] : null;
    } catch (error) {
        console.error(`Error getting waiting room for bet ${betAmount}:`, error);
        return null;
    }
}

async function removeWaitingRoom(betAmount, roomId) {
    if (!redisHealthy) {
        console.warn('Cannot remove waiting room - Redis unhealthy');
        return;
    }
    try {
        await redisClient.zrem(`waiting_rooms:${betAmount}`, roomId);
        console.log(`Removed room ${roomId} from waiting index for bet ${betAmount}`);
    } catch (error) {
        console.error(`Error removing waiting room ${roomId}:`, error);
    }
}

async function verifyAndValidateTransaction(signature, expectedAmount, senderAddress, recipientAddress, nonce, maxRetries = 3, retryDelay = 500) {
    console.log(`Verifying transaction ${signature} for ${expectedAmount} USDC from ${senderAddress} to ${recipientAddress}, nonce: ${nonce}`);

    const key = `tx:${signature}`;
    const nonceKey = `nonce:${nonce}`;

    // Step 1: MongoDB atomic check-and-insert (PRIMARY PROTECTION)
    try {
        const result = await TransactionLog.findOneAndUpdate(
            { signature },
            {
                $setOnInsert: {
                    signature,
                    walletAddress: senderAddress,
                    betAmount: expectedAmount,
                    verifiedAt: new Date(),
                    status: 'verified'
                }
            },
            { upsert: true, new: false, runValidators: true }
        );

        if (result !== null) {
            console.error(`Duplicate transaction ${signature} (MongoDB atomic check)`);
            throw new Error('Transaction already processed');
        }
        console.log(`MongoDB audit entry created for ${signature}`);
    } catch (dbErr) {
        if (dbErr.code === 11000) {
            console.error(`Race condition: ${signature} duplicate key`);
            throw new Error('Transaction already processed');
        }
        console.error('MongoDB audit failed:', dbErr.message);
        throw new Error('Audit service unavailable');
    }

    // Step 2: Redis checks (fast path + nonce)
    if (redisHealthy) {
        try {
            const exists = await redisClient.get(key);
            if (exists) {
                console.log(`Redis replay detected for ${key}`);
                throw new Error('This transaction has already been used');
            }

            const storedNonce = await redisClient.get(nonceKey);
            if (storedNonce) {
                throw new Error('Nonce already used');
            }
            await redisClient.set(nonceKey, 'used', 'EX', 86400);
        } catch (redisErr) {
            console.error('Redis check failed:', redisErr.message);
            redisHealthy = false;
            // Continue - MongoDB is primary
        }
    }

    // Step 3-4: Blockchain validation
    let transaction;
    try {
        transaction = await verifyTransactionWithStatus(signature, maxRetries, retryDelay);
    } catch (error) {
        if (error.message.includes('Invalid param: Invalid')) {
            console.error(`Invalid transaction signature: ${signature}`);
            await TransactionLog.findOneAndUpdate(
                { signature },
                { status: 'failed', errorMessage: 'Invalid signature' }
            );
            throw new Error('Invalid transaction signature');
        }
        console.error(`Error verifying transaction ${signature}: ${error.message}`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: error.message }
        );
        throw new Error('Failed to verify transaction');
    }

    if (!transaction) {
        console.error(`Transaction ${signature} not found after ${maxRetries} retries`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: 'Transaction not found' }
        );
        throw new Error('Transaction could not be verified');
    }
    if (transaction.meta.err) {
        console.error(`Transaction ${signature} failed on chain: ${JSON.stringify(transaction.meta.err)}`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: JSON.stringify(transaction.meta.err) }
        );
        throw new Error('Transaction failed on the blockchain');
    }

    const postTokenBalances = transaction.meta.postTokenBalances;
    const preTokenBalances = transaction.meta.preTokenBalances;
    if (!postTokenBalances || !preTokenBalances) {
        console.error(`Transaction ${signature} missing token balances`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: 'Missing token balances' }
        );
        throw new Error('Transaction missing required balance information');
    }

    const treasuryPostBalance = postTokenBalances.find(b => b.owner === recipientAddress);
    const treasuryPreBalance = preTokenBalances.find(b => b.owner === recipientAddress);
    if (!treasuryPostBalance || !treasuryPreBalance) {
        console.error(`Transaction ${signature} missing treasury balance change`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: 'Missing treasury balance' }
        );
        throw new Error('Transaction does not include treasury balance change');
    }

    const balanceChange = (treasuryPostBalance.uiTokenAmount.uiAmount || 0) - (treasuryPreBalance.uiTokenAmount.uiAmount || 0);
    if (Math.abs(balanceChange - expectedAmount) > 0.001) {
        console.error(`Transaction ${signature} amount mismatch: expected ${expectedAmount}, got ${balanceChange}`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: `Amount mismatch: expected ${expectedAmount}, got ${balanceChange}` }
        );
        throw new Error('Transaction amount does not match the expected bet');
    }

    // Step 5: Cache in Redis (best-effort)
    if (redisHealthy) {
        try {
            await redisClient.set(key, 1, 'EX', 604800);
        } catch (redisErr) {
            console.error('Redis cache failed (non-blocking):', redisErr.message);
        }
    }

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
    if (!redisHealthy) {
        // Graceful degradation for rate limiting - allow but log
        console.warn(`Rate limiting skipped due to Redis unhealthiness for ${walletAddress}:${eventName}`);
        return;
    }
    const key = `rate:${walletAddress}:${eventName}`;
    const count = await redisClient.get(key) || 0;
    if (count >= maxRequests) {
        throw new Error(`Too many ${eventName} requests`);
    }
    await redisClient.set(key, parseInt(count) + 1, 'EX', windowSeconds);
}

// FIXED: Add Redis rate limiter for failed reCAPTCHA (max 5 per IP per hour)
async function rateLimitFailedRecaptcha(ip) {
    if (!redisHealthy) {
        console.warn(`reCAPTCHA rate limiting skipped due to Redis unhealthiness for ${ip}`);
        return;
    }
    const key = `recaptcha_fail:${ip}`;
    const attempts = await redisClient.get(key) || 0;
    if (parseInt(attempts) >= 5) {         
        throw new Error('Too many failed verification attempts. Try again in 1 hour.');
    }
    await redisClient.incr(key);
    await redisClient.expire(key, 3600); // 1 hour TTL
}

// Enhanced: Socket-specific rate-limit
async function rateLimitSocket(socket, points = 100, duration = 60) {
    if (!redisHealthy || !socketRateLimiter) {
        console.warn(`Socket rate limiting skipped for ${socket.id}`);
        return;
    }
    try {
        await socketRateLimiter.consume(socket.id, points);
    } catch (rejRes) {
        throw new Error(`Rate limited: ${rejRes.consumedPoints} points used of ${points}`);
    }
}

function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
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
        // Store the string for client-side display or other uses
        this.difficultyLevelString = difficultyString;
        this.currentQuestionIndex = 0;
        this.answersGiven = [];
        this.isBot = true;
    }

    async answerQuestion(question, options, correctAnswer) {
        // Determine if the bot will answer correctly based on difficulty
        const willAnswerCorrectly = Math.random() < this.difficultySetting.correctRate; // Use difficultySetting
        
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
        const [minTime, maxTime] = this.difficultySetting.responseTimeRange; // Use difficultySetting
        const responseTime = Math.floor(Math.random() * (maxTime - minTime)) + minTime;
        
        await new Promise(resolve => setTimeout(resolve, responseTime));
        
        this.totalResponseTime += responseTime;
        
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

// Enable authentication middleware with exemptions for login events
io.use((socket, next) => {
    // Exempt login/reconnect (no socket.user yet) - check handshake auth
    const incomingEvent = socket.handshake.auth?.event || '';  // Client sends this on connect (e.g., { auth: { event: 'walletLogin' } })
    if (incomingEvent === 'walletLogin' || incomingEvent === 'walletReconnect') {
        return next();  // Allow without auth
    }
    
    // Otherwise, enforce full middleware for game events
    authMiddleware(socket, next);
});

io.on('connection', (socket) => {
    console.log('New client connected:', socket.id);
    
    const connectionData = {
        ip: socket.handshake.headers['x-forwarded-for'] || socket.handshake.address,
        userAgent: socket.handshake.headers['user-agent'],
        timestamp: new Date(),
        sessionId: socket.id
    };
    
    botDetector.trackConnection(connectionData.ip, connectionData.userAgent, socket.id);
    
    if (redisHealthy && redisClient) {
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

    // In socket.use() middleware: Soften burst limit (5/10s → 10/30s)
    socket.use(async (packet, next) => {
        try {
            if (packet.type === 0 || packet.type === 2) { // Skip for connect/events
                next();
                return;
            }
            // Use a separate, burst-friendly limiter for packets
            if (!redisHealthy) {
                console.warn('Packet rate limiting skipped');
                next();
                return;
            }
            const packetLimiter = new RateLimiterRedis({
                storeClient: redisClient,
                points: 10, // 10 packets/30s burst
                duration: 30,
                keyPrefix: 'socket-packet'
            });
            await packetLimiter.consume(socket.id);
            next();
        } catch (error) {
            console.warn(`Packet rate limit hit for ${socket.id}: ${error.message}`);
            next(new Error('Rate limited'));
        }
    });

    socket.on('walletLogin', async ({ walletAddress, signature, message, recaptchaToken, clientData }) => {
        try {
            if (redisHealthy && redisClient) {
                const isWalletBlocked = await redisClient.get(`blocklist:wallet:${walletAddress}`);
                if (isWalletBlocked) {
                    console.warn(`Blocked wallet attempting to login: ${walletAddress}`);
                    socket.emit('loginFailure', 'This wallet is temporarily blocked.');
                    return;
                }
            }
            console.log('Wallet login attempt:', { walletAddress, recaptchaToken: !!recaptchaToken });
            
            // FIXED: Rate limit login attempts (existing) + failed reCAPTCHA specifically
            if (redisHealthy && redisClient) {
                const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                const loginLimitKey = `login:${clientIP}`;
                const loginAttempts = await redisClient.get(loginLimitKey) || 0;
                
                if (loginAttempts > 100) {
                    console.warn(`Rate limit exceeded for IP ${clientIP}`);
                    return socket.emit('loginFailure', 'Too many login attempts. Please try again later.');
                }
                await redisClient.set(loginLimitKey, parseInt(loginAttempts) + 1, 'EX', 3600);
                
            }
            
            // FIXED: Enforce reCAPTCHA - throw if fails (no fallback success)
            let recaptchaResult;
            try {
                recaptchaResult = await verifyRecaptcha(recaptchaToken);
            } catch (error) {
                // FIXED: Log failure for rate limiting, then emit error
                if (redisHealthy && redisClient) {
                    const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                    try {
                        await rateLimitFailedRecaptcha(clientIP); // Increment on failure
                    } catch (rateError) {
                        console.warn(`reCAPTCHA rate limit hit for IP ${clientIP}:`, rateError.message);
                        return socket.emit('loginFailure', rateError.message);
                    }
                }
                console.warn(`reCAPTCHA verification failed for wallet ${walletAddress}: ${error.message}`);
                return socket.emit('loginFailure', error.message);
            }
            console.log('reCAPTCHA verification result:', recaptchaResult);
            
            // FIXED: Fallback anomaly check if reCAPTCHA disabled (basic clientData validation)
            if (process.env.ENABLE_RECAPTCHA !== 'true') {
                const anomalies = [];
                if (!clientData) anomalies.push('missing clientData');
                else {
                    // Example checks: impossible values
                    if (clientData.timezone && !Intl.supportedValuesOf('timeZone').includes(clientData.timezone)) anomalies.push('invalid timezone');
                    if (clientData.screenResolution && !/^\d+x\d+$/.test(clientData.screenResolution)) anomalies.push('invalid resolution');
                }
                if (anomalies.length > 0) {
                    console.warn(`Client data anomalies for ${walletAddress}: ${anomalies.join(', ')}`);
                    return socket.emit('loginFailure', 'Invalid client information. Please try again.');
                }
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
                        userAgent: connectionData.userAgent,
                        recentQuestions: []
                    });
                } else {
                    user.lastLoginIP = connectionData.ip;
                    user.lastLoginDate = new Date();
                    user.userAgent = connectionData.userAgent;
                    await user.save();
                }

                const fingerprint = crypto.createHash('sha256').update(JSON.stringify(clientData)).digest('hex');
                user.deviceFingerprint = fingerprint;
                await user.save();

                socket.user = { walletAddress, fingerprint };

                console.log('Login successful for wallet:', walletAddress);
                
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
            console.log(`Reconnect attempt for wallet: ${walletAddress}`);
            const user = await User.findOne({ walletAddress });
            if (user) {
                // Set socket.user for auth
                socket.user = { walletAddress };
                console.log(`Reconnect successful for ${walletAddress}`);
                socket.emit('loginSuccess', {
                    walletAddress: user.walletAddress,
                    virtualBalance: user.virtualBalance || 0
                });
            } else {
                socket.emit('loginFailure', 'Wallet not found—please login again');
            }
        } catch (error) {
            console.error('Reconnect error:', error);
            socket.emit('loginFailure', error.message);
        }
    });

    // NEW: Listen for payment completion/failure events from processor (broadcast to relevant sockets)
    socket.on('connect', () => {
        // Join a "wallet room" for payment notifications (use wallet as room name)
        if (socket.user && socket.user.walletAddress) {
            socket.join(`wallet:${socket.user.walletAddress}`);
        }
    });

    // Apply rate-limit + auth to game events
    const gameEvents = ['joinGame', 'playerReady', 'joinHumanMatchmaking', 'joinBotGame', 'switchToBot', 'matchFound', 'leaveRoom', 'requestBotRoom', 'requestBotGame', 'submitAnswer'];
    gameEvents.forEach(event => {
        socket.on(event, async (...args) => {
            try {
                // await rateLimitSocket(socket);
                if (!socket.user) throw new Error('Unauthorized');
                    
                // Call original handler based on event type
                if (event === 'joinGame') {
                    const data = args[0];
                    await rateLimitEvent(data.walletAddress, 'joinGame', 5, 60);
                    const { error } = transactionSchema.validate(data);
                    if (error) {
                        console.error('Validation error:', error.message);
                        socket.emit('joinGameFailure', error.message);
                        return;
                    }
                    const { walletAddress, betAmount } = data;

                    console.log('Join game request:', { walletAddress, betAmount });

                    if (!walletAddress || typeof betAmount !== 'number' || betAmount <= 0) {
                        throw new Error('Invalid join game request');
                    }

                    const roomId = generateRoomId();
                    await createGameRoom(roomId, betAmount, 'waiting');
                    let room = await getGameRoom(roomId);
                    room.players.push({
                        id: socket.id,
                        username: walletAddress,
                        score: 0,
                        totalResponseTime: 0
                    });
                    await updateGameRoom(roomId, room);

                    socket.join(roomId);
                    socket.roomId = roomId;  // FIXED: Store roomId on socket for O(1) disconnect cleanup
                    console.log(`Player ${walletAddress} joined temporary room ${roomId}`);
                    socket.emit('gameJoined', roomId);

                    await logGameRoomsState();
                } else if (event === 'playerReady') {
                    const { roomId, preferredMode, recaptchaToken } = args[0];
                    
                    // ✅ NEW: Rate limit playerReady to prevent DoS (max 3 per minute)
                    await rateLimitEvent(socket.user.walletAddress, 'playerReady', 3, 60);
                    
                    const { error } = playerReadySchema.validate({ roomId, preferredMode, recaptchaToken });
                    if (error) {
                        console.error('Validation error in playerReady:', error.message);
                        socket.emit('gameError', `Invalid input: ${error.message}`);
                        return;
                    }

                    console.log(`Player ${socket.id} ready in room ${roomId}, preferred mode: ${preferredMode || 'not specified'}`);
                    let room = await getGameRoom(roomId);

                    if (!room) {
                        console.error(`Room ${roomId} not found when player ${socket.id} marked ready`);
                        socket.emit('gameError', 'Room not found');
                        return;
                    }

                    const player = room.players.find(p => p.id === socket.id);
                    if (!player) {
                        socket.emit('gameError', 'Player not found in room');
                        return;
                    }
                    const username = player.username;

                    // Device fingerprint check
                    const user = await User.findOne({ walletAddress: username });
                    if (user && socket.user && user.deviceFingerprint !== socket.user.fingerprint) {
                        console.warn(`Device fingerprint mismatch for ${username} in playerReady`);
                        botDetector.trackEvent(username, 'fingerprint_mismatch', { event: 'playerReady' });
                        if (!recaptchaToken || !(await verifyRecaptcha(recaptchaToken)).success) {
                            socket.emit('gameError', 'Device verification failed. Please relogin.');
                            return;
                        }
                    }

                    // High-win streak captcha check
                    if (user && user.gamesPlayed > 5 && (user.wins / user.gamesPlayed) > 0.8) {
                        if (!recaptchaToken || !(await verifyRecaptcha(recaptchaToken)).success) {
                            socket.emit('gameError', 'Additional verification required due to high win rate.');
                            return;
                        }
                    }

                    // BotDetector integration
                    botDetector.trackEvent(username, 'player_ready', { preferredMode, roomId });

                    if (room.roomMode === 'bot') {
                        console.log(`Room ${roomId} is set for bot play, not starting regular game`);
                        return;
                    }

                    if (preferredMode === 'human') {
                        room.roomMode = 'human';
                        await updateGameRoom(roomId, room);
                        console.log(`Room ${roomId} marked for human vs human play`);

                        if (room.players.length === 1) {
                            let matchFound = false;

                            // ✅ FIXED: O(1) lookup instead of O(N) scanKeys
                            const otherRoomId = await getWaitingRoom(room.betAmount);
                            
                            if (otherRoomId && otherRoomId !== roomId) {
                                const otherRoom = await getGameRoom(otherRoomId);
                                if (
                                    otherRoom &&
                                    otherRoom.roomMode === 'human' &&
                                    !otherRoom.gameStarted &&
                                    otherRoom.betAmount === room.betAmount &&
                                    otherRoom.players.length === 1
                                ) {
                                    console.log(`Found matching room ${otherRoomId} for player in room ${roomId} (O(1) lookup)`);
                                    const player = room.players[0];
                                    otherRoom.players.push(player);
                                    await updateGameRoom(otherRoomId, otherRoom);

                                    socket.leave(roomId);
                                    if (roomId === socket.roomId) socket.roomId = null;
                                    socket.join(otherRoomId);
                                    socket.roomId = otherRoomId;

                                    socket.emit('matchFound', { newRoomId: otherRoomId });
                                    io.to(otherRoomId).emit('playerJoined', player.username);

                                    otherRoom.gameStarted = true;
                                    await updateGameRoom(otherRoomId, otherRoom);
                                    await startGame(otherRoomId);

                                    // ✅ Clean up both rooms from waiting index
                                    await removeWaitingRoom(room.betAmount, roomId);
                                    await removeWaitingRoom(room.betAmount, otherRoomId);
                                    await deleteGameRoom(roomId);
                                    matchFound = true;
                                } else {
                                    // Other room invalid/gone, remove from index and add current room
                                    console.log(`Waiting room ${otherRoomId} no longer valid, replacing with ${roomId}`);
                                    await removeWaitingRoom(room.betAmount, otherRoomId);
                                    await addWaitingRoom(room.betAmount, roomId);
                                }
                            } else {
                                // No waiting room found, add this one to index
                                await addWaitingRoom(room.betAmount, roomId);
                                console.log(`No match found for player in room ${roomId}, added to waiting index`);
                            }
                        }
                    }

                    if (room.players.length === 2 && !room.gameStarted) {
                        console.log(`Starting multiplayer game in room ${roomId} with 2 players`);
                        room.gameStarted = true;
                        room.roomMode = 'multiplayer';
                        await updateGameRoom(roomId, room);
                        await startGame(roomId);
                    } else {
                        console.log(`Room ${roomId} has ${room.players.length} players, waiting for more to join`);
                    }

                    await logGameRoomsState();
                } else if (event === 'joinHumanMatchmaking') {
                    if (!redisHealthy) {
                        socket.emit('joinGameFailure', 'Service temporarily unavailable - please try again later');
                        return;
                    }
                    const data = args[0];
                    await rateLimitEvent(data.walletAddress, 'joinHumanMatchmaking');
                    const { error } = transactionSchema.validate(data);
                    if (error) {
                        console.error('Validation error:', error.message);
                        socket.emit('joinGameFailure', error.message);
                        return;
                    }

                    const { walletAddress, betAmount, transactionSignature, gameMode, recaptchaToken, nonce } = data;  // NEW: Extract nonce
                    console.log('Human matchmaking request:', { walletAddress, betAmount, gameMode, nonce });

                    // FIXED: Strict reCAPTCHA enforcement
                    let recaptchaResult;
                    try {
                        recaptchaResult = await verifyRecaptcha(recaptchaToken);
                    } catch (error) {
                        console.error('reCAPTCHA failed for human matchmaking:', error.message);
                        // FIXED: Increment failed attempts ONLY on reCAPTCHA failure
                        if (redisHealthy && redisClient) {
                            const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                            await rateLimitFailedRecaptcha(clientIP);
                        }
                        socket.emit('joinGameFailure', error.message);  // Use error message directly
                        return;
                    }

                    const maxRetries = parseInt(process.env.TRANSACTION_RETRIES) || 3;
                    const retryDelay = parseInt(process.env.TRANSACTION_RETRY_DELAY) || 500;

                    const transaction = await verifyAndValidateTransaction(
                        transactionSignature,
                        betAmount,
                        walletAddress,
                        config.TREASURY_WALLET.toString(),
                        nonce,  // NEW: Pass nonce
                        maxRetries,
                        retryDelay
                    );

                    console.log('Transaction verified successfully');

                    // FIXED: Clean up existing room using socket.roomId (no scan needed)
                    if (socket.roomId) {
                        let existingRoom = await getGameRoom(socket.roomId);
                        if (existingRoom) {
                            const playerIndex = existingRoom.players.findIndex(p => p.username === walletAddress);
                            if (playerIndex !== -1) {
                                existingRoom.players.splice(playerIndex, 1);
                                await updateGameRoom(socket.roomId, existingRoom);
                                socket.leave(socket.roomId);
                                socket.roomId = null;  // FIXED: Clear roomId
                                console.log(`Player ${walletAddress} left room ${socket.roomId} for matchmaking`);
                                if (existingRoom.players.length === 0) {
                                    await deleteGameRoom(socket.roomId);
                                    console.log(`Deleted empty room ${socket.roomId}`);
                                }
                            }
                        }
                    }

                    // Step 1: Check for duplicates (read-only, safe)
                    const pool = await getMatchmakingPool(betAmount);
                    const existingPlayer = pool.find(p => p.walletAddress === walletAddress);
                    if (existingPlayer) {
                        socket.emit('matchmakingError', { message: 'You are already in matchmaking' });
                        return;
                    }

                    // Step 2: ATOMIC get-and-remove in ONE operation
                    // ✅ This is the critical fix!
                    const opponentJson = await redisClient.lpop(`matchmaking:human:${betAmount}`);

                    if (opponentJson) {
                        // SUCCESS: We atomically got an opponent
                        // No other server could have gotten this same player
                        const opponent = JSON.parse(opponentJson);
                        const roomId = generateRoomId();
                        console.log(`✅ ATOMIC MATCH: Creating game room ${roomId} for ${walletAddress} vs ${opponent.walletAddress}`);
                        
                        await createGameRoom(roomId, betAmount, 'multiplayer');
                        let room = await getGameRoom(roomId);
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
                        await updateGameRoom(roomId, room);

                        socket.join(roomId);
                        socket.roomId = roomId;
                        const opponentSocket = io.sockets.sockets.get(opponent.socketId);
                        if (opponentSocket) {
                            opponentSocket.join(roomId);
                            opponentSocket.roomId = roomId;
                            opponentSocket.matchmakingPool = null;
                        }

                        io.to(roomId).emit('matchFound', {
                            gameRoomId: roomId,
                            players: [walletAddress, opponent.walletAddress]
                        });

                        await startGame(roomId);
                    } else {
                        // FAILURE: Queue was empty
                        // Add current player to matchmaking pool
                        console.log(`No opponents available. Adding ${walletAddress} to matchmaking pool for ${betAmount}`);
                        // ✅ FIXED: Verify pool add succeeds before setting socket property
                        const poolAdded = await addToMatchmakingPool(betAmount, {
                            socketId: socket.id,
                            walletAddress,
                            joinTime: Date.now(),
                            transactionSignature
                        });

                        if (poolAdded) {
                            socket.matchmakingPool = betAmount;  // ✅ Only set if confirmed added
                            socket.emit('matchmakingJoined', {
                                waitingRoomId: `matchmaking-${betAmount}`,
                                position: (await getMatchmakingPool(betAmount)).length
                            });
                        } else {
                            // Should not happen (addToMatchmakingPool throws on error), but defensive
                            throw new Error('Failed to join matchmaking pool');
                        }
                    }

                    await logMatchmakingState();
                } else if (event === 'joinBotGame') {
                    if (!redisHealthy) {
                        socket.emit('joinGameFailure', 'Service temporarily unavailable - please try again later');
                        return;
                    }
                    const data = args[0];
                    await rateLimitEvent(data.walletAddress, 'joinBotGame', 3, 60);
                    const { error } = transactionSchema.validate(data);
                    if (error) {
                        console.error('Validation error:', error.message);
                        socket.emit('joinGameFailure', error.message);
                        return;
                    }

                    const { walletAddress, betAmount, transactionSignature, gameMode, recaptchaToken, nonce } = data;  // NEW: Extract nonce
                    console.log('Bot game request:', { walletAddress, betAmount, gameMode, nonce });

                    // FIXED: Strict reCAPTCHA enforcement
                    let recaptchaResult;
                    try {
                        recaptchaResult = await verifyRecaptcha(recaptchaToken);
                    } catch (error) {
                        console.error('reCAPTCHA failed for bot game:', error.message);
                        // FIXED: Increment failed attempts ONLY on reCAPTCHA failure
                        if (redisHealthy && redisClient) {
                            const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                            await rateLimitFailedRecaptcha(clientIP);
                        }
                        socket.emit('joinGameFailure', error.message);  // Use error message directly
                        return;
                    }

                    const maxRetries = parseInt(process.env.TRANSACTION_RETRIES) || 3;
                    const retryDelay = parseInt(process.env.TRANSACTION_RETRY_DELAY) || 500;

                    const transaction = await verifyAndValidateTransaction(
                        transactionSignature,
                        betAmount,
                        walletAddress,
                        config.TREASURY_WALLET.toString(),
                        nonce,  // NEW: Pass nonce
                        maxRetries,
                        retryDelay
                    );

                    console.log('Transaction verified successfully');

                    // FIXED: Clean up existing room using socket.roomId (no scan needed)
                    if (socket.roomId) {
                        let existingRoom = await getGameRoom(socket.roomId);
                        if (existingRoom) {
                            const playerIndex = existingRoom.players.findIndex(p => p.username === walletAddress);
                            if (playerIndex !== -1) {
                                console.log(`Player ${walletAddress} already in room ${socket.roomId}, cleaning up`);
                                existingRoom.players.splice(playerIndex, 1);
                                existingRoom.isDeleted = true;
                                await updateGameRoom(socket.roomId, existingRoom);
                                socket.leave(socket.roomId);
                                socket.roomId = null;  // FIXED: Clear roomId
                                await redisClient.del(`room:${socket.roomId}`);
                                console.log(`Deleted room ${socket.roomId} due to new bot game request`);
                            }
                        }
                    }

                    const roomId = generateRoomId();
                    console.log(`Creating bot game room ${roomId} for player ${walletAddress}`);

                    await createGameRoom(roomId, betAmount, 'bot');
                    let room = await getGameRoom(roomId);
                    room.players.push({
                        id: socket.id,
                        username: walletAddress,
                        score: 0,
                        totalResponseTime: 0
                    });
                    await updateGameRoom(roomId, room);

                    socket.join(roomId);
                    socket.roomId = roomId;  // FIXED: Set roomId on socket

                    const botName = chooseBotName();
                    socket.emit('botGameCreated', {
                        gameRoomId: roomId,
                        botName
                    });

                    await startSinglePlayerGame(roomId);
                    await logGameRoomsState();
                } else if (event === 'switchToBot') {
                    const { roomId } = args[0];
                    const { error } = switchToBotSchema.validate({ roomId });
                    if (error) {
                        console.error('Validation error in switchToBot:', error.message);
                        socket.emit('matchmakingError', { message: `Invalid input: ${error.message}` });
                        return;
                    }

                    console.log(`Player ${socket.id} wants to switch from matchmaking to bot game`);

                    let playerFound = false;
                    let playerData = null;
                    let playerBetAmount = null;

                    // FIXED: First, check if player is in a room (using socket.roomId, no scan)
                    if (socket.roomId) {
                        let existingRoom = await getGameRoom(socket.roomId);
                        if (existingRoom) {
                            const playerIndex = existingRoom.players.findIndex(p => p.id === socket.id);
                            if (playerIndex !== -1) {
                                playerData = existingRoom.players[playerIndex];
                                playerBetAmount = existingRoom.betAmount;
                                playerFound = true;
                                console.log(`Found player ${playerData.username} in room ${socket.roomId} with bet ${playerBetAmount}`);
                                existingRoom.players.splice(playerIndex, 1);
                                socket.leave(socket.roomId);
                                socket.roomId = null;  // FIXED: Clear roomId
                                if (existingRoom.players.length === 0) {
                                    await deleteGameRoom(socket.roomId);
                                    console.log(`Deleted empty room ${socket.roomId}`);
                                } else {
                                    await updateGameRoom(socket.roomId, existingRoom);
                                    io.to(socket.roomId).emit('playerLeft', playerData.username);
                                }
                            }
                        }
                    }

                    if (!playerFound && socket.matchmakingPool) {
                        console.log(`Player ${socket.id} found in matchmaking pool via socket reference`);
                        const playerDataFromPool = await removeFromMatchmakingPool(socket.matchmakingPool, socket.id);
                        if (playerDataFromPool) {
                            playerData = playerDataFromPool;
                            playerBetAmount = socket.matchmakingPool;
                            playerFound = true;
                            socket.matchmakingPool = null;  // ✅ Clear reference after removal
                            console.log(`Removed player ${playerData.walletAddress} from matchmaking pool for ${playerBetAmount}`);
                        }
                    }

                    // ✅ FIXED: Removed fallback scanKeys - force root cause fix
                    if (!playerFound) {
                        console.error(`CRITICAL METRIC: socket.matchmakingPool missing for ${socket.id} - potential bug or race condition`);
                        // TODO: Send to monitoring service (Sentry, Datadog, CloudWatch, etc.)
                        // Example: await metrics.increment('matchmaking.missing_pool_ref', { socketId: socket.id });
                        
                        socket.emit('matchmakingError', { 
                            message: 'Matchmaking state lost. Please try joining the queue again.' 
                        });
                        return;
                    }

                    if (!playerFound || !playerData) {
                        console.error(`Player ${socket.id} not found in any matchmaking pool or room`);
                        socket.emit('matchmakingError', { message: 'Not found in matchmaking or game rooms' });
                        return;
                    }

                    const playerIdentifier = playerData.username || playerData.walletAddress || socket.id;
                    const newRoomId = generateRoomId();
                    console.log(`Creating bot game room ${newRoomId} for player ${playerIdentifier}`);

                    // Create a new game room in Redis
                    await createGameRoom(newRoomId, playerBetAmount, 'bot');
                    let room = await getGameRoom(newRoomId);
                    if (!room) {
                        console.error(`Failed to create or retrieve room ${newRoomId}`);
                        socket.emit('matchmakingError', { message: 'Failed to create bot game room' });
                        return;
                    }

                    // Add player to the room
                    room.players.push({
                        id: socket.id,
                        username: playerIdentifier,
                        score: 0,
                        totalResponseTime: 0,
                        answered: false,
                        lastAnswer: null
                    });

                    // Update the room in Redis
                    await updateGameRoom(newRoomId, room);

                    socket.join(newRoomId);
                    socket.roomId = newRoomId;  // FIXED: Set roomId on socket

                    const botName = chooseBotName();
                    socket.emit('botGameCreated', {
                        gameRoomId: newRoomId,
                        botName
                    });

                    await startSinglePlayerGame(newRoomId);
                    await logGameRoomsState();
                    await logMatchmakingState();
                } else if (event === 'matchFound') {
                    const { newRoomId } = args[0];
                    try {
                        // Validate input
                        const { error } = matchFoundSchema.validate({ newRoomId });
                        if (error) {
                            console.error('Validation error in matchFound:', error.message);
                            socket.emit('gameError', `Invalid input: ${error.message}`);
                            return;
                        }

                        console.log(`Match found, player ${socket.id} moved to room ${newRoomId}`);
                        socket.roomId = newRoomId;  // FIXED: Set roomId on socket
                        // Additional handling if needed
                    } catch (error) {
                        console.error('Error in matchFound:', error);
                        socket.emit('gameError', `Error: ${error.message}`);
                    }
                } else if (event === 'leaveRoom') {
                    const { roomId } = args[0];
                    try {
                        const { error } = leaveRoomSchema.validate({ roomId });
                        if (error) {
                            console.error('Validation error in leaveRoom:', error.message);
                            socket.emit('gameError', `Invalid input: ${error.message}`);
                            return;
                        }

                        console.log(`Player ${socket.id} requested to leave room ${roomId}`);

                        let room = await getGameRoom(roomId);
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
                            if (roomId === socket.roomId) socket.roomId = null;  // FIXED: Clear roomId if matching

                            if (room.players.length === 0) {
                                console.log(`Room ${roomId} is now empty, deleting it`);
                                await deleteGameRoom(roomId);
                            } else {
                                await updateGameRoom(roomId, room);
                                console.log(`Notifying remaining players in room ${roomId}`);
                                io.to(roomId).emit('playerLeft', player.username);
                            }
                        }
                        
                        // ✅ NEW: Clear matchmaking ref if somehow set (edge case)
                        socket.matchmakingPool = null;

                        socket.emit('leftRoom', { roomId });
                    } catch (error) {
                        console.error('Error in leaveRoom:', error);
                        socket.emit('gameError', `Error: ${error.message}`);
                    }
                } else if (event === 'requestBotRoom') {
                    const { walletAddress, betAmount } = args[0];
                    try {
                        const { error } = requestBotRoomSchema.validate({ walletAddress, betAmount });
                        if (error) {
                            console.error('Validation error in requestBotRoom:', error.message);
                            socket.emit('gameError', `Invalid input: ${error.message}`);
                            return;
                        }

                        console.log(`Player ${walletAddress} requesting dedicated bot room with bet ${betAmount}`);

                        const roomId = generateRoomId();
                        console.log(`Creating new bot room ${roomId} for ${walletAddress}`);

                        await createGameRoom(roomId, betAmount, 'bot');
                        let room = await getGameRoom(roomId);
                        if (!room) {
                            console.error(`Failed to create or retrieve room ${roomId}`);
                            socket.emit('gameError', { message: 'Failed to create bot room' });
                            return;
                        }

                        room.players.push({
                            id: socket.id,
                            username: walletAddress,
                            score: 0,
                            totalResponseTime: 0
                        });

                        await updateGameRoom(roomId, room);

                        socket.join(roomId);
                        socket.roomId = roomId;  // FIXED: Set roomId on socket
                        socket.emit('botRoomCreated', roomId);
                        await logGameRoomsState();
                    } catch (error) {
                        console.error('Error in requestBotRoom:', error);
                        socket.emit('gameError', `Error: ${error.message}`);
                    }
                } else if (event === 'requestBotGame') {
                    const { roomId } = args[0];
                    try {
                        const { error } = requestBotGameSchema.validate({ roomId });
                        if (error) {
                            console.error('Validation error in requestBotGame:', error.message);
                            socket.emit('gameError', `Invalid input: ${error.message}`);
                            return;
                        }

                        console.log(`Bot game requested for room ${roomId}`);

                        let room = await getGameRoom(roomId);
                        if (!room) {
                            console.error(`Room ${roomId} not found when requesting bot game`);
                            socket.emit('gameError', 'Room not found');
                            return;
                        }

                        if (room.waitingTimeout) {
                            clearTimeout(room.waitingTimeout);
                            room.waitingTimeout = null;
                            await updateGameRoom(roomId, room);
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
                        await updateGameRoom(roomId, room);

                        await startSinglePlayerGame(roomId);
                        await logGameRoomsState();
                    } catch (error) {
                        console.error('Error in requestBotGame:', error);
                        socket.emit('gameError', `Error: ${error.message}`);
                    }
                } else if (event === 'submitAnswer') {
                    const { roomId, questionId, answer, recaptchaToken } = args[0];
                    try {
                        // ===== 1. INPUT VALIDATION =====
                        const { error } = submitAnswerSchema.validate({ roomId, questionId, answer, recaptchaToken });
                        if (error) {
                            console.error('Validation error in submitAnswer:', error.message);
                            socket.emit('answerError', `Invalid input: ${error.message}`);
                            return;
                        }

                        // ===== 2. AUTHENTICATION CHECK =====
                        if (!socket.user || !socket.user.walletAddress) {
                            socket.emit('answerError', 'Not authenticated');
                            return;
                        }

                        const authenticatedUsername = socket.user.walletAddress;
                        await rateLimitEvent(authenticatedUsername, 'submitAnswer', 10, 60);

                        console.log(`Received answer from ${authenticatedUsername} in room ${roomId} for question ${questionId}:`, { answer });

                        // ===== 3. ROOM & QUESTION VALIDATION =====
                        let room = await getGameRoom(roomId);
                        if (!room) {
                            console.error(`Room ${roomId} not found for answer submission`);
                            socket.emit('answerError', 'Room not found');
                            return;
                        }

                        if (!room.questionStartTime || room.currentQuestionIndex >= room.questions.length) {
                            console.error(`No active question in room ${roomId} when ${authenticatedUsername} submitted answer`);
                            socket.emit('answerError', 'No active question');
                            return;
                        }

                        const currentQuestion = room.questionIdMap.get(questionId);
                        if (!currentQuestion || questionId !== room.questions[room.currentQuestionIndex].tempId) {
                            console.error(`Invalid question ${questionId} for room ${roomId}`);
                            socket.emit('answerError', 'Invalid question');
                            return;
                        }

                        const player = room.players.find(p => p.username === authenticatedUsername && !p.isBot);
                        if (!player) {
                            console.error(`Player ${authenticatedUsername} not found in room ${roomId} or is a bot`);
                            socket.emit('answerError', 'Player not found');
                            return;
                        }

                        if (player.answered) {
                            console.log(`Player ${authenticatedUsername} already answered this question`);
                            socket.emit('answerError', 'Already answered');
                            return;
                        }

                        // ===== 4. TIMING VALIDATION =====
                        const serverResponseTime = Date.now() - room.questionStartTime;
                        if (serverResponseTime < 200 || serverResponseTime > 15000) {
                            console.warn(`Invalid response time ${serverResponseTime}ms from ${authenticatedUsername} in room ${roomId}`);
                            if (redisHealthy && redisClient) {
                                await redisClient.set(`suspect:${authenticatedUsername}`, 1, 'EX', 3600);
                            }
                            socket.emit('answerError', 'Invalid response timing');
                            return;
                        }

                        // ===== 5. BOT DETECTION =====
                        const botSuspicion = botDetector.getSuspicionScore(authenticatedUsername);
                        console.log(`Bot suspicion for ${authenticatedUsername}: ${botSuspicion}`);

                        // ===== 6. RECAPTCHA VERIFICATION (ENVIRONMENT-AWARE) =====
                        const isProduction = process.env.NODE_ENV === 'production';
                        let recaptchaResult = null;

                        if (isProduction) {
                            // PRODUCTION: ALWAYS require reCAPTCHA (no exceptions)
                            if (!recaptchaToken) {
                                console.error(`Missing reCAPTCHA token from ${authenticatedUsername} in PRODUCTION`);
                                socket.emit('answerError', 'Verification required');
                                return;
                            }

                            try {
                                recaptchaResult = await verifyRecaptcha(recaptchaToken);
                                console.log(`reCAPTCHA verified for ${authenticatedUsername} (score: ${recaptchaResult.score || 'N/A'})`);

                                // Check score threshold (v3 only)
                                if (recaptchaResult.score !== undefined && recaptchaResult.score < 0.5) {
                                    console.warn(`Low reCAPTCHA score ${recaptchaResult.score} for ${authenticatedUsername}`);
                                    botDetector.trackEvent(authenticatedUsername, 'low_recaptcha_score', { 
                                        score: recaptchaResult.score,
                                        event: 'submitAnswer'
                                    });
                                    socket.emit('answerError', 'Suspicious activity detected. Please try again.');
                                    return;
                                }
                            } catch (error) {
                                console.error(`reCAPTCHA verification failed for ${authenticatedUsername}: ${error.message}`);
                                
                                // Track failed attempt for rate limiting
                                if (redisHealthy && redisClient) {
                                    const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                                    try {
                                        await rateLimitFailedRecaptcha(clientIP);
                                    } catch (rateError) {
                                        console.warn(`reCAPTCHA rate limit hit for IP ${clientIP}:`, rateError.message);
                                        socket.emit('answerError', rateError.message);
                                        return;
                                    }
                                }
                                socket.emit('answerError', error.message);
                                return;
                            }
                        } else if (process.env.ENABLE_RECAPTCHA === 'true') {
                            // DEVELOPMENT: Optional reCAPTCHA (for testing)
                            if (recaptchaToken) {
                                try {
                                    recaptchaResult = await verifyRecaptcha(recaptchaToken);
                                    console.log(`✅ Dev reCAPTCHA verified (score: ${recaptchaResult.score || 'N/A'})`);
                                    
                                    // Still check score in dev for testing
                                    if (recaptchaResult.score !== undefined && recaptchaResult.score < 0.5) {
                                        console.warn(`⚠️ Low score in dev: ${recaptchaResult.score} (allowing anyway)`);
                                    }
                                } catch (error) {
                                    console.warn(`⚠️ Dev reCAPTCHA failed (allowing anyway): ${error.message}`);
                                }
                            } else {
                                console.log(`🔓 Dev mode - no reCAPTCHA token provided`);
                            }
                        } else {
                            // DEVELOPMENT: reCAPTCHA disabled
                            console.log(`🔓 Dev mode - reCAPTCHA disabled for ${authenticatedUsername}`);
                        }

                        // ===== 7. DEVICE FINGERPRINT CHECK (RISK-BASED) =====
                        const user = await User.findOne({ walletAddress: authenticatedUsername });
                        if (user && socket.user && user.deviceFingerprint !== socket.user.fingerprint) {
                            console.warn(`Device fingerprint mismatch for ${authenticatedUsername} in submitAnswer`);
                            botDetector.trackEvent(authenticatedUsername, 'fingerprint_mismatch', { event: 'submitAnswer' });
                            
                            // In production, if reCAPTCHA score is also suspicious = likely bot attack
                            if (isProduction && recaptchaResult && recaptchaResult.score !== undefined && recaptchaResult.score < 0.7) {
                                console.error(`Device mismatch + low reCAPTCHA score (${recaptchaResult.score}) for ${authenticatedUsername}`);
                                socket.emit('answerError', 'Device verification failed. Please relogin.');
                                return;
                            }
                            
                            // In development or if score is high, just log and continue
                            console.log(`Allowing fingerprint mismatch (production: ${isProduction}, score: ${recaptchaResult?.score || 'N/A'})`);
                        }

                        // ===== 8. HIGH-WIN STREAK CHECK (USES STORED RESULT) =====
                        if (user && user.gamesPlayed > 5 && (user.wins / user.gamesPlayed) > 0.8) {
                            // FIXED: Use stored recaptchaResult instead of re-verifying
                            if (isProduction) {
                                // In production, reCAPTCHA already verified above
                                if (!recaptchaResult || !recaptchaResult.success) {
                                    console.error(`High-win player ${authenticatedUsername} failed verification`);
                                    socket.emit('answerError', 'Additional verification required due to high win rate.');
                                    return;
                                }
                                console.log(`High-win verification passed for ${authenticatedUsername} (score: ${recaptchaResult.score})`);
                            } else if (process.env.ENABLE_RECAPTCHA === 'true' && !recaptchaToken) {
                                // In dev with reCAPTCHA enabled, require token for high-win players
                                console.warn(`High-win player ${authenticatedUsername} in dev without reCAPTCHA`);
                                socket.emit('answerError', 'Verification required for high win rate players.');
                                return;
                            }
                        }

                        // ===== 9. PROCESS ANSWER =====
                        console.log(`SERVER CALCULATED: ${authenticatedUsername} response time: ${serverResponseTime}ms`);

                        const isCorrect = answer === currentQuestion.shuffledCorrectAnswer;
                        player.answered = true;
                        player.lastAnswer = answer;
                        player.lastResponseTime = serverResponseTime;
                        player.totalResponseTime = (player.totalResponseTime || 0) + serverResponseTime;

                        if (isCorrect) {
                            player.score = (player.score || 0) + 1;
                            console.log(`Correct answer from ${authenticatedUsername}. New score: ${player.score}`);
                            try {
                                await User.findOneAndUpdate(
                                    { walletAddress: authenticatedUsername },
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

                        // BotDetector integration
                        botDetector.trackEvent(authenticatedUsername, 'answer_submitted', {
                            responseTime: serverResponseTime,
                            isCorrect,
                            answer,
                            questionId,
                            recaptchaScore: recaptchaResult?.score
                        });

                        room.answersReceived += 1;
                        await updateGameRoom(roomId, room);

                        // ===== 10. EMIT RESULTS =====
                        socket.emit('answerResult', {
                            username: player.username,
                            isCorrect,
                            questionId,
                            selectedAnswer: answer
                        });

                        socket.to(roomId).emit('playerAnswered', {
                            username: authenticatedUsername,
                            isBot: false,
                            responseTime: serverResponseTime,
                            timedOut: false
                        });

                        // Emit score update to all players in the room
                        io.to(roomId).emit('scoreUpdate', room.players.map(p => ({
                            username: p.username,
                            score: p.score || 0,
                            totalResponseTime: p.totalResponseTime || 0,
                            isBot: p.isBot || false,
                            difficulty: p.isBot ? p.difficultyLevelString : undefined
                        })));

                        // Do not call completeQuestion here; wait for the timeout
                    } catch (error) {
                        console.error('Error in submitAnswer:', error.message);
                        socket.emit('answerError', `Error submitting answer: ${error.message}`);
                    }
                } 
            } catch (error) {
                console.error(`Error in ${event}:`, error);
                socket.emit(`${event}Error` || 'gameError', error.message);
            }
        });
    });

    socket.on('disconnect', async () => {
        console.log('Client disconnected:', socket.id);

        // 1. Check and remove from matchmaking pools in Redis (retained scan—fewer keys)
        if (socket.matchmakingPool && redisHealthy) {
            try {
                const removedPlayer = await removeFromMatchmakingPool(socket.matchmakingPool, socket.id);
                if (removedPlayer) {
                    console.log(`Player ${removedPlayer.walletAddress} (socket ${socket.id}) removed from matchmaking pool for bet ${socket.matchmakingPool} (O(1))`);
                }
                socket.matchmakingPool = null;  // ✅ Clear ref
                await logMatchmakingState();
            } catch (error) {
                console.error(`Error in O(1) matchmaking cleanup for socket ${socket.id}:`, error);
                // FALLBACK ALERT: Log if ref missing/unhealthy (no scan to avoid DoS)
                if (!redisHealthy || !socket.matchmakingPool) {
                    console.warn(`Fallback needed for disconnect ${socket.id} - ref missing/unhealthy. Investigate manually.`);
                    // TODO: Metric/alert (e.g., via Sentry) - do NOT scan here
                }
            }
        } else if (!redisHealthy) {
            console.warn('Skipping matchmaking cleanup due to Redis unhealthiness');
        }

        // 2. Handle disconnection from active game rooms (FIXED: Use socket.roomId—no scan!)
        try {
            if (socket.roomId) {
                const roomId = socket.roomId;
                let room = await getGameRoom(roomId);
                if (!room || room.isDeleted) {
                    socket.roomId = null;  // FIXED: Clear stale roomId
                    return;
                }

                const playerIndex = room.players.findIndex(p => p.id === socket.id);
                if (playerIndex !== -1) {
                    const disconnectedPlayer = room.players[playerIndex];
                    console.log(`Player ${disconnectedPlayer.username} (socket ${socket.id}) disconnected from room ${roomId}`);

                    // Clear question timeout
                    if (room.questionTimeout) {
                        clearTimeout(room.questionTimeout);
                        room.questionTimeout = null;
                    }

                    room.players.splice(playerIndex, 1);
                    room.playerLeft = true;
                    room.isDeleted = true; // Mark room as deleted
                    await updateGameRoom(roomId, room);

                    // Scenario 1: Bot Game Forfeit (Human disconnected)
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
                        } else {
                            console.error(`CRITICAL: Bot not found in bot game room ${roomId} after human ${disconnectedPlayer.username} disconnected.`);
                            io.to(roomId).emit('gameError', 'An error occurred due to player disconnection.');
                        }

                        // Ensure room is deleted
                        await deleteGameRoom(roomId);
                        await redisClient.del(`room:${roomId}`);
                        console.log(`Confirmed deletion of room ${roomId}`);
                        await logGameRoomsState();
                        socket.roomId = null;  // FIXED: Clear roomId
                        return;
                    }

                    // Scenario 2: Human vs Human Game Forfeit
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
                        await redisClient.del(`room:${roomId}`);
                        await logGameRoomsState();
                        socket.roomId = null;  // FIXED: Clear roomId
                        return;
                    }

                    // Scenario 3: Room becomes empty
                    if (room.players.length === 0) {
                        console.log(`Room ${roomId} is now empty after ${disconnectedPlayer.username} left. Deleting room.`);
                        await deleteGameRoom(roomId);
                        await redisClient.del(`room:${roomId}`);
                        await logGameRoomsState();
                        socket.roomId = null;  // FIXED: Clear roomId
                        return;
                    }

                    // If game hasn't started, notify remaining players
                    if (!room.gameStarted) {
                        io.to(roomId).emit('playerLeft', disconnectedPlayer.username);
                    }

                    socket.roomId = null;  // FIXED: Clear roomId
                }
            } else {
                console.log(`No room associated with disconnected socket ${socket.id}`);
            }
        } catch (error) {
            console.error(`Error cleaning up game rooms for socket ${socket.id}:`, error);
            socket.roomId = null;  // FIXED: Clear on error to avoid stale state
        }
    });
});

io.engine.on('connection_error', (err) => {
    console.warn('Socket.io connection error (non-fatal):', {
        req: err.req,     // Incoming request
        code: err.code,   // e.g., 1 = transport error
        message: err.message, // e.g., "Session ID unknown"
        context: err.context,
        transport: err.req ? err.req._query?.transport : 'unknown'
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
        console.log("reCAPTCHA config loaded:", { 
            enabled: window.recaptchaEnabled, 
            siteKey: window.recaptchaSiteKey,
            grecaptchaLoaded: !!window.grecaptcha,
            enterpriseLoaded: !!window.grecaptcha?.enterprise 
        });
        
        // Wait for grecaptcha to load and log
        if (window.grecaptcha) {
            window.grecaptcha.enterprise.ready(() => {
                console.log("reCAPTCHA Enterprise ready");
            }).catch(err => console.error("reCAPTCHA Enterprise ready error:", err));
        }
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

// NEW: API endpoint to check payment status
app.get('/api/payment/:paymentId', async (req, res) => {
    try {
        const payment = await PaymentQueue.findById(req.params.paymentId);
        if (!payment) {
            return res.status(404).json({ error: 'Payment not found' });
        }
        res.json({
            paymentId: payment._id,
            status: payment.status,
            amount: payment.amount,
            transactionSignature: payment.transactionSignature,
            errorMessage: payment.errorMessage
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});


async function startGame(roomId) {
    console.log(`Attempting to start game in room ${roomId}`);
    let room = await getGameRoom(roomId);
    if (!room) {
        console.log(`Room ${roomId} not found when trying to start game`);
        return;
    }

    // Idempotent: Skip if already started
    if (room.gameStarted) {
        console.log(`Game already started in room ${roomId}, skipping`);
        return;
    }

    room.players.forEach(player => (player.score = 0));
    await updateGameRoom(roomId, room);

    try {
        // Dynamic question rotation: exclude recent questions for human player
        let matchStage = [];
        const humanPlayer = room.players.find(p => !p.isBot);
        if (humanPlayer) {
            const user = await User.findOne({ walletAddress: humanPlayer.username });
            if (user && user.recentQuestions && user.recentQuestions.length > 0) {
                const recentIds = user.recentQuestions.map(id => new mongoose.Types.ObjectId(id));
                matchStage = [{ $match: { _id: { $nin: recentIds } } }];
            }
        }

        const rawQuestions = await Quiz.aggregate([...matchStage, { $sample: { size: 7 } }]);
        console.log(`Fetched ${rawQuestions.length} questions for room ${roomId}`);

        // FIXED: Pre-shuffle ALL questions here (no race in startNextQuestion)
        room.questions = rawQuestions.map((question, index) => {
            const tempId = `${roomId}-${uuidv4()}`;
            const options = question.options;
            const shuffledOptions = shuffleArray([...options]); // Shuffle copy
            const shuffledCorrectAnswer = shuffledOptions.indexOf(options[question.correctAnswer]);
            if (shuffledCorrectAnswer === -1) {
                console.error(`Failed to shuffle question ${tempId} correctly`);
                throw new Error('Question shuffle failed');
            }
            const questionData = {
                tempId,
                _id: question._id,  // For rotation tracking
                question: question.question,
                options: options,   // Original for reference
                correctAnswer: question.correctAnswer,  // Original index
                shuffledOptions,    // FIXED: Pre-compute
                shuffledCorrectAnswer  // FIXED: Pre-compute
            };
            room.questionIdMap.set(tempId, questionData);
            return questionData;
        });

        await updateGameRoom(roomId, room);  // Save with all shuffled data

        // ✅ DEBUG: Verify shuffle data persisted
        const verifyRoom = await getGameRoom(roomId);
        console.log('🔍 Shuffle verification:', {
            questionCount: verifyRoom.questions.length,
            firstQuestionHasShuffle: !!verifyRoom.questions[0]?.shuffledOptions,
            shuffledOptionsLength: verifyRoom.questions[0]?.shuffledOptions?.length,
            mapSize: verifyRoom.questionIdMap.size,
            mapHasShuffle: !!verifyRoom.questionIdMap.get(verifyRoom.questions[0]?.tempId)?.shuffledOptions
        });

        if (!verifyRoom.questions[0]?.shuffledOptions) {
            console.error('❌ CRITICAL: Shuffle data NOT persisted to Redis!');
            throw new Error('Redis shuffle data not persisted');
        }
        console.log('✅ Shuffle data verified in Redis');

        io.to(roomId).emit('gameStart', {
            players: room.players.map(p => ({
                username: p.username,
                score: p.score,
                isBot: p.isBot || false,
                difficulty: p.isBot ? p.difficultyLevelString : undefined  // Note: Use p.difficultyLevelString if set
            })),
            questionCount: room.questions.length
        });
        await startNextQuestion(roomId);
    } catch (error) {
        console.error('Error starting game:', error);
        io.to(roomId).emit('gameError', 'Failed to start the game. Please try again.');
    }
}

async function startSinglePlayerGame(roomId) {
    console.log('Starting single player game with bot for room:', roomId);
    let room = await getGameRoom(roomId);
    if (!room) {
        console.log('Room not found for bot creation');
        return;
    }

    if (room.roomMode !== 'bot') {
        console.log(`Room ${roomId} is no longer in bot mode, not adding bot`);
        return;
    }

    try {
        // Dynamic question rotation: exclude recent questions for human player
        let matchStage = [];
        let humanPlayer = room.players.find(p => !p.isBot);
        if (humanPlayer) {
            const user = await User.findOne({ walletAddress: humanPlayer.username });
            if (user && user.recentQuestions && user.recentQuestions.length > 0) {
                const recentIds = user.recentQuestions.map(id => new mongoose.Types.ObjectId(id));
                matchStage = [{ $match: { _id: { $nin: recentIds } } }];
            }
        }

        const rawQuestions = await Quiz.aggregate([...matchStage, { $sample: { size: 7 } }]);

        room.questions = rawQuestions.map((question, index) => {
            const tempId = `${roomId}-${uuidv4()}`;
            const options = question.options;
            const shuffledOptions = shuffleArray([...options]); // Shuffle copy
            const shuffledCorrectAnswer = shuffledOptions.indexOf(options[question.correctAnswer]);
            
            if (shuffledCorrectAnswer === -1) {
                console.error(`Failed to shuffle question ${tempId} correctly`);
                throw new Error('Question shuffle failed');
            }
            
            const questionData = {
                tempId,
                _id: question._id,
                question: question.question,
                options: options,   // Original for reference
                correctAnswer: question.correctAnswer,  // Original index
                shuffledOptions,    // ✅ Pre-computed
                shuffledCorrectAnswer  // ✅ Pre-computed
            };
            room.questionIdMap.set(tempId, questionData);
            return questionData;
        });

        const humanPlayers = room.players.filter(p => !p.isBot);

        if (humanPlayers.length !== 1) {
            console.log(`Room ${roomId} has ${humanPlayers.length} human players, expected exactly 1`);
            if (humanPlayers.length === 0) {
                await deleteGameRoom(roomId);
                await logGameRoomsState();
            } else {
                room.roomMode = 'multiplayer';
                room.gameStarted = true;
                await updateGameRoom(roomId, room);
                io.to(roomId).emit('gameStart', {
                    players: room.players,
                    questionCount: room.questions.length,
                    singlePlayerMode: false
                });
                await startNextQuestion(roomId);
            }
            return;
        }

        humanPlayer = humanPlayers[0];
        console.log('Human player:', humanPlayer.username);

        humanPlayer.score = 0;
        humanPlayer.totalResponseTime = 0;
        humanPlayer.answered = false;
        humanPlayer.lastAnswer = null;

        if (room.players.some(p => p.isBot)) {
            console.log(`Room ${roomId} already has a bot player`);
            if (!room.gameStarted) {
                room.gameStarted = true;
                await updateGameRoom(roomId, room);
                await startNextQuestion(roomId);
            }
            return;
        }

        const difficultyString = await determineBotDifficulty(humanPlayer.username);
        const botName = chooseBotName();
        console.log('Creating bot with name:', botName, 'and difficulty:', difficultyString);

        const bot = new TriviaBot(botName, difficultyString);
        console.log('Bot instance created:', {
            username: bot.username,
            difficulty: bot.difficultyLevelString,
            hasAnswerQuestion: typeof bot.answerQuestion === 'function'
        });

        room.players.push({
            username: bot.username,
            difficultyLevelString: bot.difficultyLevelString,
            isBot: true,
            score: bot.score,
            totalResponseTime: bot.totalResponseTime,
            currentQuestionIndex: bot.currentQuestionIndex,
            answersGiven: bot.answersGiven,
            answered: bot.answered,
            lastAnswer: bot.lastAnswer,
            lastResponseTime: bot.lastResponseTime
        });
        room.hasBot = true;
        console.log('Bot added to room. Total players:', room.players.length);

        await updateGameRoom(roomId, room);

        // ✅ DEBUG: Verify shuffle data persisted
        const verifyRoom = await getGameRoom(roomId);
        console.log('🔍 Shuffle verification:', {
            questionCount: verifyRoom.questions.length,
            firstQuestionHasShuffle: !!verifyRoom.questions[0]?.shuffledOptions,
            shuffledOptionsLength: verifyRoom.questions[0]?.shuffledOptions?.length,
            mapSize: verifyRoom.questionIdMap.size,
            mapHasShuffle: !!verifyRoom.questionIdMap.get(verifyRoom.questions[0]?.tempId)?.shuffledOptions
        });

        if (!verifyRoom.questions[0]?.shuffledOptions) {
            console.error('❌ CRITICAL: Shuffle data NOT persisted to Redis!');
            throw new Error('Redis shuffle data not persisted');
        }
        console.log('✅ Shuffle data verified in Redis');

        io.to(roomId).emit('botGameReady', {
            botName: bot.username,
            difficulty: bot.difficultyLevelString
        });

        io.to(roomId).emit('gameStart', {
            players: room.players.map(p => ({
                username: p.username,
                score: p.score,
                isBot: p.isBot || false,
                difficulty: p.isBot ? p.difficultyLevelString : undefined
            })),
            questionCount: room.questions.length,
            singlePlayerMode: true,
            botOpponent: bot.username
        });

        room.gameStarted = true;
        await updateGameRoom(roomId, room);
        await startNextQuestion(roomId);
        await logGameRoomsState();
    } catch (error) {
        console.error('Error starting single player game with bot:', error);
        io.to(roomId).emit('gameError', 'Failed to start the game. Please try again.');
        await deleteGameRoom(roomId);
    }
}

async function startNextQuestion(roomId) {
    let room = await getGameRoom(roomId);
    if (!room) {
        console.log(`Room ${roomId} not found when trying to start next question`);
        return;
    }

    // Check if room is deleted
    if (room.isDeleted) {
        console.log(`Room ${roomId} is marked as deleted, stopping game`);
        if (room.questionTimeout) {
            clearTimeout(room.questionTimeout);
            room.questionTimeout = null;
        }
        await redisClient.del(`room:${roomId}`); // Ensure deletion
        await logGameRoomsState();
        return;
    }

    // Check if there are any human players
    const humanPlayers = room.players.filter(p => !p.isBot);
    if (humanPlayers.length === 0) {
        console.log(`No human players in room ${roomId}. Stopping game.`);
        if (room.questionTimeout) {
            clearTimeout(room.questionTimeout);
            room.questionTimeout = null;
        }
        room.isDeleted = true;
        await updateGameRoom(roomId, room);
        await redisClient.del(`room:${roomId}`);
        await logGameRoomsState();
        return;
    }

    if (room.currentQuestionIndex >= room.questions.length) {
        console.log(`No more questions for room ${roomId}. Ending game.`);
        await handleGameOver(room, roomId);
        return;
    }

    const currentQuestion = room.questions[room.currentQuestionIndex];
    if (!currentQuestion || !currentQuestion.options || currentQuestion.correctAnswer === undefined) {
        console.error(`Invalid question data for room ${roomId}, question index ${room.currentQuestionIndex}`);
        io.to(roomId).emit('gameError', 'Invalid question data');
        room.isDeleted = true;
        await updateGameRoom(roomId, room);
        await redisClient.del(`room:${roomId}`);
        return;
    }

    room.questionStartTime = Date.now();
    room.answersReceived = 0;
    room.players.forEach(player => {
        player.answered = false;
        player.lastAnswer = null;
        player.lastResponseTime = null;
    });

    const shuffledOptions = currentQuestion.shuffledOptions;
    const shuffledCorrectAnswer = currentQuestion.shuffledCorrectAnswer;

    // ✅ Validation with recovery
    if (!shuffledOptions || !Array.isArray(shuffledOptions) || shuffledOptions.length === 0) {
        console.error(`❌ Missing shuffledOptions for question ${currentQuestion.tempId} in room ${roomId}`);
        console.error('Current question data:', JSON.stringify(currentQuestion, null, 2));
        
        // Try recovery from room.questions array
        const originalQ = room.questions.find(q => q.tempId === currentQuestion.tempId);
        if (originalQ && originalQ.shuffledOptions && originalQ.shuffledOptions.length > 0) {
            console.log('✅ Recovered shuffle data from room.questions array');
            currentQuestion.shuffledOptions = originalQ.shuffledOptions;
            currentQuestion.shuffledCorrectAnswer = originalQ.shuffledCorrectAnswer;
        } else {
            console.error('❌ CRITICAL: Cannot recover shuffle data. Aborting game.');
            io.to(roomId).emit('gameError', 'Critical: shuffle data lost. Please restart the game.');
            room.isDeleted = true;
            await updateGameRoom(roomId, room);
            await redisClient.del(`room:${roomId}`);
            return;
        }
    }

    if (shuffledCorrectAnswer === undefined || shuffledCorrectAnswer === -1) {
        console.error(`❌ Invalid shuffledCorrectAnswer for question ${currentQuestion.tempId}`);
        io.to(roomId).emit('gameError', 'Invalid question configuration');
        room.isDeleted = true;
        await updateGameRoom(roomId, room);
        await redisClient.del(`room:${roomId}`);
        return;
    }

    // ✅ Update map with verified shuffle data (idempotent)
    room.questionIdMap.set(currentQuestion.tempId, {
        ...currentQuestion,
        shuffledOptions,
        shuffledCorrectAnswer
    });

    await updateGameRoom(roomId, room);
    console.log(`Question ${room.currentQuestionIndex + 1} started at timestamp: ${room.questionStartTime} for room ${roomId}`);

    io.to(roomId).emit('clearQuestionUI');
    io.to(roomId).emit('nextQuestion', {
        questionId: currentQuestion.tempId,
        question: currentQuestion.question,
        options: shuffledOptions,
        questionNumber: room.currentQuestionIndex + 1,
        totalQuestions: room.questions.length
    });

    // Handle bot answer if applicable
    const botData = room.players.find(p => p.isBot);
    if (botData) {
        const bot = new TriviaBot(botData.username, botData.difficultyLevelString || 'MEDIUM');
        bot.score = botData.score || 0;
        bot.totalResponseTime = botData.totalResponseTime || 0;
        bot.currentQuestionIndex = botData.currentQuestionIndex || 0;
        bot.answersGiven = botData.answersGiven || [];

        try {
            const botAnswer = await bot.answerQuestion(
                currentQuestion.question,
                currentQuestion.shuffledOptions,
                shuffledCorrectAnswer
            );

            // Re-check room state before updating
            room = await getGameRoom(roomId);
            if (!room || room.isDeleted) {
                console.log(`Room ${roomId} deleted or not found during bot answer processing`);
                return;
            }

            const botIndex = room.players.findIndex(p => p.isBot);
            if (botIndex !== -1) {
                room.players[botIndex] = {
                    ...room.players[botIndex],
                    score: bot.score,
                    totalResponseTime: bot.totalResponseTime,
                    currentQuestionIndex: bot.currentQuestionIndex,
                    answersGiven: bot.answersGiven,
                    answered: true,
                    lastAnswer: botAnswer.answer,
                    lastResponseTime: botAnswer.responseTime
                };
                room.answersReceived += 1;
                await updateGameRoom(roomId, room);
            }

            console.log(`Bot ${bot.username} answered question ${currentQuestion.tempId}: ${botAnswer.answer} (correct: ${botAnswer.isCorrect}, time: ${botAnswer.responseTime}ms)`);
            io.to(roomId).emit('playerAnswered', {
                username: bot.username,
                isBot: true,
                responseTime: botAnswer.responseTime,
                timedOut: false
            });
        } catch (error) {
            console.error(`Error processing bot answer in room ${roomId}:`, error);
            io.to(roomId).emit('gameError', 'Error processing bot response. Game ended.');
            room.isDeleted = true;
            await updateGameRoom(roomId, room);
            await redisClient.del(`room:${roomId}`);
            return;
        }
    }

    room.questionTimeout = setTimeout(async () => {
        room = await getGameRoom(roomId);
        if (!room || room.isDeleted) {
            console.log(`Room ${roomId} not found or deleted during timeout`);
            return;
        }

        // Check again for human players
        const remainingHumanPlayers = room.players.filter(p => !p.isBot);
        if (remainingHumanPlayers.length === 0) {
            console.log(`No human players remaining in room ${roomId} during timeout. Stopping game.`);
            if (room.questionTimeout) {
                clearTimeout(room.questionTimeout);
                room.questionTimeout = null;
            }
            room.isDeleted = true;
            await updateGameRoom(roomId, room);
            await redisClient.del(`room:${roomId}`);
            await logGameRoomsState();
            return;
        }

        let timedOut = false;
        room.players.forEach(player => {
            if (!player.answered && !player.isBot) {
                player.answered = true;
                player.lastAnswer = -1;
                const timeoutResponseTime = Date.now() - room.questionStartTime;
                player.lastResponseTime = timeoutResponseTime;
                room.answersReceived += 1;
                timedOut = true;

                console.log(`Player ${player.username} timed out on question ${currentQuestion.tempId} with responseTime: ${timeoutResponseTime}ms`);
                io.to(roomId).emit('playerAnswered', {
                    username: player.username,
                    isBot: false,
                    timedOut: true,
                    responseTime: timeoutResponseTime
                });
            }
        });

        if (timedOut) {
            await updateGameRoom(roomId, room);
        }

        await completeQuestion(roomId);
    }, 10000);
}

function chooseBotName() {
    const botNames = [
        'BrainyBot', 'QuizMaster', 'Trivia Titan', 'FactFinder', 
        'QuestionQueen', 'KnowledgeKing', 'TriviaWhiz', 'WisdomBot',
        'FactBot', 'QuizGenius', 'BrainiacBot', 'TriviaLegend'
    ];
    return botNames[Math.floor(Math.random() * botNames.length)];
}

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
    let room = await getGameRoom(roomId);
    if (!room) {
        console.error(`Room ${roomId} not found in completeQuestion`);
        io.to(roomId).emit('gameError', 'Room not found');
        return;
    }

    // Check if room is deleted
    if (room.isDeleted) {
        console.log(`Room ${roomId} is marked as deleted, stopping game`);
        if (room.questionTimeout) {
            clearTimeout(room.questionTimeout);
            room.questionTimeout = null;
        }
        await redisClient.del(`room:${roomId}`);
        await logGameRoomsState();
        return;
    }

    // Check if there are any human players
    const humanPlayers = room.players.filter(p => !p.isBot);
    if (humanPlayers.length === 0) {
        console.log(`No human players in room ${roomId}. Stopping game.`);
        if (room.questionTimeout) {
            clearTimeout(room.questionTimeout);
            room.questionTimeout = null;
        }
        room.isDeleted = true;
        await updateGameRoom(roomId, room);
        await redisClient.del(`room:${roomId}`);
        await logGameRoomsState();
        return;
    }

    const currentQuestion = room.questions[room.currentQuestionIndex];
    if (!currentQuestion || !currentQuestion.shuffledOptions || currentQuestion.shuffledCorrectAnswer === undefined) {
        console.error(`Invalid question data for room ${roomId}, index ${room.currentQuestionIndex}`);
        io.to(roomId).emit('gameError', 'Invalid question data');
        room.isDeleted = true;
        await updateGameRoom(roomId, room);
        await redisClient.del(`room:${roomId}`);
        return;
    }

    io.to(roomId).emit('roundComplete', {
        questionId: currentQuestion.tempId,
        playerResults: room.players.map(p => ({
            username: p.username,
            isCorrect: p.lastAnswer === currentQuestion.shuffledCorrectAnswer,
            answer: p.lastAnswer || -1,
            responseTime: p.lastResponseTime || 0,
            isBot: p.isBot || false
        })),
        correctAnswerText: currentQuestion.shuffledOptions[currentQuestion.shuffledCorrectAnswer]
    });

    // Emit score update
    io.to(roomId).emit('scoreUpdate', room.players.map(p => ({
        username: p.username,
        score: p.score || 0,
        totalResponseTime: p.totalResponseTime || 0,
        isBot: p.isBot || false,
        difficulty: p.isBot ? p.difficultyLevelString : undefined
    })));

    room.questionStartTime = null;
    room.roundStartTime = null;
    room.players.forEach(player => {
        player.answered = false;
        player.lastResponseTime = null;
        player.lastAnswer = null;
    });
    room.currentQuestionIndex += 1;
    room.answersReceived = 0;

    await updateGameRoom(roomId, room);

    if (room.playerLeft) {
        console.log(`Game in room ${roomId} ending early because a player left`);
        await handleGameOver(room, roomId);
        return;
    }

    if (room.currentQuestionIndex < room.questions.length) {
        setTimeout(() => {
            startNextQuestion(roomId);
        }, 3000);
    } else {
        console.log(`Game over in room ${roomId}`);
        await handleGameOver(room, roomId);
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
                winner = (humanPlayer.totalResponseTime || 0) <= (botPlayer.totalResponseTime || 0)
                    ? humanPlayer.username
                    : botPlayer.username;
            }
        } else if (botPlayer && !humanPlayer) {
            winner = botPlayer.username;
        } else if (humanPlayer && !botPlayer) {
            winner = humanPlayer.username;
        }
    } else if (sortedPlayers.length === 1) {
        winner = sortedPlayers[0].username;
    } else if (sortedPlayers.length > 1 && !botOpponent) {
        winner = sortedPlayers[0].username;
    }

    try {
        const playersForStats = room.players.map(p => ({
            username: p.username,
            score: p.score || 0,
            totalResponseTime: p.totalResponseTime || 0,
            isBot: p.isBot || false
        }));

        await updatePlayerStats(playersForStats, {
            winner: winner,
            botOpponent: botOpponent,
            betAmount: room.betAmount
        });

        // Dynamic question rotation: update recent questions for human players
        for (const player of room.players.filter(p => !p.isBot)) {
            const user = await User.findOne({ walletAddress: player.username });
            if (user) {
                const usedIds = room.questions.map(q => q._id.toString());
                user.recentQuestions = [...new Set([...(user.recentQuestions || []), ...usedIds])].slice(-20);
                await user.save();
            }
        }

        const winnerIsActuallyHuman = winner && !room.players.find(p => p.username === winner && p.isBot);
        let payoutSignature = null;
        let paymentId = null;

        if (winnerIsActuallyHuman && paymentProcessor) {
            try {
                const multiplier = botOpponent ? 1.5 : 1.8;
                const winningAmount = room.betAmount * multiplier;
                // FIXED: Queue the payout instead of sending directly
                const queuedPayment = await paymentProcessor.queuePayment(
                    winner,
                    winningAmount,
                    roomId, // Use roomId as gameId
                    room.betAmount,
                    { botOpponent, singlePlayerMode: isSinglePlayerEncounter }
                );
                paymentId = queuedPayment._id.toString();
                console.log(`Payout queued for ${winner}: Payment ID ${paymentId}, Amount ${winningAmount} USDC`);
            } catch (error) {
                console.error('Error queueing payout:', error);
                // Emit error but continue (payout is queued or will be retried)
                io.to(roomId).emit('gameOver', {
                    error: 'Payout queued but initial setup failed. Check your balance or contact support.',
                    players: sortedPlayers.map(p => ({
                        username: p.username,
                        score: p.score,
                        totalResponseTime: p.totalResponseTime || 0,
                        isBot: p.isBot || false
                    })),
                    winner: winner,
                    betAmount: room.betAmount,
                    singlePlayerMode: isSinglePlayerEncounter,
                    botOpponent: botOpponent,
                    paymentId
                });
                await deleteGameRoom(roomId);
                return;
            }
        }

        io.to(roomId).emit('gameOver', {
            players: sortedPlayers.map(p => ({
                username: p.username,
                score: p.score,
                totalResponseTime: p.totalResponseTime || 0,
                isBot: p.isBot || false
            })),
            winner: winner,
            betAmount: room.betAmount,
            payoutSignature, // Will be null; use paymentId instead
            paymentId, // NEW: Include queued payment ID
            singlePlayerMode: isSinglePlayerEncounter,
            botOpponent: botOpponent,
            message: paymentId ? `Payout queued! Check status with ID: ${paymentId}` : 'No payout required'
        });

        await deleteGameRoom(roomId);
        await logGameRoomsState();
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


// FIXED: Enhanced verifyRecaptcha with strict enforcement and error throwing
async function verifyRecaptcha(token) {
    if (process.env.ENABLE_RECAPTCHA !== 'true') {
        console.log('reCAPTCHA verification skipped (disabled in config)');
        return { success: true, score: 1.0 };
    }
    if (!token) {
        console.error('reCAPTCHA token missing');
        throw new Error('reCAPTCHA token required');
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
        
        // FIXED: Strict enforcement - throw on failure
        if (!response.data.success) {
            console.warn('reCAPTCHA verification failed:', response.data['error-codes']);
            throw new Error('reCAPTCHA verification failed');
        }
        
        // FIXED: Enforce score threshold for v3
        if (response.data.score !== undefined && response.data.score < 0.5) {
            console.warn(`reCAPTCHA score too low: ${response.data.score}`);
            throw new Error('Bot activity suspected (low reCAPTCHA score)');
        }
        
        return { success: true, score: response.data.score };
    } catch (error) {
        console.error('reCAPTCHA verification error:', error);
        throw new Error('Verification service unavailable. Please try again later.');
    }
}

async function createGameRoom(roomId, betAmount, roomMode = null) {
    if (!redisHealthy) {
        throw new Error('Service temporarily unavailable');
    }
    const room = {
        players: [],
        betAmount,
        questions: [],
        questionIdMap: {},
        currentQuestionIndex: 0,
        answersReceived: 0,
        gameStarted: false,
        roomMode: roomMode,
        waitingTimeout: null,
        questionTimeout: null,
        playerLeft: false,
        hasBot: false,
        questionStartTime: null,
        roundStartTime: null,
        isDeleted: false
    };

    try {
        await redisClient.hset(`room:${roomId}`, {
            players: JSON.stringify(room.players),
            questions: JSON.stringify(room.questions),
            questionIdMap: JSON.stringify([]),  // ✅ Store as empty array, not {}
            betAmount: betAmount.toString(),
            currentQuestionIndex: room.currentQuestionIndex.toString(),
            answersReceived: room.answersReceived.toString(),
            gameStarted: room.gameStarted.toString(),
            roomMode: roomMode || '',
            hasBot: room.hasBot.toString(),
            playerLeft: room.playerLeft.toString(),
            questionStartTime: room.questionStartTime ? room.questionStartTime.toString() : '',
            roundStartTime: room.roundStartTime ? room.roundStartTime.toString() : '',
            isDeleted: room.isDeleted.toString()
        });
        await redisClient.expire(`room:${roomId}`, 3600);
        console.log(`Created room ${roomId} in Redis with bet amount ${betAmount}`);
    } catch (error) {
        console.error(`Error creating room ${roomId} in Redis:`, error);
        throw error;
    }
}

async function getGameRoom(roomId) {
    if (!redisHealthy) {
        throw new Error('Service temporarily unavailable');
    }
    try {
        const roomData = await redisClient.hgetall(`room:${roomId}`);
        if (!roomData || Object.keys(roomData).length === 0) {
            return null;
        }

        // ✅ FIXED: Properly deserialize questions
        const questions = JSON.parse(roomData.questions || '[]').map(q => ({
            ...q,
            _id: q._id ? new mongoose.Types.ObjectId(q._id) : null,
            shuffledOptions: q.shuffledOptions || [],
            shuffledCorrectAnswer: q.shuffledCorrectAnswer ?? -1
        }));

        // ✅ FIXED: Handle both empty array and legacy object format
        let questionIdMap = new Map();
        try {
            const mapData = JSON.parse(roomData.questionIdMap || '[]');
            
            // Check if it's an array (new format) or object (legacy format)
            if (Array.isArray(mapData)) {
                // New format: array of {key, value} objects
                questionIdMap = new Map(
                    mapData.map(item => [
                        item.key,
                        {
                            ...item.value,
                            _id: item.value._id ? new mongoose.Types.ObjectId(item.value._id) : null,
                            shuffledOptions: item.value.shuffledOptions || [],
                            shuffledCorrectAnswer: item.value.shuffledCorrectAnswer ?? -1
                        }
                    ])
                );
            } else if (typeof mapData === 'object' && mapData !== null) {
                // Legacy format: plain object (convert to Map)
                console.warn(`Room ${roomId} using legacy questionIdMap format - converting`);
                questionIdMap = new Map(
                    Object.entries(mapData).map(([key, val]) => [
                        key,
                        {
                            ...val,
                            _id: val._id ? new mongoose.Types.ObjectId(val._id) : null,
                            shuffledOptions: val.shuffledOptions || [],
                            shuffledCorrectAnswer: val.shuffledCorrectAnswer ?? -1
                        }
                    ])
                );
            }
        } catch (parseError) {
            console.error(`Error parsing questionIdMap for room ${roomId}:`, parseError);
            // Start with empty Map if parsing fails
            questionIdMap = new Map();
        }

        return {
            players: JSON.parse(roomData.players || '[]'),
            betAmount: parseFloat(roomData.betAmount) || 0,
            questions: questions,
            questionIdMap: questionIdMap,
            currentQuestionIndex: parseInt(roomData.currentQuestionIndex) || 0,
            answersReceived: parseInt(roomData.answersReceived) || 0,
            gameStarted: roomData.gameStarted === 'true',
            roomMode: roomData.roomMode || null,
            hasBot: roomData.hasBot === 'true',
            playerLeft: roomData.playerLeft === 'true',
            questionStartTime: roomData.questionStartTime ? parseInt(roomData.questionStartTime) : null,
            roundStartTime: roomData.roundStartTime ? parseInt(roomData.roundStartTime) : null,
            questionTimeout: null,
            waitingTimeout: null,
            isDeleted: roomData.isDeleted === 'true'
        };
    } catch (error) {
        console.error(`Error fetching room ${roomId} from Redis:`, error);
        redisHealthy = false;
        throw error;
    }
}

async function updateGameRoom(roomId, room) {
    if (!redisHealthy) {
        throw new Error('Service temporarily unavailable');
    }
    try {
        if (room.isDeleted) {
            console.log(`Room ${roomId} is marked as deleted, skipping update`);
            return;
        }

        // ✅ Serialize questions with explicit shuffle data
        const serializedQuestions = room.questions.map(q => ({
            tempId: q.tempId,
            _id: q._id ? q._id.toString() : null,
            question: q.question,
            options: q.options,
            correctAnswer: q.correctAnswer,
            shuffledOptions: q.shuffledOptions || [],
            shuffledCorrectAnswer: q.shuffledCorrectAnswer ?? -1
        }));

        // ✅ Serialize Map as array of {key, value} objects
        const serializedMap = Array.from(room.questionIdMap.entries()).map(([key, val]) => ({
            key: key,
            value: {
                tempId: val.tempId,
                _id: val._id ? val._id.toString() : null,
                question: val.question,
                options: val.options,
                correctAnswer: val.correctAnswer,
                shuffledOptions: val.shuffledOptions || [],
                shuffledCorrectAnswer: val.shuffledCorrectAnswer ?? -1
            }
        }));

        const roomData = {
            players: JSON.stringify(room.players),
            questions: JSON.stringify(serializedQuestions),
            questionIdMap: JSON.stringify(serializedMap),
            betAmount: room.betAmount.toString(),
            currentQuestionIndex: room.currentQuestionIndex.toString(),
            answersReceived: room.answersReceived.toString(),
            gameStarted: room.gameStarted.toString(),
            roomMode: room.roomMode || '',
            hasBot: room.hasBot.toString(),
            playerLeft: room.playerLeft.toString(),
            questionStartTime: room.questionStartTime ? room.questionStartTime.toString() : '',
            roundStartTime: room.roundStartTime ? room.roundStartTime.toString() : '',
            isDeleted: room.isDeleted.toString()
        };

        const multi = redisClient.multi();
        multi.hset(`room:${roomId}`, roomData);
        multi.expire(`room:${roomId}`, 3600);
        await multi.exec();
        console.log(`Updated room ${roomId} in Redis`);
    } catch (error) {
        console.error(`Error updating room ${roomId} in Redis:`, error);
        redisHealthy = false;
        throw error;
    }
}


async function deleteGameRoom(roomId) {
    if (!redisHealthy) {
        console.warn('Skipping room deletion due to Redis unhealthiness');
        return;
    }
    try {
        let room = await getGameRoom(roomId);
        if (room) {
            if (room.questionTimeout) {
                clearTimeout(room.questionTimeout);
                room.questionTimeout = null;
            }
            room.isDeleted = true;
            await updateGameRoom(roomId, room); // Mark as deleted
            
            // ✅ NEW: Clean up from waiting room index if present
            if (room.betAmount && room.roomMode === 'human') {
                await removeWaitingRoom(room.betAmount, roomId);
            }
        }

        const multi = redisClient.multi();
        multi.del(`room:${roomId}`);
        await multi.exec();
        console.log(`Deleted room ${roomId} from Redis via transaction`);
        const roomExists = await redisClient.exists(`room:${roomId}`);
        if (roomExists) {
            console.error(`Room ${roomId} still exists after deletion attempt`);
            await redisClient.del(`room:${roomId}`);
        }
    } catch (error) {
        console.error(`Error deleting room ${roomId} from Redis:`, error);
        redisHealthy = false;
        throw error;
    }
}

async function addToMatchmakingPool(betAmount, playerData) {
    if (!redisHealthy) {
        throw new Error('Service temporarily unavailable');
    }
    try {
        await redisClient.lpush(`matchmaking:human:${betAmount}`, JSON.stringify(playerData));
        console.log(`Added player ${playerData.walletAddress} to matchmaking pool for ${betAmount}`);
        return true;  // ✅ Return success for caller to verify
    } catch (error) {
        console.error(`Error adding to matchmaking pool for ${betAmount}:`, error);
        redisHealthy = false;
        throw error;  // ✅ Throw to propagate error
    }
}

async function removeFromMatchmakingPool(betAmount, socketId) {
    if (!redisHealthy) {
        console.warn('Skipping matchmaking removal due to Redis unhealthiness');
        return null;
    }
    try {
        const pool = await redisClient.lrange(`matchmaking:human:${betAmount}`, 0, -1) || [];
        if (!Array.isArray(pool)) {
            console.error(`Redis lrange returned non-array value for matchmaking:human:${betAmount}:`, pool);
            return null;
        }

        const playerIndex = pool.findIndex(p => {
            try {
                const player = JSON.parse(p);
                return player && player.socketId === socketId;
            } catch (parseError) {
                console.error(`Error parsing player data in pool for ${betAmount}:`, parseError, p);
                return false;
            }
        });

        if (playerIndex !== -1) {
            const removedPlayer = await redisClient.lrem(`matchmaking:human:${betAmount}`, 1, pool[playerIndex]);
            console.log(`Removed player with socketId ${socketId} from matchmaking pool for ${betAmount}`);
            try {
                return removedPlayer ? JSON.parse(pool[playerIndex]) : null;
            } catch (parseError) {
                console.error(`Error parsing removed player data for ${betAmount}:`, parseError, pool[playerIndex]);
                return null;
            }
        }

        console.log(`Player with socketId ${socketId} not found in matchmaking pool for ${betAmount}`);
        return null;
    } catch (error) {
        console.error(`Error removing from matchmaking pool for ${betAmount}:`, error);
        redisHealthy = false;
        return null; // Return null instead of throwing to allow switchToBot to continue
    }
}

async function getMatchmakingPool(betAmount) {
    if (!redisHealthy) {
        return [];
    }
    try {
        const pool = await redisClient.lrange(`matchmaking:human:${betAmount}`, 0, -1);
        return pool.map(p => JSON.parse(p));
    } catch (error) {
        console.error(`Error fetching matchmaking pool for ${betAmount}:`, error);
        redisHealthy = false;
        return [];
    }
}

// REMOVED: sendWinnings function - replaced by PaymentProcessor.queuePayment

async function findAssociatedTokenAddress(walletAddress, tokenMintAddress) {
    return await getAssociatedTokenAddress(
        tokenMintAddress,
        walletAddress,
        false,
        TOKEN_PROGRAM_ID,
        ASSOCIATED_TOKEN_PROGRAM_ID
    );
}

app.get('/api/tokens.json', async (req, res) => {
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.warn(`Potential bot detected accessing honeypot: ${clientIP}`);
    if (redisHealthy && redisClient) {
        await redisClient.set(`blocklist:${clientIP}`, 1, 'EX', 86400); // Block for 24 hours
    }
    
    // Return fake data
    res.json({ status: "success", data: { tokens: [] } });
});

app.get('/api/leaderboard', async (req, res) => {
    try {
        const leaderboard = await User.find({})
            .select('walletAddress gamesPlayed totalWinnings wins correctAnswers')
            .sort({ totalWinnings: -1 })
            .limit(20)
            .lean();
        
        // Transform data
        const transformedLeaderboard = leaderboard.map(user => ({
            username: user.walletAddress,
            correctAnswers: user.correctAnswers || 0,
            gamesPlayed: user.gamesPlayed || 0,
            totalPoints: user.correctAnswers || 0,
            wins: user.wins || 0,
            totalWinnings: user.totalWinnings || 0
        }));
        
        res.json(transformedLeaderboard);
    } catch (error) {
        console.error('Error fetching leaderboard:', error);
        res.status(500).json({ error: 'Failed to fetch leaderboard' });
    }
});

app.get('/admin', (req, res) => {
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.warn(`Potential bot detected accessing admin honeypot: ${clientIP}`);
    if (redisHealthy && redisClient) {
        redisClient.set(`blocklist:${clientIP}`, 1, 'EX', 86400);
    }
    
    // Redirect to home
    res.redirect('/');
});

async function handlePlayerLeftWin(roomId, remainingPlayer, disconnectedPlayer, betAmount, botOpponent, allPlayers) {
    try {
        // Calculate winnings using the appropriate multiplier
        const multiplier = botOpponent ? 1.5 : 1.8;
        const winningAmount = betAmount * multiplier;

        // FIXED: Queue payout instead of sending directly
        let payoutSignature = null;
        let paymentId = null;
        if (!botOpponent && paymentProcessor) {
            const queuedPayment = await paymentProcessor.queuePayment(
                remainingPlayer.username,
                winningAmount,
                roomId,
                betAmount,
                { botOpponent, forfeit: true }
            );
            paymentId = queuedPayment._id.toString();
            console.log(`Forfeit payout queued for ${remainingPlayer.username}: Payment ID ${paymentId}`);
        }

        // Emit game over event with forfeit information
        io.to(roomId).emit('gameOverForfeit', {
            winner: remainingPlayer.username,
            disconnectedPlayer: disconnectedPlayer.username,
            betAmount: betAmount,
            payoutSignature,
            paymentId, // NEW: Include queued payment ID
            botOpponent,
            message: `${disconnectedPlayer.username} left the game. ${remainingPlayer.username} wins by forfeit!${paymentId ? ` Payout queued (ID: ${paymentId})` : ''}`
        });

        // Update stats for all players
        await updatePlayerStats(allPlayers, {
            winner: remainingPlayer.username,
            botOpponent: botOpponent,
            betAmount: betAmount
        });

        // Clean up the room
        await deleteGameRoom(roomId);
        await logGameRoomsState();
    } catch (error) {
        console.error('Error processing player left win:', error);
        io.to(roomId).emit('gameError', 'Error processing win after player left. Please contact support.');
        await deleteGameRoom(roomId);
        await logGameRoomsState();
    }
}

async function logGameRoomsState() {
    if (!redisHealthy) {
        console.warn('Skipping room state log due to Redis unhealthiness');
        return;
    }
    console.log('Current game rooms state:');
    const roomKeys = await scanKeys('room:*');
    console.log(`Total rooms: ${roomKeys.length}`);

    for (const key of roomKeys) {
        const roomId = key.replace('room:', '');
        const room = await getGameRoom(roomId);
        if (room) {
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
}

async function logMatchmakingState() {
    if (!redisHealthy) {
        console.warn('Skipping matchmaking state log due to Redis unhealthiness');
        return;
    }
    console.log('Current Matchmaking State:');

    try {
        console.log('Human Matchmaking Pools:');
        const poolKeys = await scanKeys('matchmaking:human:*');
        for (const key of poolKeys) {
            const betAmount = key.replace('matchmaking:human:', '');
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
    } catch (error) {
        console.error('Error logging matchmaking state:', error);
    }
}

setInterval(async () => {
    if (!redisHealthy) {
        return;
    }
    const now = Date.now();
    const MAX_WAIT_TIME = 5 * 60 * 1000; // 5 minutes

    const poolKeys = await scanKeys('matchmaking:human:*');
    for (const key of poolKeys) {
        const betAmount = key.replace('matchmaking:human:', '');
        const pool = await getMatchmakingPool(betAmount);
        const expiredPlayers = pool.filter(player => (now - player.joinTime) > MAX_WAIT_TIME);

        if (expiredPlayers.length > 0) {
            console.log(`Removing ${expiredPlayers.length} expired players from matchmaking pool for ${betAmount}`);
            for (const player of expiredPlayers) {
                const playerSocket = io.sockets.sockets.get(player.socketId);
                if (playerSocket) {
                    playerSocket.emit('matchmakingExpired', {
                        message: 'Your matchmaking request has expired'
                    });
                }
                await redisClient.lrem(`matchmaking:human:${betAmount}`, 1, JSON.stringify(player));
            }
        }
    }
}, 60000);

async function updatePlayerStats(players, roomData) {
    console.log('Updating stats for all players:', players);
    const winner = roomData.winner;
    const multiplier = roomData.botOpponent ? 1.5 : 1.8;
    const winningAmount = roomData.betAmount * multiplier;
    
    console.log(`Game stats: winner=${winner}, betAmount=${roomData.betAmount}, winnings=${winningAmount}`);
    
    // ✅ Check if MongoDB supports transactions (replica set or Atlas)
    const supportsTransactions = mongoose.connection.client.topology?.description?.type !== 'Single';
    
    if (supportsTransactions) {
        // PRODUCTION: Use transactions for ACID guarantees
        console.log('Using MongoDB transactions for player stats');
        const session = await mongoose.startSession();
        session.startTransaction();
        
        try {
            for (const player of players) {
                if (player.isBot) {
                    console.log(`Skipping bot: ${player.username}`);
                    continue;
                }
                
                if (!player.username) {
                    console.log(`Skipping player with no username`);
                    continue;
                }
                
                const isWinner = player.username === winner;
                console.log(`Updating ${player.username} (winner: ${isWinner})`);
                
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
                
                const result = await User.findOneAndUpdate(
                    { walletAddress: player.username },
                    updateObj,
                    { 
                        upsert: true, 
                        new: true,
                        session  // Include session for transaction
                    }
                );
                
                console.log(`Updated ${player.username}:`, {
                    gamesPlayed: result.gamesPlayed,
                    wins: result.wins,
                    totalWinnings: result.totalWinnings
                });
            }
            
            await session.commitTransaction();
            console.log('All player stats committed successfully (transaction)');
        } catch (error) {
            await session.abortTransaction();
            console.error('Player stats transaction failed (rolled back):', error);
            throw error;
        } finally {
            session.endSession();
        }
    } else {
        // DEVELOPMENT: Use atomic operations without transactions
        console.log('⚠️ Using atomic updates (no transactions - standalone MongoDB)');
        
        try {
            for (const player of players) {
                if (player.isBot) {
                    console.log(`Skipping bot: ${player.username}`);
                    continue;
                }
                
                if (!player.username) {
                    console.log(`Skipping player with no username`);
                    continue;
                }
                
                const isWinner = player.username === winner;
                console.log(`Updating ${player.username} (winner: ${isWinner})`);
                
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
                
                // ✅ Atomic $inc operations (safe without transactions for single-doc updates)
                const result = await User.findOneAndUpdate(
                    { walletAddress: player.username },
                    updateObj,
                    { 
                        upsert: true, 
                        new: true
                        // No session - atomic at field level
                    }
                );
                
                console.log(`Updated ${player.username}:`, {
                    gamesPlayed: result.gamesPlayed,
                    wins: result.wins,
                    totalWinnings: result.totalWinnings
                });
            }
            
            console.log('All player stats updated successfully (atomic)');
        } catch (error) {
            console.error('Error in updatePlayerStats (atomic mode):', error);
            throw error;
        }
    }
}