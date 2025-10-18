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

// NEW: TransactionLog model for permanent audit
const TransactionLog = mongoose.model('TransactionLog', new mongoose.Schema({
    signature: { type: String, required: true, unique: true },
    walletAddress: String,
    betAmount: Number,
    verifiedAt: { type: Date, default: Date.now },
    status: { type: String, enum: ['verified', 'replayed', 'failed'] }
}));

// NEW: In-memory fallback cache for signatures (limited to prevent memory bloat)
const replayCache = new Set();  // Simple Set for quick lookup
const MAX_CACHE_SIZE = 10000;  // Limit to recent txs

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
    username: solanaPublicKey,  // FIXED: Use custom validator (username is wallet address)
    recaptchaToken: Joi.string().allow(null, '').optional()  // Allow null/empty
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
    betAmount: Joi.number().positive().integer().min(3).max(30).required(),  // FIXED: Tightened to game options
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

// LOOKT AT THIS FUNCTION AGAIN WHEN THE GAME IS LIVE!!!
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
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
    connection: new Connection(process.env.SOLANA_RPC_URL, 'confirmed')
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
            // NEW: Alert on error (in prod, integrate with monitoring)
            console.warn('Redis error - falling back to in-memory cache for replay protection');
        });
        // Test Redis connection with ping
        await redisClient.ping();  // Simple health check
        await redisClient.set('test', '1', 'EX', 60);
        const testValue = await redisClient.get('test');
        console.log(`Redis test: ${testValue}`);
        await initializeRateLimiter(); // Init after Redis
    } catch (error) {
        console.error('Failed to initialize Redis:', error);
        console.warn('Using in-memory fallback for all Redis ops');
        // Don't exit; continue with fallback
    }
}

initializeRedis().catch((err) => {
    console.error('Redis init failed, but continuing with fallback:', err);
    // Removed process.exit(1) - now graceful
});

// Socket.io Redis Adapter for scaling (pub/sub across processes)
let pubClient, subClient;
async function initializeSocketAdapter() {
    pubClient = redisClient.duplicate();
    subClient = redisClient.duplicate();
    io.adapter(createAdapter(pubClient, subClient));
    console.log('Socket.io Redis adapter initialized for scaling');
}

initializeSocketAdapter().catch(console.error);

// SCAN-based helper: Replace KEYS for non-blocking iteration
async function scanKeys(pattern, batchSize = 100) {
    let cursor = '0';
    let keys = [];
    do {
        const result = await redisClient.scan(cursor, 'MATCH', pattern, 'COUNT', batchSize);
        cursor = result[0];
        keys = keys.concat(result[1]);
    } while (cursor !== '0');
    return keys;
}

async function verifyAndValidateTransaction(signature, expectedAmount, senderAddress, recipientAddress, nonce, maxRetries = 3, retryDelay = 500) {  // NEW: Add nonce param
    console.log(`Verifying transaction ${signature} for ${expectedAmount} USDC from ${senderAddress} to ${recipientAddress}, nonce: ${nonce}`);

    const key = `tx:${signature}`;

    // NEW: Fallback-aware replay check
    let exists = false;
    try {
        exists = await redisClient.get(key);
        if (exists) {
            console.log(`Redis replay detected for ${key}`);
        }
    } catch (redisErr) {
        console.warn('Redis get failed, checking in-memory cache:', redisErr.message);
        exists = replayCache.has(signature);
    }
    
    if (exists) {
        console.error(`Transaction ${signature} already used`);
        throw new Error('This transaction has already been used');
    }

    // NEW: Nonce check (store in Redis/DB; fallback to memory)
    const nonceKey = `nonce:${nonce}`;
    try {
        const storedNonce = await redisClient.get(nonceKey);
        if (storedNonce) {
            throw new Error('Nonce already used - replay attempt');
        }
        await redisClient.set(nonceKey, 'used', 'EX', 86400);
    } catch (redisErr) {
        console.warn('Redis nonce check failed, using in-memory');
        if (replayCache.has(`nonce:${nonce}`)) {
            throw new Error('Nonce already used - replay attempt');
        }
        replayCache.add(`nonce:${nonce}`);
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

    // NEW: Store with extended TTL (7 days)
    const ttl = 604800;  // 7 days
    try {
        await redisClient.set(key, 1, 'EX', ttl);
        console.log(`Stored transaction signature ${signature} in Redis with ${ttl}s TTL`);
    } catch (redisErr) {
        console.warn('Redis set failed, added to in-memory cache:', redisErr.message);
        replayCache.add(signature);
        if (replayCache.size > MAX_CACHE_SIZE) {
            // Evict oldest (simple pop, but for demo; use LRU in prod)
            const firstItem = Array.from(replayCache)[0];
            replayCache.delete(firstItem);
        }
    }

    // NEW: Log to MongoDB for permanent audit
    try {
        await TransactionLog.create({
            signature,
            walletAddress: senderAddress,
            betAmount: expectedAmount,
            status: 'verified'
        });
        console.log(`Transaction ${signature} logged to MongoDB audit`);
    } catch (dbErr) {
        console.error('Failed to log transaction to DB:', dbErr);
        // Continue even if audit fails
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
    const key = `rate:${walletAddress}:${eventName}`;
    const count = await redisClient.get(key) || 0;
    if (count >= maxRequests) {
        throw new Error(`Too many ${eventName} requests`);
    }
    await redisClient.set(key, parseInt(count) + 1, 'EX', windowSeconds);
}

// FIXED: Add Redis rate limiter for failed reCAPTCHA (max 5 per IP per hour)
async function rateLimitFailedRecaptcha(ip) {
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

// io.use(authMiddleware);

io.on('connection', (socket) => {
    console.log('New client connected:', socket.id);
    
    const connectionData = {
        ip: socket.handshake.headers['x-forwarded-for'] || socket.handshake.address,
        userAgent: socket.handshake.headers['user-agent'],
        timestamp: new Date(),
        sessionId: socket.id
    };
    
    botDetector.trackConnection(connectionData.ip, connectionData.userAgent, socket.id);
    
    if (redisClient) {
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
            const isWalletBlocked = await redisClient.get(`blocklist:wallet:${walletAddress}`);
            if (isWalletBlocked) {
                console.warn(`Blocked wallet attempting to login: ${walletAddress}`);
                socket.emit('loginFailure', 'This wallet is temporarily blocked.');
                return;
            }
            console.log('Wallet login attempt:', { walletAddress, recaptchaToken: !!recaptchaToken });
            
            // FIXED: Rate limit login attempts (existing) + failed reCAPTCHA specifically
            if (redisClient) {
                const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                const loginLimitKey = `login:${clientIP}`;
                const loginAttempts = await redisClient.get(loginLimitKey) || 0;
                
                if (loginAttempts > 100) {
                    console.warn(`Rate limit exceeded for IP ${clientIP}`);
                    return socket.emit('loginFailure', 'Too many login attempts. Please try again later.');
                }
                await redisClient.set(loginLimitKey, parseInt(loginAttempts) + 1, 'EX', 3600);
                
                // FIXED: New - rate limit failed reCAPTCHA attempts
                try {
                    await rateLimitFailedRecaptcha(clientIP);
                } catch (rateError) {
                    console.warn(`reCAPTCHA rate limit hit for IP ${clientIP}:`, rateError.message);
                    return socket.emit('loginFailure', rateError.message);
                }
            }
            
            // FIXED: Enforce reCAPTCHA - throw if fails (no fallback success)
            let recaptchaResult;
            try {
                recaptchaResult = await verifyRecaptcha(recaptchaToken);
            } catch (error) {
                // FIXED: Log failure for rate limiting, then emit error
                if (redisClient) {
                    const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                    await rateLimitFailedRecaptcha(clientIP); // Increment on failure
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

    // Apply rate-limit + auth to game events
    const gameEvents = ['joinGame', 'playerReady', 'joinHumanMatchmaking', 'joinBotGame', 'switchToBot', 'matchFound', 'leaveRoom', 'requestBotRoom', 'requestBotGame', 'submitAnswer', 'getLeaderboard'];
    gameEvents.forEach(event => {
        socket.on(event, async (...args) => {
            try {
                // await rateLimitSocket(socket);

                if (event !== 'getLeaderboard') {
                    if (!socket.user) throw new Error('Unauthorized');
                }
                    
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
                    console.log(`Player ${walletAddress} joined temporary room ${roomId}`);
                    socket.emit('gameJoined', roomId);

                    await logGameRoomsState();
                } else if (event === 'playerReady') {
                    const { roomId, preferredMode, recaptchaToken } = args[0];
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

                            const roomKeys = await scanKeys('room:*');
                            for (const key of roomKeys) {
                                const otherRoomId = key.replace('room:', '');
                                if (otherRoomId === roomId) continue;

                                const otherRoom = await getGameRoom(otherRoomId);
                                if (
                                    otherRoom &&
                                    otherRoom.roomMode === 'human' &&
                                    !otherRoom.gameStarted &&
                                    otherRoom.betAmount === room.betAmount &&
                                    otherRoom.players.length === 1
                                ) {
                                    console.log(`Found matching room ${otherRoomId} for player in room ${roomId}`);
                                    const player = room.players[0];
                                    otherRoom.players.push(player);
                                    await updateGameRoom(otherRoomId, otherRoom);

                                    socket.leave(roomId);
                                    socket.join(otherRoomId);

                                    socket.emit('matchFound', { newRoomId: otherRoomId });
                                    io.to(otherRoomId).emit('playerJoined', player.username);

                                    otherRoom.gameStarted = true;
                                    await updateGameRoom(otherRoomId, otherRoom);
                                    await startGame(otherRoomId);

                                    await deleteGameRoom(roomId);
                                    matchFound = true;
                                    break;
                                }
                            }

                            if (!matchFound) {
                                console.log(`No match found for player in room ${roomId}, waiting for others`);
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
                        socket.emit('joinGameFailure', error.message);  // Use error message directly
                        return;
                    }
                    // FIXED: Increment failed attempts
                    if (redisClient) {
                        const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                        await rateLimitFailedRecaptcha(clientIP);
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

                    // FIXED: Use scanKeys instead of keys
                    const roomKeys = await scanKeys('room:*');
                    for (const key of roomKeys) {
                        const roomId = key.replace('room:', '');
                        let room = await getGameRoom(roomId);
                        const playerIndex = room.players.findIndex(p => p.username === walletAddress);
                        if (playerIndex !== -1) {
                            room.players.splice(playerIndex, 1);
                            await updateGameRoom(roomId, room);
                            socket.leave(roomId);
                            console.log(`Player ${walletAddress} left room ${roomId} for matchmaking`);
                            if (room.players.length === 0) {
                                await deleteGameRoom(roomId);
                                console.log(`Deleted empty room ${roomId}`);
                            }
                            break;
                        }
                    }

                    const pool = await getMatchmakingPool(betAmount);
                    const existingPlayer = pool.find(p => p.walletAddress === walletAddress);
                    if (existingPlayer) {
                        console.log(`Player ${walletAddress} is already in matchmaking pool for ${betAmount}`);
                        socket.emit('matchmakingError', { message: 'You are already in matchmaking' });
                        return;
                    }

                    if (pool.length > 0) {
                        const opponent = pool.shift();
                        await redisClient.ltrim(`matchmaking:human:${betAmount}`, 1, -1);

                        const roomId = generateRoomId();
                        console.log(`Creating game room ${roomId} for matched players ${walletAddress} and ${opponent.walletAddress}`);

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
                } else if (event === 'joinBotGame') {
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
                        socket.emit('joinGameFailure', error.message);  // Use error message directly
                        return;
                    }
                    // FIXED: Increment failed attempts
                    if (redisClient) {
                        const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                        await rateLimitFailedRecaptcha(clientIP);
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

                    // Check existing rooms for this player
                    const roomKeys = await scanKeys('room:*');
                    for (const key of roomKeys) {
                        const roomId = key.replace('room:', '');
                        let room = await getGameRoom(roomId);
                        if (!room || room.isDeleted) continue;

                        const playerIndex = room.players.findIndex(p => p.username === walletAddress);
                        if (playerIndex !== -1) {
                            console.log(`Player ${walletAddress} already in room ${roomId}, cleaning up`);
                            room.players.splice(playerIndex, 1);
                            room.isDeleted = true;
                            await updateGameRoom(roomId, room);
                            socket.leave(roomId);
                            await redisClient.del(`room:${roomId}`);
                            console.log(`Deleted room ${roomId} due to new bot game request`);
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

                    // Check all matchmaking pools in Redis
                    const poolKeys = await scanKeys('matchmaking:human:*');
                    for (const key of poolKeys) {
                        const betAmount = key.replace('matchmaking:human:', '');
                        const parsedBetAmount = parseFloat(betAmount);
                        if (isNaN(parsedBetAmount)) {
                            console.warn(`Invalid bet amount in Redis key ${key}`);
                            continue;
                        }
                        const playerDataFromPool = await removeFromMatchmakingPool(betAmount, socket.id);
                        if (playerDataFromPool) {
                            playerData = playerDataFromPool;
                            playerBetAmount = parsedBetAmount;
                            playerFound = true;
                            console.log(`Removed player ${playerData.walletAddress} from matchmaking pool for ${playerBetAmount}`);
                            break;
                        }
                    }

                    // If player not found in matchmaking, check existing rooms
                    if (!playerFound) {
                        console.log(`Player ${socket.id} not found in matchmaking pools, checking existing rooms`);
                        const roomKeys = await scanKeys('room:*');
                        for (const key of roomKeys) {
                            const existingRoomId = key.replace('room:', '');
                            let room = await getGameRoom(existingRoomId);
                            if (!room) continue;

                            const playerIndex = room.players.findIndex(p => p.id === socket.id);
                            if (playerIndex !== -1) {
                                playerData = room.players[playerIndex];
                                playerBetAmount = room.betAmount;
                                playerFound = true;
                                console.log(`Found player ${playerData.username} in room ${existingRoomId} with bet ${playerBetAmount}`);
                                room.players.splice(playerIndex, 1);
                                socket.leave(existingRoomId);
                                if (room.players.length === 0) {
                                    await deleteGameRoom(existingRoomId);
                                    console.log(`Deleted empty room ${existingRoomId}`);
                                } else {
                                    await updateGameRoom(existingRoomId, room);
                                    io.to(existingRoomId).emit('playerLeft', playerData.username);
                                }
                                break;
                            }
                        }
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
                        currentRoomId = newRoomId;
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

                            if (room.players.length === 0) {
                                console.log(`Room ${roomId} is now empty, deleting it`);
                                await deleteGameRoom(roomId);
                            } else {
                                await updateGameRoom(roomId, room);
                                console.log(`Notifying remaining players in room ${roomId}`);
                                io.to(roomId).emit('playerLeft', player.username);
                            }
                        }

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
                    const { roomId, questionId, answer, username, recaptchaToken } = args[0];
                    try {
                        const { error } = submitAnswerSchema.validate({ roomId, questionId, answer, username, recaptchaToken });
                        if (error) {
                            console.error('Validation error in submitAnswer:', error.message);
                            socket.emit('answerError', `Invalid input: ${error.message}`);
                            return;
                        }

                        await rateLimitEvent(username, 'submitAnswer', 10, 60);

                        console.log(`Received answer from ${username} in room ${roomId} for question ${questionId}:`, { answer });

                        let room = await getGameRoom(roomId);
                        if (!room) {
                            console.error(`Room ${roomId} not found for answer submission`);
                            socket.emit('answerError', 'Room not found');
                            return;
                        }

                        if (!room.questionStartTime || room.currentQuestionIndex >= room.questions.length) {
                            console.error(`No active question in room ${roomId} when ${username} submitted answer`);
                            socket.emit('answerError', 'No active question');
                            return;
                        }

                        const currentQuestion = room.questionIdMap.get(questionId);
                        if (!currentQuestion || questionId !== room.questions[room.currentQuestionIndex].tempId) {
                            console.error(`Invalid question ${questionId} for room ${roomId}`);
                            socket.emit('answerError', 'Invalid question');
                            return;
                        }

                        const player = room.players.find(p => p.username === username && !p.isBot);
                        if (!player) {
                            console.error(`Player ${username} not found in room ${roomId} or is a bot`);
                            socket.emit('answerError', 'Player not found');
                            return;
                        }

                        if (player.answered) {
                            console.log(`Player ${username} already answered this question`);
                            socket.emit('answerError', 'Already answered');
                            return;
                        }

                        const serverResponseTime = Date.now() - room.questionStartTime;
                        if (serverResponseTime < 200 || serverResponseTime > 15000) {
                            console.warn(`Invalid response time ${serverResponseTime}ms from ${username} in room ${roomId}`);
                            await redisClient.set(`suspect:${username}`, 1, 'EX', 3600);
                            socket.emit('answerError', 'Invalid response timing');
                            return;
                        }

                        // Bot suspicion score
                        const botSuspicion = botDetector.getSuspicionScore(username);
                        console.log(`Bot suspicion for ${username}: ${botSuspicion}`);

                        // reCAPTCHA: Skip if null or low suspicion; otherwise verify
                        let skipCaptcha = !recaptchaToken || botSuspicion < 30;  // FIXED: Use recaptchaToken, not data
                        if (!skipCaptcha) {
                            const recaptchaResult = await verifyRecaptcha(recaptchaToken);  // FIXED: Use recaptchaToken
                            if (!recaptchaResult.success) {
                                socket.emit('answerError', 'Verification failed for answer submission.');
                                return;
                            }
                            console.log(`reCAPTCHA verified for ${username} (score: ${recaptchaResult.score || 'N/A'})`);
                        } else {
                            console.log(`Skipping reCAPTCHA for ${username} (suspicion: ${botSuspicion})`);
                        }

                        // Device fingerprint check (only if not skipping)
                        const user = await User.findOne({ walletAddress: username });
                        if (user && socket.user && user.deviceFingerprint !== socket.user.fingerprint && !skipCaptcha) {
                            console.warn(`Device fingerprint mismatch for ${username} in submitAnswer`);
                            botDetector.trackEvent(username, 'fingerprint_mismatch', { event: 'submitAnswer' });
                            // Re-verify if mismatch (even if low suspicion)
                            const recaptchaResult = await verifyRecaptcha(recaptchaToken);
                            if (!recaptchaResult.success) {
                                socket.emit('answerError', 'Device verification failed. Please relogin.');
                                return;
                            }
                        }

                        // High-win streak captcha check (always verify if condition met)
                        if (user && user.gamesPlayed > 5 && (user.wins / user.gamesPlayed) > 0.8) {
                            if (!recaptchaToken || !(await verifyRecaptcha(recaptchaToken)).success) {
                                socket.emit('answerError', 'Additional verification required due to high win rate.');
                                return;
                            }
                            console.log(`High-win verification passed for ${username}`);
                        }

                        console.log(`SERVER CALCULATED: ${username} response time: ${serverResponseTime}ms`);

                        const isCorrect = answer === currentQuestion.shuffledCorrectAnswer;
                        player.answered = true;
                        player.lastAnswer = answer;
                        player.lastResponseTime = serverResponseTime;
                        player.totalResponseTime = (player.totalResponseTime || 0) + serverResponseTime;

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
                        }

                        // BotDetector integration
                        botDetector.trackEvent(username, 'answer_submitted', {
                            responseTime: serverResponseTime,
                            isCorrect,
                            answer,
                            questionId
                        });

                        room.answersReceived += 1;
                        await updateGameRoom(roomId, room);

                        socket.emit('answerResult', {
                            username: player.username,
                            isCorrect,
                            questionId,
                            selectedAnswer: answer
                        });

                        socket.to(roomId).emit('playerAnswered', {
                            username,
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
                } else if (event === 'getLeaderboard') {
                    try {
                        // Apply rate-limiting
                        await rateLimitEvent(socket.user?.walletAddress || socket.id, 'getLeaderboard', 5, 60);

                        const leaderboard = await User.find({})
                            .select('walletAddress gamesPlayed totalWinnings wins correctAnswers')
                            .sort({ totalWinnings: -1 })
                            .limit(20);
                        
                        socket.emit('leaderboardData', leaderboard);
                    } catch (error) {
                        console.error('Error fetching leaderboard:', error);
                        socket.emit('leaderboardError', 'Failed to fetch leaderboard data');
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

        // 1. Check and remove from matchmaking pools in Redis
        try {
            const poolKeys = await scanKeys('matchmaking:human:*');
            for (const key of poolKeys) {
                const betAmount = key.replace('matchmaking:human:', '');
                const pool = await getMatchmakingPool(betAmount);
                const playerIndex = pool.findIndex(p => p.socketId === socket.id);
                if (playerIndex !== -1) {
                    const removedPlayer = await removeFromMatchmakingPool(betAmount, socket.id);
                    if (removedPlayer) {
                        console.log(`Player ${removedPlayer.walletAddress} (socket ${socket.id}) removed from matchmaking pool for bet ${betAmount}`);
                    }
                    await logMatchmakingState();
                }
            }
        } catch (error) {
            console.error(`Error cleaning up matchmaking pools for socket ${socket.id}:`, error);
        }

        // 2. Handle disconnection from active game rooms
        try {
            const roomKeys = await scanKeys('room:*');
            for (const key of roomKeys) {
                const roomId = key.replace('room:', '');
                let room = await getGameRoom(roomId);
                if (!room || room.isDeleted) continue;

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
                        return;
                    }

                    // Scenario 3: Room becomes empty
                    if (room.players.length === 0) {
                        console.log(`Room ${roomId} is now empty after ${disconnectedPlayer.username} left. Deleting room.`);
                        await deleteGameRoom(roomId);
                        await redisClient.del(`room:${roomId}`);
                        await logGameRoomsState();
                        return;
                    }

                    // If game hasn't started, notify remaining players
                    if (!room.gameStarted) {
                        io.to(roomId).emit('playerLeft', disconnectedPlayer.username);
                    }

                    break; // Player found and processed
                }
            }
        } catch (error) {
            console.error(`Error cleaning up game rooms for socket ${socket.id}:`, error);
        }
    });
});

io.engine.on('connection_error', (err) => {
    console.log('Server connection error:', {
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
            const questionData = {
                tempId,
                _id: question._id,  // Add for rotation tracking
                question: question.question,
                options: question.options,
                correctAnswer: question.correctAnswer
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

    const shuffledOptions = shuffleArray([...currentQuestion.options]);
    const shuffledCorrectAnswer = shuffledOptions.indexOf(currentQuestion.options[currentQuestion.correctAnswer]);
    if (shuffledCorrectAnswer === -1) {
        console.error(`Failed to find correct answer in shuffled options for room ${roomId}`);
        io.to(roomId).emit('gameError', 'Invalid question configuration');
        room.isDeleted = true;
        await updateGameRoom(roomId, room);
        await redisClient.del(`room:${roomId}`);
        return;
    }

    currentQuestion.shuffledOptions = shuffledOptions;
    currentQuestion.shuffledCorrectAnswer = shuffledCorrectAnswer;
    room.questionIdMap.set(currentQuestion.tempId, { ...currentQuestion });

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

        if (winnerIsActuallyHuman) {
            try {
                payoutSignature = await sendWinnings(winner, room.betAmount, botOpponent);
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
                    singlePlayerMode: isSinglePlayerEncounter,
                    botOpponent: botOpponent
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
            payoutSignature,
            singlePlayerMode: isSinglePlayerEncounter,
            botOpponent: botOpponent
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
        isDeleted: false // New flag
    };

    try {
        await redisClient.hset(`room:${roomId}`, {
            ...room,
            players: JSON.stringify(room.players),
            questions: JSON.stringify(room.questions),
            questionIdMap: JSON.stringify(room.questionIdMap),
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
    try {
        const roomData = await redisClient.hgetall(`room:${roomId}`);
        if (!roomData || Object.keys(roomData).length === 0) {
            return null;
        }

        return {
            players: JSON.parse(roomData.players || '[]'),
            betAmount: parseFloat(roomData.betAmount) || 0,
            questions: JSON.parse(roomData.questions || '[]'),
            questionIdMap: new Map(Object.entries(JSON.parse(roomData.questionIdMap || '{}'))),
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
            isDeleted: roomData.isDeleted === 'true' // Parse isDeleted
        };
    } catch (error) {
        console.error(`Error fetching room ${roomId} from Redis:`, error);
        return null;
    }
}

async function updateGameRoom(roomId, room) {
    try {
        // Check if room is marked as deleted
        if (room.isDeleted) {
            console.log(`Room ${roomId} is marked as deleted, skipping update`);
            return;
        }

        const roomData = {
            ...room,
            players: JSON.stringify(room.players),
            questions: JSON.stringify(room.questions),
            questionIdMap: JSON.stringify(Object.fromEntries(room.questionIdMap)),
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
        throw error;
    }
}


async function deleteGameRoom(roomId) {
    try {
        let room = await getGameRoom(roomId);
        if (room) {
            if (room.questionTimeout) {
                clearTimeout(room.questionTimeout);
                room.questionTimeout = null;
            }
            room.isDeleted = true;
            await updateGameRoom(roomId, room); // Mark as deleted
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
        throw error;
    }
}

async function addToMatchmakingPool(betAmount, playerData) {
    try {
        await redisClient.lpush(`matchmaking:human:${betAmount}`, JSON.stringify(playerData));
        console.log(`Added player ${playerData.walletAddress} to matchmaking pool for ${betAmount}`);
    } catch (error) {
        console.error(`Error adding to matchmaking pool for ${betAmount}:`, error);
        throw error;
    }
}

async function removeFromMatchmakingPool(betAmount, socketId) {
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
        return null; // Return null instead of throwing to allow switchToBot to continue
    }
}

async function getMatchmakingPool(betAmount) {
    try {
        const pool = await redisClient.lrange(`matchmaking:human:${betAmount}`, 0, -1);
        return pool.map(p => JSON.parse(p));
    } catch (error) {
        console.error(`Error fetching matchmaking pool for ${betAmount}:`, error);
        return [];
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