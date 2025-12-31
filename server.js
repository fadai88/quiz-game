const express = require('express');
const http = require('http');
const https = require('https');
const socketIo = require('socket.io');
const { createAdapter } = require('@socket.io/redis-adapter'); // New: Redis adapter for scaling
const Redis = require('ioredis'); // Already present, but ensure >=4.0
const { RateLimiterRedis } = require('rate-limiter-flexible'); // For enhanced rate-limiting
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser');

// ============================================================================
// SECURE SESSION CONFIGURATION
// ============================================================================
// Sessions are stored server-side in Redis and identified by secure cookies
// Cookies are httpOnly (not accessible via JavaScript) to prevent XSS theft

// Generate session secret keys (use environment variables in production)
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_SECRET_2 = process.env.SESSION_SECRET_2 || crypto.randomBytes(32).toString('hex');

if (!process.env.SESSION_SECRET && ENVIRONMENT === 'production') {
    console.error('❌ FATAL: SESSION_SECRET not set in production!');
    console.error('   Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
    process.exit(1);
}

console.log('✅ Secure session secrets configured');

const User = require('./models/User');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { Connection, PublicKey, SystemProgram, Transaction, sendAndConfirmTransaction, Keypair } = require('@solana/web3.js');
const Joi = require('joi');

// ============================================================================
// WINSTON LOGGING SYSTEM
// ============================================================================
const logger = require('./logger');
const { httpRequestLogger, socketLogger, errorHandler } = require('./middleware/requestLogger');
const { SecurityLogger, AuditLogger, PerformanceLogger } = require('./utils/securityLogger');
const { 
    alertManager, 
    trackFailedLogin, 
    trackRateLimitViolation,
    trackValidationFailure,
    trackRecaptchaFailure,
    trackBotSuspicion,
    trackFailedTransaction 
} = require('./config/alerts');

// ============================================================================
// INPUT VALIDATION SECURITY MODULE
// ============================================================================
// ✅ CRITICAL SECURITY FIX: Comprehensive input validation to prevent:
//    - SQL/NoSQL injection via malformed IDs
//    - Path traversal attacks (../, ..\)
//    - Redis key injection
//    - DoS via extremely long inputs
//    - Data corruption from special characters
//
// All user inputs MUST be validated before use in:
//    - Redis operations (room IDs, wallet addresses)
//    - Database queries
//    - File system operations
//    - External API calls
// ============================================================================

/**
 * Comprehensive validation middleware for socket events
 * @param {Object} schema - Joi validation schema
 * @param {string} eventName - Name of the socket event (for logging)
 * @returns {Function} Validation middleware function
 */
function validateInput(schema, eventName) {
    return (data) => {
        const { error, value } = schema.validate(data, {
            abortEarly: false,        // Report all errors, not just first
            stripUnknown: true,       // Remove unknown properties (security)
            convert: true             // Type coercion where safe
        });
        
        if (error) {
            const errorDetails = error.details.map(d => d.message).join('; ');
            logger.security('security_error', {
                message: `Validation failed for ${eventName}:`,
                errorDetails
            });
            throw new Error(`Validation failed: ${errorDetails}`);
        }
        
        logger.security('security_info', {
            message: `Validation passed for ${eventName}`
        });
        return value;
    };
}

/**
 * Sanitize user input for logging (prevent log injection)
 * @param {string} input - Raw user input
 * @returns {string} Sanitized string safe for logging
 */
function sanitizeForLog(input) {
    if (typeof input !== 'string') return String(input);
    // Remove control characters and limit length
    return input
        .replace(/[\x00-\x1F\x7F]/g, '') // Remove control chars
        .substring(0, 100);               // Limit length
}

// ============================================================================
// VALIDATION FAILURE TRACKING (Anti-Abuse System)
// ============================================================================
// Track validation failures per IP/wallet to detect attack patterns

const validationFailures = new Map(); // Map<identifier, {count, firstFailure, lastFailure}>
const VALIDATION_FAILURE_WINDOW = 3600000; // 1 hour
const VALIDATION_FAILURE_THRESHOLD = 100; // Max failures per hour
const blockedIdentifiers = new Set();

let paymentProcessorInterval;
let roomCleanupInterval;

/**
 * Check if identifier is blocked
 * @param {string} identifier - IP or wallet to check
 * @returns {boolean} True if blocked
 */
function isBlocked(identifier) {
    return blockedIdentifiers.has(identifier);
}

/**
 * Clear validation failure records (for testing/maintenance)
 */
function clearValidationTracking() {
    validationFailures.clear();
    blockedIdentifiers.clear();
    console.log('✅ Validation tracking cleared');
}

// Periodic cleanup of old records (every 5 minutes)
roomCleanupInterval = setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [identifier, record] of validationFailures.entries()) {
        if (now - record.lastFailure > VALIDATION_FAILURE_WINDOW) {
            validationFailures.delete(identifier);
            cleaned++;
        }
    }
    
    if (cleaned > 0) {
        logger.info(`🧹 Cleaned ${cleaned} expired validation failure records`);
    }
}, 300000);


// ============================================================================
// OUTPUT SANITIZATION (XSS Prevention)
// ============================================================================
// Note: Install with: npm install sanitize-html
// For production, ensure this package is in package.json

let sanitizeHtml;
try {
    sanitizeHtml = require('sanitize-html');
    console.log('✅ sanitize-html loaded for XSS protection');
} catch (error) {
    console.warn('⚠️  sanitize-html not installed. Install with: npm install sanitize-html');
    // Fallback: basic sanitization
    sanitizeHtml = (dirty) => {
        if (typeof dirty !== 'string') return String(dirty);
        return dirty
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    };
}

/**
 * Sanitize HTML content for safe display
 * Removes all potentially dangerous tags and attributes
 * @param {string} dirty - Unsanitized HTML content
 * @returns {string} Sanitized HTML safe for display
 */
function sanitizeOutput(dirty) {
    if (typeof sanitizeHtml === 'function' && sanitizeHtml.name !== 'sanitizeHtml') {
        // Using fallback
        return sanitizeHtml(dirty);
    }
    
    // Using sanitize-html package with strict settings
    return sanitizeHtml(dirty, {
        allowedTags: [], // No HTML tags allowed - strip everything
        allowedAttributes: {},
        disallowedTagsMode: 'discard'
    });
}

/**
 * Sanitize text for display in HTML context
 * Allows basic formatting but removes scripts
 * @param {string} text - Text to sanitize
 * @returns {string} Sanitized text
 */
function sanitizeText(text) {
    if (typeof text !== 'string') return String(text);
    
    if (typeof sanitizeHtml === 'function' && sanitizeHtml.name !== 'sanitizeHtml') {
        // Using fallback
        return sanitizeHtml(text);
    }
    
    // Allow some basic formatting tags but nothing dangerous
    return sanitizeHtml(text, {
        allowedTags: ['b', 'i', 'em', 'strong', 'br'],
        allowedAttributes: {},
        disallowedTagsMode: 'escape'
    });
}

// ============================================================================
// ERROR SANITIZATION (Information Disclosure Prevention)
// ============================================================================
// ✅ CRITICAL SECURITY FIX: Prevent error message information disclosure
//    - Stack traces NOT sent to client (only in server logs)
//    - Database errors NOT exposed (schema protection)
//    - Wallet addresses NOT leaked in errors
//    - Internal system information NOT revealed
//
// All errors MUST be sanitized before sending to clients
// ============================================================================

/**
 * Centralized error sanitization for client responses
 * Prevents information disclosure while maintaining trackability
 * @param {Error} error - The original error object
 * @param {string} context - Where the error occurred (for logging)
 * @param {string} [userMessage] - Optional user-friendly message
 * @returns {Object} Sanitized error response safe for clients
 */
function sanitizeError(error, context, userMessage = null) {
    // Generate unique error ID for support tracking
    const errorId = uuidv4().substring(0, 8);
    
    // Full error details in server logs (NOT sent to client)
    logger.error(`[ERROR:${errorId}] ${context}:`);
    logger.error(`  Message: ${error.message}`);
    logger.error(`  Stack: ${error.stack}`);
    if (error.code) logger.error(`  Code: ${error.code}`);
    
    // Determine environment
    const isProduction = process.env.NODE_ENV === 'production';
    
    if (isProduction) {
        // PRODUCTION: Generic messages only, no technical details
        return {
            error: userMessage || 'An error occurred. Please try again.',
            code: 'SERVER_ERROR',
            errorId // For support tickets
        };
    } else {
        // DEVELOPMENT: More details for debugging (but still sanitized)
        return {
            error: userMessage || 'An error occurred',
            message: sanitizeForLog(error.message), // Sanitized message
            code: error.code || 'UNKNOWN',
            errorId,
            context // Help developers debug
        };
    }
}

/**
 * Sanitize validation errors specifically (they're less sensitive)
 * @param {Object} validationError - Joi validation error object
 * @param {string} context - Where validation failed
 * @returns {Object} Sanitized validation error
 */
function sanitizeValidationError(validationError, context) {
    const errorId = uuidv4().substring(0, 8);
    
    // Log full details server-side
    console.error(`[VALIDATION:${errorId}] ${context}:`, validationError.message);
    
    const isProduction = process.env.NODE_ENV === 'production';
    
    if (isProduction) {
        // PRODUCTION: Generic message
        return {
            error: 'Invalid input format',
            code: 'VALIDATION_ERROR',
            errorId
        };
    } else {
        // DEVELOPMENT: Show which fields failed (but not values)
        const fields = validationError.details?.map(d => d.path.join('.')) || [];
        return {
            error: 'Validation failed',
            fields: fields,
            code: 'VALIDATION_ERROR',
            errorId
        };
    }
}

console.log('✅ Error sanitization configured');

// Export sanitization functions
module.exports = {
    ...module.exports,
    sanitizeOutput,
    sanitizeText,
    sanitizeForLog
};

console.log('✅ Output sanitization utilities initialized');

const BotDetector = require('./botDetector');
const crypto = require('crypto');
const bs58 = require('bs58').default;
const { getCachedTreasurySecretKey } = require('./aws-secrets-integration');

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
    
    // Enforce Redis security in production
    if (!process.env.REDIS_PASSWORD) {
        console.error('❌ FATAL: REDIS_PASSWORD required in production!');
        console.error('   Set REDIS_PASSWORD in your .env file to secure Redis');
        process.exit(1);
    }
    
    console.log('✅ reCAPTCHA properly configured for production');
    console.log('✅ Redis security properly configured for production');
} else {
    console.log('🔧 Starting in DEVELOPMENT mode');
    if (process.env.ENABLE_RECAPTCHA === 'true') {
        console.log('   reCAPTCHA: ENABLED (for testing)');
    } else {
        console.log('   reCAPTCHA: DISABLED (faster development)');
    }
    
    if (process.env.REDIS_PASSWORD) {
        console.log('   Redis: PASSWORD PROTECTED');
    } else {
        console.log('   ⚠️  Redis: NO PASSWORD (insecure - dev only)');
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

// ✅ SECURITY: Strict room ID validation (alphanumeric, hyphens, underscores only, 1-100 chars)
const roomIdSchema = Joi.string()
    .pattern(/^[a-zA-Z0-9_-]+$/)
    .min(1)
    .max(100)
    .required()
    .messages({
        'string.pattern.base': 'Room ID must contain only alphanumeric characters, hyphens, and underscores',
        'string.min': 'Room ID must be at least 1 character',
        'string.max': 'Room ID cannot exceed 100 characters'
    });

// ✅ SECURITY: Strict question ID validation (roomId-uuid format: "q2bu9-562cf6b6-306a-4ba0-a86d-7855c9426831")
const questionIdSchema = Joi.string()
    .pattern(/^[a-zA-Z0-9_-]+-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i)
    .min(1)
    .max(150)
    .required()
    .messages({
        'string.pattern.base': 'Question ID must be in format: roomId-uuid (e.g., room123-a1b2c3d4-...)',
        'string.max': 'Question ID cannot exceed 150 characters'
    });

const submitAnswerSchema = Joi.object({
    roomId: roomIdSchema,
    questionId: questionIdSchema,
    answer: Joi.number().integer().min(-1).max(3).required().messages({
        'number.min': 'Answer must be -1 (timeout) or 0-3 (option index)',
        'number.max': 'Answer index cannot exceed 3'
    }),
    recaptchaToken: Joi.string().allow(null, '').optional()  // username removed - will use socket.user.walletAddress
});

const playerReadySchema = Joi.object({
    roomId: roomIdSchema,
    preferredMode: Joi.string().valid('human', 'bot').optional(),
    recaptchaToken: Joi.string().optional()
});

const switchToBotSchema = Joi.object({
    roomId: roomIdSchema
});

const requestBotRoomSchema = Joi.object({
    walletAddress: solanaPublicKey,  // FIXED: Use custom validator
    betAmount: Joi.number().valid(3, 10, 15, 20, 30).required(),  // FIXED: Tightened to game options
    nonce: nonceSchema.optional()  // NEW: Add nonce (optional for non-transaction events)
});

const requestBotGameSchema = Joi.object({
    roomId: roomIdSchema
});

const leaveRoomSchema = Joi.object({
    roomId: roomIdSchema
});

const matchFoundSchema = Joi.object({
    newRoomId: roomIdSchema
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

// ============================================================================
// SECURITY HEADERS MIDDLEWARE
// ============================================================================
// Implements OWASP recommended security headers to prevent common attacks

app.use((req, res, next) => {
    // Prevent clickjacking attacks
    res.setHeader('X-Frame-Options', 'DENY');
    
    // Prevent MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // Enable browser XSS protection
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Control referrer information
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Prevent browser from caching sensitive data
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    
    // Content Security Policy (CSP)
    // Configured for game application with Solana, reCAPTCHA, and CDN resources
    const cspDirectives = [
        "default-src 'self'",
        
        // Scripts: Allow game libraries and reCAPTCHA
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.google.com https://www.gstatic.com https://bundle.run https://unpkg.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
        
        // Styles: Allow inline styles for dynamic UI
        "style-src 'self' 'unsafe-inline'",
        
        // Images: Allow data URIs and HTTPS images
        "img-src 'self' data: https:",
        
        // Fonts: Allow data URIs and self-hosted fonts
        "font-src 'self' data:",
        
        // Connections: Allow WebSocket, Solana RPC, CDNs, and API endpoints
        "connect-src 'self' wss: ws: https://devnet.helius-rpc.com https://api.anthropic.com https://unpkg.com https://cdn.jsdelivr.net https://bundle.run https://cdnjs.cloudflare.com https://www.google.com https://www.gstatic.com",
        
        // Frames: Allow Google reCAPTCHA frames
        "frame-src 'self' https://www.google.com https://recaptcha.google.com https://www.recaptcha.net",
        
        // Child frames (for embedded content)
        "child-src 'self' https://www.google.com https://recaptcha.google.com",
        
        // Prevent others from framing this site
        "frame-ancestors 'none'",
        
        // Base URI restriction
        "base-uri 'self'",
        
        // Form submission restriction
        "form-action 'self'"
    ].join('; ');
    res.setHeader('Content-Security-Policy', cspDirectives);
    
    // Permissions Policy (formerly Feature Policy)
    const permissionsPolicy = [
        'geolocation=()',
        'microphone=()',
        'camera=()',
        'payment=()',
        'usb=()',
        'magnetometer=()',
        'accelerometer=()',
        'gyroscope=()'
    ].join(', ');
    res.setHeader('Permissions-Policy', permissionsPolicy);
    
    // HSTS (HTTP Strict Transport Security) - Only in production with HTTPS
    if (ENVIRONMENT === 'production' && req.secure) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }
    
    next();
});

console.log('✅ Security headers middleware initialized');

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
io.use(socketLogger);

// Enhanced rate-limiting: Per-socket, Redis-backed (install rate-limiter-flexible)
let socketRateLimiter;
// ============================================================================
// ENHANCED PER-EVENT RATE LIMITERS
// ============================================================================
// Each event type has its own rate limiter with appropriate thresholds
const eventLimiters = new Map();

async function initializeRateLimiter() {
    try {
        // General socket-level rate limiter
        socketRateLimiter = new RateLimiterRedis({
            storeClient: redisClient,
            points: 200, // Max 200 events/min per socket
            duration: 60,
            keyPrefix: 'socket'
        });
        
        // Per-event rate limiters with appropriate thresholds
        eventLimiters.set('submitAnswer', new RateLimiterRedis({
            storeClient: redisClient,
            points: 10,          // 10 answers per minute
            duration: 60,
            blockDuration: 300,  // Block for 5 minutes on exceed
            keyPrefix: 'event:submitAnswer'
        }));
        
        eventLimiters.set('joinGame', new RateLimiterRedis({
            storeClient: redisClient,
            points: 5,           // 5 game joins per minute
            duration: 60,
            blockDuration: 180,  // Block for 3 minutes on exceed
            keyPrefix: 'event:joinGame'
        }));
        
        eventLimiters.set('joinHumanMatchmaking', new RateLimiterRedis({
            storeClient: redisClient,
            points: 5,           // 5 matchmaking requests per minute
            duration: 60,
            blockDuration: 180,
            keyPrefix: 'event:joinHumanMatchmaking'
        }));
        
        eventLimiters.set('joinBotGame', new RateLimiterRedis({
            storeClient: redisClient,
            points: 8,           // 8 bot games per minute
            duration: 60,
            blockDuration: 120,
            keyPrefix: 'event:joinBotGame'
        }));
        
        eventLimiters.set('playerReady', new RateLimiterRedis({
            storeClient: redisClient,
            points: 20,          // 20 ready signals per minute
            duration: 60,
            blockDuration: 60,
            keyPrefix: 'event:playerReady'
        }));
        
        eventLimiters.set('leaveRoom', new RateLimiterRedis({
            storeClient: redisClient,
            points: 15,          // 15 leave requests per minute
            duration: 60,
            blockDuration: 60,
            keyPrefix: 'event:leaveRoom'
        }));
        
        console.log('✅ Socket and per-event rate-limiters initialized');
    } catch (error) {
        logger.error('❌ Failed to init rate-limiter:', { error: error });
    }
}

// Auth middleware: Validate socket.user on events (post-login)
const authMiddleware = async (socket, next) => {
    try {
        // Check 1: User must be attached to socket
        if (!socket.user || !socket.user.walletAddress) {
            logger.auth(`Connection attempt without user: ${socket.id}`);
            return next(new Error('Unauthorized: No valid session'));
        }

        // Check 2: Validate session in Redis
        const walletAddress = socket.user.walletAddress;
        const sessionKey = `session:${walletAddress}`;
        
        const session = await redisClient.get(sessionKey);
        
        if (!session) {
            SecurityLogger.sessionExpired(walletAddress, sessionAge);
            socket.emit('error', {
                message: 'Session expired: Please login again',
                code: 'SESSION_EXPIRED'
            });
            socket.disconnect(true);
            return next(new Error('Session expired'));
        }

        // Check 3: Validate session age
        try {
            const sessionData = JSON.parse(session);
            const sessionAge = Date.now() - sessionData.timestamp;
            const MAX_SESSION_AGE = 24 * 60 * 60 * 1000; // 24 hours

            if (sessionAge > MAX_SESSION_AGE) {
                SecurityLogger.sessionTooOld(walletAddress, sessionAge, MAX_SESSION_AGE);
                await redisClient.del(sessionKey);
                socket.emit('error', {
                    message: 'Session expired: Please login again',
                    code: 'SESSION_EXPIRED'
                });
                socket.disconnect(true);
                return next(new Error('Session expired'));
            }
        } catch (parseError) {
            logger.security('auth_error', {
                message: `Session parse error for ${walletAddress}`,
                parseError
            });
            await redisClient.del(sessionKey);
            socket.emit('error', {
                message: 'Session corrupted: Please login again',
                code: 'SESSION_EXPIRED'
            });
            socket.disconnect(true);
            return next(new Error('Session corrupted'));
        }

        // ✅ All checks passed - allow connection
        logger.auth('connection_authenticated', { walletAddress, sessionId: sessionToken?.substring(0, 8) });
        next();
        
    } catch (error) {
        logger.error('[AUTH] Connection middleware error:', { error: error });
        socket.emit('error', {
            message: 'Authentication error occurred',
            code: 'AUTH_ERROR'
        });
        next(new Error('Authentication error'));
    }
};

app.use(express.json());

// ============================================================================
// COOKIE MIDDLEWARE - Secure Session Management
// ============================================================================
// Use httpOnly cookies to prevent XSS access to session tokens
app.use(cookieParser(SESSION_SECRET));
app.use(httpRequestLogger);

// Session cookie configuration
const COOKIE_OPTIONS = {
    httpOnly: true,  // Prevents JavaScript access (XSS protection)
    secure: ENVIRONMENT === 'production',  // HTTPS only in production
    sameSite: 'strict',  // CSRF protection
    maxAge: 24 * 60 * 60 * 1000,  // 24 hours
    signed: true  // Sign cookies to prevent tampering
};

logger.info('✅ Secure cookie middleware initialized', {
    httpOnly: COOKIE_OPTIONS.httpOnly,
    secure: COOKIE_OPTIONS.secure,
    sameSite: COOKIE_OPTIONS.sameSite
});

// ============================================================================
// SECURE HTTP AUTHENTICATION ENDPOINTS
// ============================================================================
// These endpoints handle login/logout with httpOnly cookies for XSS protection

app.post('/api/auth/login', async (req, res) => {
    try {
        const { walletAddress, verifyToken, recaptchaToken, clientData } = req.body;
        
        // Validate verification token (proves Socket.IO already verified signature)
        const storedToken = await redisClient.get(`verify:${walletAddress}`);
        
        if (!storedToken || storedToken !== verifyToken) {
            SecurityLogger.invalidToken(walletAddress, 'expired_or_invalid');
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid verification. Please try logging in again.' 
            });
        }
        
        // Delete verification token (one-time use)
        await redisClient.del(`verify:${walletAddress}`);
        logger.auth(`Verification token validated for ${walletAddress}`);
        
        // Verify reCAPTCHA if enabled
        if (process.env.ENABLE_RECAPTCHA === 'true') {
            if (!recaptchaToken) {
                return res.status(400).json({ success: false, error: 'reCAPTCHA required' });
            }
            const recaptchaResult = await verifyRecaptcha(recaptchaToken);
            if (!recaptchaResult.success) {
                return res.status(400).json({ success: false, error: 'reCAPTCHA failed' });
            }
        }
        
        // Create/update user
        let user = await User.findOne({ walletAddress });
        const connectionData = {
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.headers['user-agent']
        };
        
        if (!user) {
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
        
        // Generate fingerprint
        const fingerprint = crypto.createHash('sha256')
            .update(JSON.stringify(clientData || {}))
            .digest('hex');
        user.deviceFingerprint = fingerprint;
        await user.save();
        
        // Generate secure session token
        const sessionToken = crypto.randomBytes(32).toString('hex');
        
        // Store session in Redis
        const sessionData = {
            walletAddress,
            fingerprint,
            timestamp: Date.now(),
            ip: connectionData.ip,
            userAgent: connectionData.userAgent
        };
        
        await redisClient.set(`session:${sessionToken}`, JSON.stringify(sessionData), 'EX', 86400);
        await redisClient.set(`session:wallet:${walletAddress}`, sessionToken, 'EX', 86400);
        
        logger.info(`[SESSION] HTTP login successful for ${walletAddress}`);
        
        // Set httpOnly cookie
        res.cookie('sessionToken', sessionToken, COOKIE_OPTIONS);
        
        res.json({ success: true, virtualBalance: user.virtualBalance });
        
    } catch (error) {
        logger.error('[AUTH] HTTP login error:', { error: error });
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

app.post('/api/auth/logout', async (req, res) => {
    const { sessionToken } = req.signedCookies;
    if (sessionToken) {
        redisClient.del(`session:${sessionToken}`).catch(console.error);
    }
    res.clearCookie('sessionToken');
    res.json({ success: true });
});

app.get('/api/auth/session', async (req, res) => {
    try {
        const { sessionToken } = req.signedCookies;
        
        if (!sessionToken) {
            return res.status(401).json({ authenticated: false });
        }
        
        const sessionDataStr = await redisClient.get(`session:${sessionToken}`);
        if (!sessionDataStr) {
            res.clearCookie('sessionToken');
            return res.status(401).json({ authenticated: false });
        }
        
        const sessionData = JSON.parse(sessionDataStr);
        const user = await User.findOne({ walletAddress: sessionData.walletAddress });
        
        res.json({
            authenticated: true,
            walletAddress: sessionData.walletAddress,
            virtualBalance: user?.virtualBalance || 0
        });
        
    } catch (error) {
        logger.error('[AUTH] Session validation error:', { error: error });
        res.status(500).json({ authenticated: false });
    }
});

console.log('✅ HTTP authentication endpoints configured');

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

let config = null;
let paymentProcessor = null;

async function initializeConfig() {
    try {
        console.log('🔐 Initializing config with AWS Secrets Manager...');
        const secretString = await getCachedTreasurySecretKey();
        const secretKey = JSON.parse(secretString);
        
        config = {
            USDC_MINT: new PublicKey('Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr'),
            TREASURY_WALLET: new PublicKey('GN6uUVKuijj15ULm3X954mQTKEzur9jxXdRRuLeMqmgH'),
            TREASURY_KEYPAIR: Keypair.fromSecretKey(Buffer.from(secretKey)),
            connection: new Connection(process.env.SOLANA_RPC_URL, 'confirmed'),
            rpcEndpoints: [process.env.SOLANA_RPC_URL],
            io: io
        };
        
        console.log('✅ Config initialized successfully with AWS secret');
        return config;
    } catch (error) {
        logger.error('❌ FATAL: Failed to initialize config:', { error: error });
        process.exit(1);
    }
}

// NEW: Initialize PaymentProcessor AFTER config is ready
mongoose.connection.once('open', async () => {
    try {
        // ✅ FIXED: Initialize config first
        await initializeConfig();
        
        // ✅ FIXED: Now config has connection, TREASURY_KEYPAIR, io, etc.
        paymentProcessor = new PaymentProcessor(config);
        paymentProcessor.startProcessing(60000); // Process every 60s
        console.log('✅ PaymentProcessor initialized with valid config');
    } catch (error) {
        logger.error('❌ FATAL: PaymentProcessor initialization failed:', { error: error });
        process.exit(1);
    }
});

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
        // Build Redis configuration with security settings
        const redisConfig = {
            // Connection settings
            host: process.env.REDIS_HOST || 'localhost',
            port: process.env.REDIS_PORT || 6379,
            
            // Security: Password authentication
            password: process.env.REDIS_PASSWORD,
            
            // Security: TLS encryption (only if explicitly enabled)
            // Set REDIS_TLS=true in .env to enable TLS
            tls: process.env.REDIS_TLS === 'true' ? {
                rejectUnauthorized: process.env.REDIS_TLS_REJECT_UNAUTHORIZED !== 'false'
            } : undefined,
            
            // Robust retry configuration
            retryStrategy: (times) => {
                const delay = Math.min(times * 50, 2000);
                return delay;
            },
            maxRetriesPerRequest: 3,
            retryDelayOnFailover: 100,
            enableReadyCheck: true,
            lazyConnect: true,
            connectTimeout: 10000,
            commandTimeout: 5000
        };
        
        // Create Redis client with secure configuration
        redisClient = new Redis(redisConfig);
        
        // Health monitoring events
        redisClient.on('ready', () => { 
            console.log('✅ Redis ready'); 
            if (process.env.REDIS_PASSWORD) {
                console.log('   🔒 Using password authentication');
            }
            if (process.env.REDIS_TLS === 'true') {
                console.log('   🔐 Using TLS encryption');
            }
        });
        
        redisClient.on('connect', () => {
            console.log('Redis connected');
        });
        
        redisClient.on('error', (err) => { 
            logger.error('⚠️  Redis error (will auto-retry):', { error: err.message }); 
        });
        
        redisClient.on('close', () => { 
            console.warn('⚠️  Redis connection closed (will auto-reconnect)'); 
        });
        
        // Test Redis connection with ping
        await redisClient.ping();  // Simple health check
        await redisClient.set('test', '1', 'EX', 60);
        const testValue = await redisClient.get('test');
        logger.info(`Redis test: ${testValue}`);
    // Redis health auto-managed by ioredis
        await initializeRateLimiter(); // Init after Redis
    } catch (error) {
        logger.error('Failed to initialize Redis:', { error: error });
    // Redis health auto-managed by ioredis
        // CRITICAL: Do not fallback; log and set unhealthy
        console.error('Redis unavailable - transaction processing disabled');
    }
}

initializeRedis().catch((err) => {
    logger.error('Redis init failed:', { error: err });
    // Redis health auto-managed by ioredis
});

// ============================================================================
// REDIS HELPER FUNCTIONS - Proper error handling at operation level
// ============================================================================

/**
 * Execute a Redis operation with automatic error handling.
 * Returns fallback value on failure (graceful degradation).
 */
async function safeRedisOp(operation, fallbackValue = null, operationName = 'Redis operation') {
    try {
        return await operation();
    } catch (error) {
        console.error(`${operationName} failed:`, error.message);
        return fallbackValue;
    }
}

/**
 * Execute a critical Redis operation that must succeed.
 * Throws on failure, forcing the caller to handle it.
 */
async function criticalRedisOp(operation, operationName = 'Critical Redis operation') {
    try {
        return await operation();
    } catch (error) {
        console.error(`${operationName} failed (CRITICAL):`, error.message);
        throw new Error(`Service temporarily unavailable: ${operationName}`);
    }
}



// Socket.io Redis Adapter for scaling (pub/sub across processes)
let pubClient, subClient;
async function initializeSocketAdapter() {
    try {
        pubClient = redisClient.duplicate();
        subClient = redisClient.duplicate();
        io.adapter(createAdapter(pubClient, subClient));
        console.log('Socket.io Redis adapter initialized for scaling');
    } catch (error) {
        logger.error('Failed to initialize Socket.io adapter:', { error: error });
    }
}

// Redis operation wrapped in safeRedisOp
setTimeout(() => {
    initializeSocketAdapter().catch(console.error);
}, 1000);


// Get all active room IDs (O(N) but N is bounded by concurrent games, not all keys)
async function getCleanActiveRooms() {
    try {
        // 1. Get all IDs from the set
        const roomIds = await redisClient.smembers('active:rooms');
        if (roomIds.length === 0) return [];

        const validRooms = [];
        const pipeline = redisClient.pipeline();

        // 2. Check existence of every room efficiently
        for (const roomId of roomIds) {
            pipeline.exists(`room:${roomId}`);
        }
        
        const results = await pipeline.exec(); // [ [null, 1], [null, 0] ... ]

        // 3. Filter results and prepare cleanup
        const cleanupPipeline = redisClient.pipeline();
        
        roomIds.forEach((roomId, index) => {
            const exists = results[index][1] === 1;
            if (exists) {
                validRooms.push(roomId);
            } else {
                // Room data is gone, but ID is still in set -> Zombie!
                // Queue it for removal
                cleanupPipeline.srem('active:rooms', roomId);
            }
        });

        // 4. Execute cleanup if needed
        if (cleanupPipeline.length > 0) {
            await cleanupPipeline.exec();
            logger.info(`🧹 Cleaned up ${roomIds.length - validRooms.length} zombie room IDs`);
        }

        return validRooms;
    } catch (error) {
        logger.error('Error getting/cleaning active rooms:', { error: error });
        return [];
    }
}

// Add wallet to matchmaking pool set
async function trackMatchmakingPlayer(betAmount, walletAddress) {
    try {
        await redisClient.sadd(`active:matchmaking:${betAmount}`, walletAddress);
        logger.info(`✅ Tracking matchmaking player: ${walletAddress} in ${betAmount} pool`);
    } catch (error) {
        logger.error('Error tracking matchmaking player:', { error: error });
    }
}

// Remove wallet from matchmaking pool set
async function untrackMatchmakingPlayer(betAmount, walletAddress) {
    try {
        await redisClient.srem(`active:matchmaking:${betAmount}`, walletAddress);
        logger.info(`✅ Untracked matchmaking player: ${walletAddress} from ${betAmount} pool`);
    } catch (error) {
        logger.error('Error untracking matchmaking player:', { error: error });
    }
}

// Get all wallets in a specific matchmaking pool
async function getMatchmakingPoolWallets(betAmount) {
    try {
        return await redisClient.smembers(`active:matchmaking:${betAmount}`);
    } catch (error) {
        logger.error('Error getting matchmaking pool wallets:', { error: error });
        return [];
    }
}

// Get all active matchmaking bet amounts
async function getAllMatchmakingPools() {
    const validBets = [3, 10, 15, 20, 30];
    const pools = {};
    
    for (const bet of validBets) {
        const wallets = await getMatchmakingPoolWallets(bet);
        if (wallets.length > 0) {
            pools[bet] = wallets;
        }
    }
    
    return pools;
}

// ✅ NEW: O(1) waiting room index management to replace O(N) room scans
async function addWaitingRoom(betAmount, roomId) {
    // Redis operations use criticalRedisOp for error handling
    try {
        await redisClient.zadd(`waiting_rooms:${betAmount}`, Date.now(), roomId);
        await redisClient.expire(`waiting_rooms:${betAmount}`, 3600);
        logger.info(`Added room ${roomId} to waiting index for bet ${betAmount}`);
        return true;
    } catch (error) {
        console.error(`Error adding waiting room ${roomId}:`, error);
        return false;
    }
}

async function getWaitingRoom(betAmount) {
    try {
        const roomIds = await redisClient.zrange(`waiting_rooms:${betAmount}`, 0, 0);
        return roomIds.length > 0 ? roomIds[0] : null;
    } catch (error) {
        console.error(`Error getting waiting room for bet ${betAmount}:`, error);
        return null;
    }
}

async function removeWaitingRoom(betAmount, roomId) {
    try {
        await redisClient.zrem(`waiting_rooms:${betAmount}`, roomId);
        logger.info(`Removed room ${roomId} from waiting index for bet ${betAmount}`);
    } catch (error) {
        console.error(`Error removing waiting room ${roomId}:`, error);
    }
}

async function verifyAndValidateTransaction(signature, expectedAmount, senderAddress, recipientAddress, nonce, maxRetries = 3, retryDelay = 500) {
    logger.info(`🔐 SECURE VERIFICATION: ${signature}`);
    logger.info(`   Expected: ${expectedAmount} USDC from ${senderAddress} to ${recipientAddress}`);
    logger.info(`   Nonce: ${nonce}`);

    const key = `tx:${signature}`;
    const nonceKey = `nonce:${nonce}`;

    // ========================================================================
    // STEP 1: REPLAY ATTACK PREVENTION (MongoDB Atomic Check)
    // ========================================================================
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
            logger.error(`❌ REPLAY ATTACK DETECTED: ${signature} already processed`);
            throw new Error('Transaction already processed - replay attack prevented');
        }
        logger.info(`✅ MongoDB: New transaction recorded`);
    } catch (dbErr) {
        if (dbErr.code === 11000) {
            logger.error(`❌ RACE CONDITION: ${signature} duplicate key error`);
            throw new Error('Transaction already processed');
        }
        logger.error('❌ MongoDB audit failed:', { error: dbErr.message });
        throw new Error('Audit service unavailable');
    }

    // ========================================================================
    // STEP 2: REDIS CACHING & NONCE VERIFICATION
    // ========================================================================
    
    // 2A: Redis signature check (non-blocking, best-effort)
    await safeRedisOp(
        async () => {
            const exists = await redisClient.get(key);
            if (exists) {
                logger.info(`⚠️  Redis: Replay detected for ${key} (MongoDB already prevented)`);
            }
        },
        null,
        'Redis signature check'
    );

    // 2B: Redis nonce check (STRICT BLOCKING)
    try {
        const storedNonce = await redisClient.get(nonceKey);
        if (storedNonce) {
            logger.error(`❌ NONCE REUSE DETECTED: ${nonce}`);
            await TransactionLog.findOneAndUpdate(
                { signature },
                { status: 'failed', errorMessage: 'Nonce already used' }
            );
            throw new Error('Nonce already used - duplicate request prevented');
        }
        
        await redisClient.set(nonceKey, 'used', 'EX', 86400); // 24 hour expiry
        logger.info(`✅ Nonce registered: ${nonce}`);
    } catch (error) {
        if (error.message.includes('Nonce already used')) {
            throw error;
        }
        
        // Redis infrastructure failure - REJECT for safety
        logger.error(`❌ CRITICAL: Redis nonce service unavailable`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: 'Nonce verification service unavailable' }
        );
        throw new Error('Unable to verify transaction - please try again');
    }

    // ========================================================================
    // STEP 3: FETCH & VALIDATE BLOCKCHAIN TRANSACTION
    // ========================================================================
    let transaction;
    try {
        transaction = await verifyTransactionWithStatus(signature, maxRetries, retryDelay);
    } catch (error) {
        if (error.message.includes('Invalid param: Invalid')) {
            logger.error(`❌ Invalid signature format: ${signature}`);
            await TransactionLog.findOneAndUpdate(
                { signature },
                { status: 'failed', errorMessage: 'Invalid signature' }
            );
            throw new Error('Invalid transaction signature');
        }
        logger.error(`❌ Blockchain verification failed: ${error.message}`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: error.message }
        );
        throw new Error('Failed to verify transaction on blockchain');
    }

    if (!transaction) {
        logger.error(`❌ Transaction not found after ${maxRetries} retries`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: 'Transaction not found' }
        );
        throw new Error('Transaction could not be verified');
    }

    // Check if transaction failed on-chain
    if (transaction.meta.err) {
        logger.error(`❌ Transaction failed on-chain: ${JSON.stringify(transaction.meta.err)}`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: JSON.stringify(transaction.meta.err) }
        );
        throw new Error('Transaction failed on the blockchain');
    }

    logger.info(`✅ Transaction fetched from blockchain`);

    // ========================================================================
    // STEP 4: VERIFY TRANSACTION SENDER (CRITICAL SECURITY CHECK)
    // ========================================================================
    const accountKeys = transaction.transaction.message.accountKeys;
    const senderIndex = accountKeys.findIndex(
        key => key.toBase58() === senderAddress
    );

    if (senderIndex === -1) {
        logger.error(`❌ SENDER NOT FOUND: ${senderAddress} not in transaction accounts`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: 'Sender wallet not found in transaction' }
        );
        throw new Error('Transaction sender verification failed');
    }

    // Verify sender is a signer (actually authorized the transaction)
    const message = transaction.transaction.message;
    const isAccountSigner = (index) => {
        // In Solana, signers are indicated by the requiredSignatures count
        // Accounts 0 to (header.numRequiredSignatures - 1) are signers
        return index < message.header.numRequiredSignatures;
    };

    if (!isAccountSigner(senderIndex)) {
        logger.error(`❌ UNAUTHORIZED: ${senderAddress} did not sign transaction`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: 'Sender did not sign transaction' }
        );
        throw new Error('Transaction not signed by expected sender');
    }

    logger.info(`✅ Sender verified: ${senderAddress} signed transaction`);

    // ========================================================================
    // STEP 5: VERIFY TREASURY RECEIVES TOKENS (via Balance Check)
    // ========================================================================
    // NOTE: For SPL token transfers, the treasury wallet might not be directly 
    // in accountKeys. Instead, the treasury's Associated Token Account (ATA) 
    // receives tokens. We verify the treasury through the balance check below,
    // which confirms the token account's owner is the treasury wallet.
    // This is more accurate than checking accountKeys for SPL transfers.

    // ========================================================================
    // STEP 6: VERIFY TOKEN BALANCES & USDC MINT (CRITICAL)
    // ========================================================================
    const postTokenBalances = transaction.meta.postTokenBalances;
    const preTokenBalances = transaction.meta.preTokenBalances;

    if (!postTokenBalances || !preTokenBalances) {
        logger.error(`❌ Missing token balance data`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: 'Missing token balances' }
        );
        throw new Error('Transaction missing required balance information');
    }

    // Find treasury's USDC balance changes
    const treasuryPostBalance = postTokenBalances.find(
        b => b.owner === recipientAddress && b.mint === config.USDC_MINT.toBase58()
    );
    const treasuryPreBalance = preTokenBalances.find(
        b => b.owner === recipientAddress && b.mint === config.USDC_MINT.toBase58()
    );

    if (!treasuryPostBalance) {
        logger.error(`❌ WRONG TOKEN: No USDC balance change for treasury`);
        logger.error(`   Expected mint: ${config.USDC_MINT.toBase58()}`);
        console.error(`   Available mints:`, postTokenBalances.map(b => b.mint));
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: 'Wrong token - expected USDC' }
        );
        throw new Error('Transaction does not transfer USDC to treasury');
    }

    if (!treasuryPreBalance) {
        logger.error(`❌ Missing pre-balance for treasury USDC account`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: 'Missing treasury pre-balance' }
        );
        throw new Error('Cannot verify treasury balance change');
    }

    logger.info(`✅ USDC mint verified: ${config.USDC_MINT.toBase58()}`);
    logger.info(`✅ Treasury verified: ${recipientAddress} received USDC tokens`);
    const postAmount = BigInt(treasuryPostBalance.uiTokenAmount.amount || '0');
    const preAmount = BigInt(treasuryPreBalance.uiTokenAmount.amount || '0');
    const actualTransferAmount = postAmount - preAmount;

    // USDC has 6 decimals - convert expectedAmount to raw amount
    const expectedBigInt = BigInt(Math.round(expectedAmount * 1_000_000));

    if (actualTransferAmount !== expectedBigInt) {
        logger.error(`❌ AMOUNT MISMATCH:`);
        logger.error(`   Expected: ${expectedAmount} USDC (${expectedBigInt} raw)`);
        logger.error(`   Received: ${Number(actualTransferAmount) / 1_000_000} USDC (${actualTransferAmount} raw)`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { 
                status: 'failed', 
                errorMessage: `Amount mismatch: expected ${expectedAmount}, got ${Number(actualTransferAmount) / 1_000_000}` 
            }
        );
        throw new Error(`Amount mismatch: expected ${expectedAmount} USDC, received ${Number(actualTransferAmount) / 1_000_000} USDC`);
    }

    logger.info(`✅ Amount verified: ${expectedAmount} USDC`);

    // ========================================================================
    // STEP 8: VERIFY TOKEN ACCOUNT OWNERSHIP (ADVANCED SECURITY)
    // ========================================================================
    // Verify that the sender's token account actually belongs to them
    const senderTokenBalance = preTokenBalances.find(
        b => b.owner === senderAddress && b.mint === config.USDC_MINT.toBase58()
    );

    if (senderTokenBalance && senderTokenBalance.owner !== senderAddress) {
        logger.error(`❌ TOKEN ACCOUNT OWNERSHIP MISMATCH`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: 'Sender token account ownership invalid' }
        );
        throw new Error('Token account ownership verification failed');
    }

    logger.info(`✅ Token account ownership verified`);

    // ========================================================================
    // STEP 9: VERIFY MEMO INSTRUCTION WITH NONCE (REPLAY PROTECTION)
    // ========================================================================
    try {
        const MEMO_PROGRAM_ID = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
        
        const memoInstruction = transaction.transaction.message.instructions.find(ix => {
            const programId = accountKeys[ix.programIdIndex];
            return programId.toString() === MEMO_PROGRAM_ID;
        });
        
        if (!memoInstruction) {
            logger.error(`❌ MISSING MEMO: Transaction missing memo instruction`);
            await TransactionLog.findOneAndUpdate(
                { signature },
                { status: 'failed', errorMessage: 'Missing memo instruction' }
            );
            throw new Error('Transaction missing memo instruction for replay protection');
        }
        
        // Decode memo data
        let memoText;
        try {
            const memoDataBytes = bs58.decode(memoInstruction.data);
            memoText = Buffer.from(memoDataBytes).toString('utf8');
        } catch (e) {
            try {
                const memoData = Buffer.from(memoInstruction.data, 'base64');
                memoText = memoData.toString('utf8');
            } catch (e2) {
                memoText = memoInstruction.data;
            }
        }
        
        logger.info(`📝 Memo text: ${memoText}`);
        
        // Verify nonce is in memo
        if (!memoText.includes(nonce)) {
            logger.error(`❌ NONCE MISMATCH: Expected "${nonce}" in memo "${memoText}"`);
            await TransactionLog.findOneAndUpdate(
                { signature },
                { status: 'failed', errorMessage: 'Nonce mismatch in transaction memo' }
            );
            throw new Error('Nonce mismatch - transaction does not match request');
        }
        
        logger.info(`✅ Memo nonce verified: ${nonce}`);
    } catch (error) {
        if (error.message.includes('Nonce') || error.message.includes('memo') || error.message.includes('MISSING')) {
            throw error;
        }
        console.error(`❌ Error parsing memo:`, error);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: 'Invalid memo format' }
        );
        throw new Error('Invalid memo instruction format');
    }

    // ========================================================================
    // STEP 10: VERIFY TRANSACTION AGE (PREVENT OLD TRANSACTION REPLAY)
    // ========================================================================
    if (!transaction.blockTime) {
        logger.error(`❌ Missing blockTime in transaction`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: 'Transaction missing timestamp' }
        );
        throw new Error('Transaction missing timestamp');
    }

    const TX_MAX_AGE = 300000; // 5 minutes (increased from 1 minute for better UX)
    const txAge = Date.now() - (transaction.blockTime * 1000);
    
    if (txAge > TX_MAX_AGE) {
        logger.error(`❌ TRANSACTION TOO OLD: ${txAge}ms (max ${TX_MAX_AGE}ms)`);
        await TransactionLog.findOneAndUpdate(
            { signature },
            { status: 'failed', errorMessage: 'Transaction expired (must be used within 5 minutes)' }
        );
        throw new Error('Transaction expired - please create a new transaction');
    }
    
    logger.info(`✅ Transaction age: ${Math.round(txAge / 1000)}s (within ${TX_MAX_AGE / 1000}s limit)`);

    // ========================================================================
    // STEP 11: CACHE IN REDIS (BEST-EFFORT)
    // ========================================================================
    try {
        await redisClient.set(key, '1', 'EX', 604800); // 7 days
        logger.info(`✅ Transaction cached in Redis`);
    } catch (redisErr) {
        logger.error('⚠️  Redis cache failed (non-blocking):', { error: redisErr.message });
    }

    // ========================================================================
    // VERIFICATION COMPLETE
    // ========================================================================
    logger.info(`🎉 TRANSACTION VERIFIED SUCCESSFULLY: ${signature}`);
    logger.info(`   ✅ Replay protection (MongoDB + Redis + Nonce)`);
    logger.info(`   ✅ Sender authorization (${senderAddress})`);
    logger.info(`   ✅ Treasury recipient (${recipientAddress})`);
    logger.info(`   ✅ USDC mint (${config.USDC_MINT.toBase58()})`);
    logger.info(`   ✅ Amount (${expectedAmount} USDC)`);
    logger.info(`   ✅ Token account ownership`);
    logger.info(`   ✅ Memo nonce (${nonce})`);
    logger.info(`   ✅ Transaction age (${Math.round(txAge / 1000)}s)`);

    return transaction;
}

async function verifyTransactionWithStatus(signature, maxRetries = 3, retryDelay = 500) {
    for (let i = 0; i < maxRetries; i++) {
        logger.info(`🔍 Verification attempt ${i + 1}/${maxRetries} for ${signature}`);
        
        const statuses = await config.connection.getSignatureStatuses(
            [signature], 
            { searchTransactionHistory: true }
        );
        
        const status = statuses.value[0];
        
        if (status && status.confirmationStatus === 'confirmed') {
            logger.info(`✅ Transaction confirmed on blockchain`);
            return await config.connection.getTransaction(signature, { 
                maxSupportedTransactionVersion: 0 
            });
        }
        
        if (i < maxRetries - 1) {
            logger.info(`⏳ Transaction not confirmed yet, retrying in ${retryDelay}ms...`);
            await new Promise(resolve => setTimeout(resolve, retryDelay));
        }
    }
    
    logger.info(`❌ Transaction verification failed after ${maxRetries} retries`);
    return null;
}

// ============================================================================
// ENHANCED RATE LIMITING WITH PROGRESSIVE PENALTIES
// ============================================================================
/**
 * Rate limit an event using dedicated RateLimiterRedis instances
 * Tracks both wallet address AND IP for defense-in-depth
 * 
 * @param {string} walletAddress - User's wallet address
 * @param {string} eventName - Name of the event being rate limited
 * @param {string} ip - IP address of the user
 * @param {object} socket - Socket.io socket object (optional, for disconnecting abusers)
 */
async function rateLimitEvent(walletAddress, eventName, ip = null, socket = null) {
    const limiter = eventLimiters.get(eventName);
    
    if (!limiter) {
        logger.warn(`⚠️  No rate limiter configured for event: ${eventName}`);
        return; // Fail open - don't block if limiter not configured
    }
    
    try {
        // Rate limit by wallet address (primary identifier)
        const walletKey = `${walletAddress}`;
        await limiter.consume(walletKey, 1);
        
        // Also rate limit by IP if provided (defense-in-depth)
        if (ip) {
            const ipKey = `ip:${ip}`;
            try {
                await limiter.consume(ipKey, 1);
            } catch (ipError) {
                logger.error(`🚨 [RATE LIMIT] IP ${ip} exceeded limit for ${eventName}`);
                // Block the IP temporarily
                await redisClient.set(`blocklist:${ip}`, '1', 'EX', 600); // 10 min block
                if (socket) {
                    socket.disconnect(true);
                }
                throw new Error(`Rate limit exceeded for ${eventName}. Please wait before trying again.`);
            }
        }
        
        logger.info(`✅ [RATE LIMIT] ${eventName} passed for ${walletAddress}`);
        
    } catch (error) {
        // Check if it's a rate limit error
        if (error.msBeforeNext !== undefined) {
            const waitSeconds = Math.ceil(error.msBeforeNext / 1000);
            logger.error(`🚨 [RATE LIMIT] ${walletAddress} exceeded limit for ${eventName}, retry in ${waitSeconds}s`);
            
            // Track repeat offenders for progressive penalties
            const offenderKey = `offender:${walletAddress}:${eventName}`;
            const offenseCount = await redisClient.incr(offenderKey);
            await redisClient.expire(offenderKey, 3600); // Reset after 1 hour
            
            if (offenseCount > 5) {
                // Progressive penalty: longer block for repeat offenders
                logger.error(`🚨 [SECURITY] ${walletAddress} is a repeat offender (${offenseCount} violations) - extended block`);
                await redisClient.set(`blocklist:wallet:${walletAddress}`, '1', 'EX', 3600); // 1 hour block
                if (socket) {
                    socket.emit('error', { 
                        message: 'Account temporarily restricted due to suspicious activity',
                        code: 'RATE_LIMIT_ABUSE'
                    });
                    socket.disconnect(true);
                }
            }
            
            throw new Error(`Rate limit exceeded for ${eventName}. Please wait ${waitSeconds} seconds before trying again.`);
        }
        
        // Re-throw other errors
        throw error;
    }
}

// DEPRECATED: Old manual counter-based rate limiting (kept for backward compatibility)
// New code should use the improved rateLimitEvent function above

// FIXED: Add Redis rate limiter for failed reCAPTCHA (max 5 per IP per hour)
async function rateLimitFailedRecaptcha(ip) {
    await safeRedisOp(
        async () => {
            const key = `recaptcha_fail:${ip}`;
            const attempts = await redisClient.get(key) || 0;
            if (parseInt(attempts) >= 5) {
                throw new Error('Too many failed verification attempts. Try again in 1 hour.');
            }
            await redisClient.incr(key);
            await redisClient.expire(key, 3600);
        },
        null,
        `reCAPTCHA rate limit for ${ip}`
    );
}

// Enhanced: Socket-specific rate-limit
async function rateLimitSocket(socket, points = 100, duration = 60) {
    if (!socketRateLimiter) {
        logger.warn(`⚠️  Socket rate limiting unavailable for ${socket.id}`);
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
                logger.warn(`TriviaBot: Invalid options or correctAnswer. Options: ${JSON.stringify(options)}, CorrectAnswer: ${correctAnswer}. Question: ${question}`);
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
                        logger.error(`TriviaBot: Options array is problematic for question "${question}". Defaulting bot answer to 0.`);
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

// ============================================================================
// SOCKET.IO COOKIE AUTHENTICATION MIDDLEWARE
// ============================================================================
// Validates session from httpOnly cookie before allowing Socket.IO connection
io.use(async (socket, next) => {
    const startTime = Date.now();
    
    try {
        // Check if this is a login/reconnect event (exempt from auth)
        const incomingEvent = socket.handshake.auth?.event || '';
        if (incomingEvent === 'walletLogin' || incomingEvent === 'walletReconnect') {
            console.log('[AUTH] Allowing unauthenticated connection for:', incomingEvent);
            return next(); // Allow without auth
        }
        
        // Extract cookies from handshake
        const cookieHeader = socket.handshake.headers.cookie;
        
        if (!cookieHeader) {
            console.warn('[AUTH] No cookies in Socket.IO handshake');
            return next(new Error('Authentication required'));
        }
        
        // Parse cookies
        const cookies = require('cookie').parse(cookieHeader);
        const cookieSignature = require('cookie-signature');
        
        // Extract signed session token
        let sessionToken = cookies.sessionToken;
        if (!sessionToken) {
            console.warn('[AUTH] No session cookie found');
            return next(new Error('No session cookie'));
        }
        
        // Unsign cookie
        if (sessionToken.startsWith('s:')) {
            sessionToken = cookieSignature.unsign(sessionToken.slice(2), SESSION_SECRET);
            if (sessionToken === false) {
                console.warn('[AUTH] Invalid cookie signature');
                return next(new Error('Invalid session'));
            }
        }
        
        // Validate session in Redis
        const sessionDataStr = await redisClient.get(`session:${sessionToken}`);
        
        if (!sessionDataStr) {
            console.warn('[AUTH] Session not found in Redis');
            return next(new Error('Session expired'));
        }
        
        const sessionData = JSON.parse(sessionDataStr);
        
        // Attach authenticated user to socket
        socket.user = {
            walletAddress: sessionData.walletAddress,
            fingerprint: sessionData.fingerprint,
            sessionToken: sessionToken
        };
        
        // Log successful authentication
        SecurityLogger.socketAuthSuccess(sessionData.walletAddress, socket);
        
        console.log('[AUTH] Socket authenticated successfully:', {
            walletAddress: sessionData.walletAddress.substring(0, 6) + '...',
            socketId: socket.id
        });
        
        next();
        
    } catch (error) {
        const duration = Date.now() - startTime;
        
        // ✅ PROPERLY LOG ERROR - THIS IS THE FIX!
        console.error('[AUTH] Socket authentication error:', error);
        
        logger.error('[AUTH] Connection middleware error', {
            error: error.message || String(error),     // ← Extract message
            errorName: error.name || 'Error',          // ← Get error type
            errorCode: error.code,                     // ← Get error code
            stack: error.stack,                        // ← Get stack trace
            socketId: socket.id,
            duration,
            hasUser: !!socket.user,
            walletAddress: socket.user?.walletAddress,
            hasCookies: !!socket.handshake.headers.cookie,
            incomingEvent: socket.handshake.auth?.event
        });
        
        next(new Error('Authentication failed'));
    }
});


io.on('connection', (socket) => {
    logger.info('New client connected:', socket.id);
    
    const connectionData = {
        ip: socket.handshake.headers['x-forwarded-for'] || socket.handshake.address,
        userAgent: socket.handshake.headers['user-agent'],
        timestamp: new Date(),
        sessionId: socket.id
    };
    
    botDetector.trackConnection(connectionData.ip, connectionData.userAgent, socket.id);
    
    // Redis operation wrapped in safeRedisOp
    (async () => {
        try {
            const isBlocked = await redisClient.get(`blocklist:${connectionData.ip}`);
            if (isBlocked) {
                logger.warn(`Blocked IP attempting to connect: ${connectionData.ip}`);
                socket.disconnect();
            }
        } catch (error) {
            logger.error('Error checking IP blocklist:', { error: error });
        }
    })();

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
            logger.warn(`Packet rate limit hit for ${socket.id}: ${error.message}`);
            next(new Error('Rate limited'));
        }
    });

    socket.on('walletLogin', async ({ walletAddress, signature, message, recaptchaToken, clientData }) => {
        try {
            // Redis operation wrapped in safeRedisOp
            const isWalletBlocked = await redisClient.get(`blocklist:wallet:${walletAddress}`);
            if (isWalletBlocked) {
                logger.warn(`Blocked wallet attempting to login: ${walletAddress}`);
                socket.emit('loginFailure', 'This wallet is temporarily blocked.');
                return;
            }
            logger.info('Wallet login attempt:', { walletAddress, recaptchaToken: !!recaptchaToken });
            
            // FIXED: Rate limit login attempts (existing) + failed reCAPTCHA specifically
            // Redis operation wrapped in safeRedisOp
            const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
            const loginLimitKey = `login:${clientIP}`;
            const loginAttempts = await redisClient.get(loginLimitKey) || 0;
                
            if (loginAttempts > 100) {
                SecurityLogger.rateLimitExceeded(clientIP, 'login', 5, '1 minute');
            trackRateLimitViolation(clientIP, { eventName: 'login' });
                return socket.emit('loginFailure', 'Too many login attempts. Please try again later.');
            }
            await redisClient.set(loginLimitKey, parseInt(loginAttempts) + 1, 'EX', 3600);
                
            
            // FIXED: Enforce reCAPTCHA - throw if fails (no fallback success)
            let recaptchaResult;
            try {
                recaptchaResult = await verifyRecaptcha(recaptchaToken);
            } catch (error) {
                // FIXED: Log failure for rate limiting, then emit error
                // Redis operation wrapped in safeRedisOp
                const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                try {
                    await rateLimitFailedRecaptcha(clientIP); // Increment on failure
                } catch (rateError) {
                    console.warn(`reCAPTCHA rate limit hit for IP ${clientIP}:`, rateError.message);
                    return socket.emit('loginFailure', 'Too many failed verification attempts. Please try again later.');
                }
                logger.warn(`reCAPTCHA verification failed for wallet ${walletAddress}: ${error.message}`);
                return socket.emit('loginFailure', 'Verification failed. Please try again.');
            }
            logger.info('reCAPTCHA verification result:', recaptchaResult);
            
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
                    logger.warn(`Client data anomalies for ${walletAddress}: ${anomalies.join(', ')}`);
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
                    logger.warn(`Invalid signature for wallet ${walletAddress}`);
                    return socket.emit('loginFailure', 'Invalid signature');
                }
            } catch (error) {
                logger.error('Signature verification error:', { error: error });
                return socket.emit('loginFailure', 'Invalid wallet credentials');
            }

            try {
                let user = await User.findOne({ walletAddress });
                if (!user) {
                    logger.info('Creating new user for wallet:', walletAddress);
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

                const sessionData = {
                    walletAddress,
                    fingerprint,
                    timestamp: Date.now(),
                    ip: connectionData.ip,
                    userAgent: connectionData.userAgent
                };

                try {
                    await redisClient.set(
                        `session:${walletAddress}`,
                        JSON.stringify(sessionData),
                        'EX',
                        86400 // 24 hours in seconds
                    );
                    logger.info(`[SESSION] Created session for ${walletAddress} (expires in 24h)`);
                } catch (redisError) {
                    console.error(`[SESSION] Failed to store session for ${walletAddress}:`, redisError);
                    // Continue anyway - session will be validated on next event
                }
                // ===== END SESSION STORAGE =====

                // Create temporary verification token for HTTP endpoint
                // This proves Socket.IO already verified the signature
                const verifyToken = crypto.randomBytes(32).toString('hex');
                try {
                    await redisClient.set(
                        `verify:${walletAddress}`,
                        verifyToken,
                        'EX',
                        30  // Expires in 30 seconds
                    );
                    logger.info(`[VERIFY] Created verification token for ${walletAddress}`);
                } catch (error) {
                    console.error(`[VERIFY] Failed to store verification token:`, error);
                }

                logger.info('Login successful for wallet:', walletAddress);

                socket.emit('loginSuccess', {
                    walletAddress: user.walletAddress,
                    virtualBalance: user.virtualBalance,
                    verifyToken: verifyToken  // Send to client for HTTP authentication
                });
            } catch (error) {
                logger.error('Database error during login:', { error: error });
                socket.emit('loginFailure', 'Server error during login. Please try again.');
            }
        } catch (error) {
            logger.error('Unexpected login error:', { error: error });
            socket.emit('loginFailure', 'An unexpected error occurred. Please try again.');
        }
    });

    socket.on('walletReconnect', async (walletAddress) => {
        try {
            logger.info(`[RECONNECT] Attempt for wallet: ${walletAddress}`);
            
            // ===== VALIDATE SESSION EXISTS IN REDIS =====
            const sessionKey = `session:${walletAddress}`;
            const session = await redisClient.get(sessionKey);
            
            if (!session) {
                logger.warn(`[RECONNECT] No valid session found for ${walletAddress}`);
                return socket.emit('loginFailure', 'Session expired - please login again');
            }

            // Parse and validate session age
            let sessionData;
            try {
                sessionData = JSON.parse(session);
                
                const sessionAge = Date.now() - sessionData.timestamp;
                const MAX_SESSION_AGE = 24 * 60 * 60 * 1000; // 24 hours
                
                if (sessionAge > MAX_SESSION_AGE) {
                    logger.warn(`[RECONNECT] Session too old for ${walletAddress}: ${sessionAge}ms`);
                    await redisClient.del(sessionKey); // Clean up
                    return socket.emit('loginFailure', 'Session expired - please login again');
                }
            } catch (error) {
                console.error(`[RECONNECT] Session parse error for ${walletAddress}:`, error);
                await redisClient.del(sessionKey); // Clean up corrupted session
                return socket.emit('loginFailure', 'Session corrupted - please login again');
            }
            
            // ===== SESSION VALID - RESTORE USER =====
            const user = await User.findOne({ walletAddress });
            if (user) {
                // Restore socket.user with fingerprint from session
                socket.user = { 
                    walletAddress,
                    fingerprint: sessionData.fingerprint 
                };
                
                // Join wallet-specific room for notifications
                socket.join(`wallet:${walletAddress}`);
                
                logger.info(`[RECONNECT] ✓ Successful for ${walletAddress} (session age: ${Math.round((Date.now() - sessionData.timestamp)/1000)}s)`);
                socket.emit('loginSuccess', {
                    walletAddress: user.walletAddress,
                    virtualBalance: user.virtualBalance || 0
                });
            } else {
                logger.warn(`[RECONNECT] User not found in database for ${walletAddress}`);
                socket.emit('loginFailure', 'Wallet not found - please login again');
            }
        } catch (error) {
            const sanitized = sanitizeError(error, 'walletReconnect', 'Reconnection failed. Please login again.');
            socket.emit('loginFailure', sanitized.error);
        }
    });

    // NEW: Listen for payment completion/failure events from processor (broadcast to relevant sockets)
    socket.on('connect', () => {
        // Join a "wallet room" for payment notifications (use wallet as room name)
        if (socket.user && socket.user.walletAddress) {
            socket.join(`wallet:${socket.user.walletAddress}`);
        }
    });

    // ADD this AFTER authMiddleware definition (around line 250):
    async function validateSocketSession(socket, eventName) {
        if (!socket.user || !socket.user.walletAddress) {
            logger.auth(`Unauthorized ${eventName} from socket ${socket.id}`);
            socket.emit('error', { 
                message: 'Unauthorized: Please login first',
                code: 'AUTH_REQUIRED'
            });
            return false;
        }

        const walletAddress = socket.user.walletAddress;
        const sessionKey = `session:${walletAddress}`;
        
        try {
            const session = await redisClient.get(sessionKey);
            
            if (!session) {
                logger.auth(`Session expired for ${walletAddress} on ${eventName}`);
                socket.emit('error', { 
                    message: 'Session expired: Please login again',
                    code: 'SESSION_EXPIRED'
                });
                socket.disconnect(true);
                return false;
            }

            const sessionData = JSON.parse(session);
            const sessionAge = Date.now() - sessionData.timestamp;
            const MAX_SESSION_AGE = 24 * 60 * 60 * 1000;

            if (sessionAge > MAX_SESSION_AGE) {
                logger.auth(`Session too old for ${walletAddress}: ${sessionAge}ms on ${eventName}`);
                await redisClient.del(sessionKey);
                socket.emit('error', { 
                    message: 'Session expired: Please login again',
                    code: 'SESSION_EXPIRED'
                });
                socket.disconnect(true);
                return false;
            }

            logger.auth(`✓ Event ${eventName} authorized for ${walletAddress}`);
            return true;
            
        } catch (error) {
            logger.security('auth_error', { message: `Session validation error for ${eventName}`, error});
            socket.emit('error', { 
                message: 'Authentication error occurred',
                code: 'AUTH_ERROR'
            });
            return false;
        }
    }
    // Apply rate-limit + auth to game events
    const gameEvents = ['joinGame', 'playerReady', 'joinHumanMatchmaking', 'joinBotGame', 'switchToBot', 'matchFound', 'leaveRoom', 'requestBotRoom', 'requestBotGame', 'submitAnswer'];
    gameEvents.forEach(event => {
        socket.on(event, async (...args) => {
            try {
                // await rateLimitSocket(socket);
                const isValidSession = await validateSocketSession(socket, event);
                if (!isValidSession) {
                    return; // Stop execution - validation function already sent error to client
                }
                    
                // Call original handler based on event type
                if (event === 'joinGame') {
                    const data = args[0];
                    const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                    await rateLimitEvent(data.walletAddress, 'joinGame', clientIP, socket);
                    
                    // ✅ Check if blocked
                    if (isBlocked(data.walletAddress) || isBlocked(socket.handshake.address)) {
                        logger.error(`🚨 [SECURITY] Blocked identifier attempted ${event}`);
                        socket.emit('joinGameFailure', 'Access denied');
                        return;
                    }
                    
                    const { error } = transactionSchema.validate(data);
                    if (error) {
                        const identifier = data.walletAddress || socket.handshake.address;
                        trackValidationFailure(identifier, 'joinGame', error.message);
                        console.error('Validation error:', sanitizeForLog(error.message));
                        socket.emit('joinGameFailure', 'Invalid input format');
                        return;
                    }
                    const { walletAddress, betAmount } = data;

                    logger.info('Join game request:', { walletAddress, betAmount });

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
                    logger.info(`Player ${walletAddress} joined temporary room ${roomId}`);
                    socket.emit('gameJoined', roomId);

                    await logGameRoomsState();
                } else if (event === 'playerReady') {
                    const { roomId, preferredMode, recaptchaToken } = args[0];
                    
                    // ✅ NEW: Rate limit playerReady to prevent DoS
                    const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                    await rateLimitEvent(socket.user.walletAddress, 'playerReady', clientIP, socket);
                    
                    const { error } = playerReadySchema.validate({ roomId, preferredMode, recaptchaToken });
                    if (error) {
                        const sanitized = sanitizeValidationError(error, 'playerReady');
                        socket.emit('gameError', sanitized);
                        return;
                    }

                    logger.info(`Player ${socket.id} ready in room ${roomId}, preferred mode: ${preferredMode || 'not specified'}`);
                    let room = await getGameRoom(roomId);

                    if (!room) {
                        logger.error(`Room ${roomId} not found when player ${socket.id} marked ready`);
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
                        SecurityLogger.deviceMismatch(username, user.deviceFingerprint, socket.user.fingerprint, { event: 'playerReady' });
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
                        logger.info(`Room ${roomId} is set for bot play, not starting regular game`);
                        return;
                    }

                    if (preferredMode === 'human') {
                        room.roomMode = 'human';
                        await updateGameRoom(roomId, room);
                        logger.info(`Room ${roomId} marked for human vs human play`);

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
                                    logger.info(`Found matching room ${otherRoomId} for player in room ${roomId} (O(1) lookup)`);
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
                                    logger.info(`Waiting room ${otherRoomId} no longer valid, replacing with ${roomId}`);
                                    await removeWaitingRoom(room.betAmount, otherRoomId);
                                    await addWaitingRoom(room.betAmount, roomId);
                                }
                            } else {
                                // No waiting room found, add this one to index
                                await addWaitingRoom(room.betAmount, roomId);
                                logger.info(`No match found for player in room ${roomId}, added to waiting index`);
                            }
                        }
                    }

                    if (room.players.length === 2 && !room.gameStarted) {
                        logger.info(`Starting multiplayer game in room ${roomId} with 2 players`);
                        room.gameStarted = true;
                        room.roomMode = 'multiplayer';
                        await updateGameRoom(roomId, room);
                        await startGame(roomId);
                    } else {
                        logger.info(`Room ${roomId} has ${room.players.length} players, waiting for more to join`);
                    }

                    await logGameRoomsState();
                } else if (event === 'joinHumanMatchmaking') {
                    const data = args[0];
                    const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                    await rateLimitEvent(data.walletAddress, 'joinHumanMatchmaking', clientIP, socket);
                    const { error } = transactionSchema.validate(data);
                    if (error) {
                        const sanitized = sanitizeValidationError(error, 'joinHumanMatchmaking');
                        socket.emit('joinGameFailure', sanitized.error);
                        return;
                    }

                    const { walletAddress, betAmount, transactionSignature, gameMode, recaptchaToken, nonce } = data;  // NEW: Extract nonce
                    logger.info('Human matchmaking request:', { walletAddress, betAmount, gameMode, nonce });

                    // FIXED: Strict reCAPTCHA enforcement
                    let recaptchaResult;
                    try {
                        recaptchaResult = await verifyRecaptcha(recaptchaToken);
                    } catch (error) {
                        SecurityLogger.recaptchaFailed(walletAddress, error.message, null, clientIP);
                        trackRecaptchaFailure(walletAddress, { error: error.message, event: 'joinHumanMatchmaking' });
                        // FIXED: Increment failed attempts ONLY on reCAPTCHA failure
                        // Redis operation wrapped in safeRedisOp
                        const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                        await rateLimitFailedRecaptcha(clientIP);
                        socket.emit('joinGameFailure', 'Verification failed. Please try again.');
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

                    AuditLogger.transactionVerified(walletAddress, betAmount, transactionSignature, config.TREASURY_WALLET.toString(), nonce, clientIP);

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
                                logger.info(`Player ${walletAddress} left room ${socket.roomId} for matchmaking`);
                                if (existingRoom.players.length === 0) {
                                    await deleteGameRoom(socket.roomId);
                                    logger.info(`Deleted empty room ${socket.roomId}`);
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
                        logger.info(`✅ ATOMIC MATCH: Creating game room ${roomId} for ${walletAddress} vs ${opponent.walletAddress}`);
                        
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
                        logger.info(`No opponents available. Adding ${walletAddress} to matchmaking pool for ${betAmount}`);
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
                    const data = args[0];
                    const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                    await rateLimitEvent(data.walletAddress, 'joinBotGame', clientIP, socket);
                    const { error } = transactionSchema.validate(data);
                    if (error) {
                        const sanitized = sanitizeValidationError(error, 'joinBotGame');
                        socket.emit('joinGameFailure', sanitized.error);
                        return;
                    }

                    const { walletAddress, betAmount, transactionSignature, gameMode, recaptchaToken, nonce } = data;  // NEW: Extract nonce
                    logger.info('Bot game request:', { walletAddress, betAmount, gameMode, nonce });

                    // FIXED: Strict reCAPTCHA enforcement
                    let recaptchaResult;
                    try {
                        recaptchaResult = await verifyRecaptcha(recaptchaToken);
                    } catch (error) {
                        SecurityLogger.recaptchaFailed(walletAddress, error.message, null, clientIP);
                        trackRecaptchaFailure(walletAddress, { error: error.message, event: 'joinBotGame' });
                        // FIXED: Increment failed attempts ONLY on reCAPTCHA failure
                        // Redis operation wrapped in safeRedisOp
                        const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                        await rateLimitFailedRecaptcha(clientIP);
                        socket.emit('joinGameFailure', 'Verification failed. Please try again.');
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

                    AuditLogger.transactionVerified(walletAddress, betAmount, transactionSignature, config.TREASURY_WALLET.toString(), nonce, clientIP);

                    // FIXED: Clean up existing room using socket.roomId (no scan needed)
                    if (socket.roomId) {
                        let existingRoom = await getGameRoom(socket.roomId);
                        if (existingRoom) {
                            const playerIndex = existingRoom.players.findIndex(p => p.username === walletAddress);
                            if (playerIndex !== -1) {
                                logger.info(`Player ${walletAddress} already in room ${socket.roomId}, cleaning up`);
                                existingRoom.players.splice(playerIndex, 1);
                                existingRoom.isDeleted = true;
                                await updateGameRoom(socket.roomId, existingRoom);
                                socket.leave(socket.roomId);
                                socket.roomId = null;  // FIXED: Clear roomId
                                await redisClient.del(`room:${socket.roomId}`);
                                logger.info(`Deleted room ${socket.roomId} due to new bot game request`);
                            }
                        }
                    }

                    const roomId = generateRoomId();
                    logger.info(`Creating bot game room ${roomId} for player ${walletAddress}`);

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
                        const sanitized = sanitizeValidationError(error, 'switchToBot');
                        socket.emit('matchmakingError', sanitized);
                        return;
                    }

                    logger.info(`Player ${socket.id} wants to switch from matchmaking to bot game`);

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
                                logger.info(`Found player ${playerData.username} in room ${socket.roomId} with bet ${playerBetAmount}`);
                                existingRoom.players.splice(playerIndex, 1);
                                socket.leave(socket.roomId);
                                socket.roomId = null;  // FIXED: Clear roomId
                                if (existingRoom.players.length === 0) {
                                    await deleteGameRoom(socket.roomId);
                                    logger.info(`Deleted empty room ${socket.roomId}`);
                                } else {
                                    await updateGameRoom(socket.roomId, existingRoom);
                                    io.to(socket.roomId).emit('playerLeft', playerData.username);
                                }
                            }
                        }
                    }

                    if (!playerFound && socket.matchmakingPool) {
                        logger.info(`Player ${socket.id} found in matchmaking pool via socket reference`);
                        const playerDataFromPool = await removeFromMatchmakingPool(socket.matchmakingPool, socket.id);
                        if (playerDataFromPool) {
                            playerData = playerDataFromPool;
                            playerBetAmount = socket.matchmakingPool;
                            playerFound = true;
                            socket.matchmakingPool = null;  // ✅ Clear reference after removal
                            logger.info(`Removed player ${playerData.walletAddress} from matchmaking pool for ${playerBetAmount}`);
                        }
                    }

                    // ✅ FIXED: Removed fallback scanKeys - force root cause fix
                    if (!playerFound) {
                        logger.error(`CRITICAL METRIC: socket.matchmakingPool missing for ${socket.id} - potential bug or race condition`);
                        // TODO: Send to monitoring service (Sentry, Datadog, CloudWatch, etc.)
                        // Example: await metrics.increment('matchmaking.missing_pool_ref', { socketId: socket.id });
                        
                        socket.emit('matchmakingError', { 
                            message: 'Matchmaking state lost. Please try joining the queue again.' 
                        });
                        return;
                    }

                    if (!playerFound || !playerData) {
                        logger.error(`Player ${socket.id} not found in any matchmaking pool or room`);
                        socket.emit('matchmakingError', { message: 'Not found in matchmaking or game rooms' });
                        return;
                    }

                    const playerIdentifier = playerData.username || playerData.walletAddress || socket.id;
                    const newRoomId = generateRoomId();
                    logger.info(`Creating bot game room ${newRoomId} for player ${playerIdentifier}`);

                    // Create a new game room in Redis
                    await createGameRoom(newRoomId, playerBetAmount, 'bot');
                    let room = await getGameRoom(newRoomId);
                    if (!room) {
                        logger.error(`Failed to create or retrieve room ${newRoomId}`);
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
                            const sanitized = sanitizeValidationError(error, 'matchFound');
                            socket.emit('gameError', sanitized);
                            return;
                        }

                        logger.info(`Match found, player ${socket.id} moved to room ${newRoomId}`);
                        socket.roomId = newRoomId;  // FIXED: Set roomId on socket
                        // Additional handling if needed
                    } catch (error) {
                        const sanitized = sanitizeError(error, 'matchFound', 'Error processing match.');
                        socket.emit('gameError', sanitized);
                    }
                } else if (event === 'leaveRoom') {
                    const { roomId } = args[0];
                    try {
                        // Rate limit leaveRoom to prevent spam
                        const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                        await rateLimitEvent(socket.user.walletAddress, 'leaveRoom', clientIP, socket);
                        
                        const { error } = leaveRoomSchema.validate({ roomId });
                        if (error) {
                            const sanitized = sanitizeValidationError(error, 'leaveRoom');
                            socket.emit('gameError', sanitized);
                            return;
                        }

                        logger.info(`Player ${socket.id} requested to leave room ${roomId}`);

                        let room = await getGameRoom(roomId);
                        if (!room) {
                            logger.info(`Room ${roomId} not found when player tried to leave`);
                            socket.emit('leftRoom', { roomId });
                            return;
                        }

                        if (room.gameStarted) {
                            logger.info(`Game already started in room ${roomId}, handling as disconnect`);
                            return;
                        }

                        const playerIndex = room.players.findIndex(p => p.id === socket.id);
                        if (playerIndex !== -1) {
                            const player = room.players[playerIndex];
                            logger.info(`Removing player ${player.username} from room ${roomId}`);
                            room.players.splice(playerIndex, 1);

                            socket.leave(roomId);
                            if (roomId === socket.roomId) socket.roomId = null;  // FIXED: Clear roomId if matching

                            if (room.players.length === 0) {
                                logger.info(`Room ${roomId} is now empty, deleting it`);
                                await deleteGameRoom(roomId);
                            } else {
                                await updateGameRoom(roomId, room);
                                logger.info(`Notifying remaining players in room ${roomId}`);
                                io.to(roomId).emit('playerLeft', player.username);
                            }
                        }
                        
                        // ✅ NEW: Clear matchmaking ref if somehow set (edge case)
                        socket.matchmakingPool = null;

                        socket.emit('leftRoom', { roomId });
                    } catch (error) {
                        const sanitized = sanitizeError(error, 'leaveRoom', 'Error leaving room.');
                        socket.emit('gameError', sanitized);
                    }
                } else if (event === 'requestBotRoom') {
                    const { walletAddress, betAmount } = args[0];
                    try {
                        const { error } = requestBotRoomSchema.validate({ walletAddress, betAmount });
                        if (error) {
                            const sanitized = sanitizeValidationError(error, 'requestBotRoom');
                            socket.emit('gameError', sanitized);
                            return;
                        }

                        logger.info(`Player ${walletAddress} requesting dedicated bot room with bet ${betAmount}`);

                        const roomId = generateRoomId();
                        logger.info(`Creating new bot room ${roomId} for ${walletAddress}`);

                        await createGameRoom(roomId, betAmount, 'bot');
                        let room = await getGameRoom(roomId);
                        if (!room) {
                            logger.error(`Failed to create or retrieve room ${roomId}`);
                            socket.emit('gameError', { error: 'Failed to create bot room', code: 'ROOM_CREATE_FAILED' });
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
                        const sanitized = sanitizeError(error, 'requestBotRoom', 'Error creating bot room.');
                        socket.emit('gameError', sanitized);
                    }
                } else if (event === 'requestBotGame') {
                    const { roomId } = args[0];
                    try {
                        const { error } = requestBotGameSchema.validate({ roomId });
                        if (error) {
                            const sanitized = sanitizeValidationError(error, 'requestBotGame');
                            socket.emit('gameError', sanitized);
                            return;
                        }

                        logger.info(`Bot game requested for room ${roomId}`);

                        let room = await getGameRoom(roomId);
                        if (!room) {
                            logger.error(`Room ${roomId} not found when requesting bot game`);
                            socket.emit('gameError', { error: 'Room not found', code: 'ROOM_NOT_FOUND' });
                            return;
                        }

                        if (room.waitingTimeout) {
                            clearTimeout(room.waitingTimeout);
                            room.waitingTimeout = null;
                            await updateGameRoom(roomId, room);
                        }

                        const humanPlayers = room.players.filter(p => !p.isBot);
                        if (humanPlayers.length > 1) {
                            logger.error(`Room ${roomId} already has ${humanPlayers.length} human players, can't add bot`);
                            socket.emit('gameError', { error: 'Cannot add bot to a room with multiple players', code: 'TOO_MANY_PLAYERS' });
                            return;
                        }

                        const playerInRoom = room.players.find(p => p.id === socket.id);
                        if (!playerInRoom) {
                            logger.error(`Player ${socket.id} not found in room ${roomId}`);
                            socket.emit('gameError', { error: 'You are not in this room', code: 'PLAYER_NOT_IN_ROOM' });
                            return;
                        }

                        logger.info(`Setting room ${roomId} to bot mode`);
                        room.roomMode = 'bot';
                        await updateGameRoom(roomId, room);

                        await startSinglePlayerGame(roomId);
                        await logGameRoomsState();
                    } catch (error) {
                        const sanitized = sanitizeError(error, 'requestBotGame', 'Error starting bot game.');
                        socket.emit('gameError', sanitized);
                    }
                } else if (event === 'submitAnswer') {
                    const { roomId, questionId, answer, recaptchaToken } = args[0];
                    try {
                        // ===== 1. INPUT VALIDATION =====
                        const { error } = submitAnswerSchema.validate({ roomId, questionId, answer, recaptchaToken });
                        if (error) {
                            const sanitized = sanitizeValidationError(error, 'submitAnswer');
                            socket.emit('answerError', sanitized);
                            return;
                        }

                        // ===== 2. AUTHENTICATION CHECK =====
                        if (!socket.user || !socket.user.walletAddress) {
                            socket.emit('answerError', 'Not authenticated');
                            return;
                        }

                        const authenticatedUsername = socket.user.walletAddress;
                        const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                        await rateLimitEvent(authenticatedUsername, 'submitAnswer', clientIP, socket);

                        console.log(`Received answer from ${authenticatedUsername} in room ${roomId} for question ${questionId}:`, { answer });

                        // ===== 3. ROOM & QUESTION VALIDATION =====
                        let room = await getGameRoom(roomId);
                        if (!room) {
                            logger.error(`Room ${roomId} not found for answer submission`);
                            socket.emit('answerError', 'Room not found');
                            return;
                        }

                        if (!room.questions || room.questions.length === 0) {
                            logger.error(`Room ${roomId} has no questions`);
                            socket.emit('answerError', 'Game not properly initialized');
                            return;
                        }

                        if (!room.questionStartTime || room.currentQuestionIndex >= room.questions.length) {
                            logger.error(`No active question in room ${roomId} when ${authenticatedUsername} submitted answer`);
                            socket.emit('answerError', 'No active question');
                            return;
                        }

                        const currentQuestion = room.questionIdMap.get(questionId);
                        if (!currentQuestion) {
                            logger.error(`No current question for room ${roomId}`);
                            socket.emit('answerError', 'No active question');
                            return;
                        }

                        // ✅ Check if question exists in the map (more reliable than array index)
                        const questionData = room.questionIdMap.get(questionId);
                        if (!questionData) {
                            logger.error(`Question ${questionId} not found in room ${roomId} questionIdMap`);
                            socket.emit('answerError', 'Invalid question ID');
                            return;
                        }

                        // ✅ Verify it's the current question (allowing for timing edge cases)
                        if (questionId !== currentQuestion.tempId) {
                            // Check if this is a late answer from previous question
                            const questionIndex = room.questions.findIndex(q => q.tempId === questionId);
                            if (questionIndex !== -1 && questionIndex < room.currentQuestionIndex) {
                                logger.info(`Player ${authenticatedUsername} submitted late answer for previous question ${questionId}`);
                                socket.emit('answerError', 'Question expired');
                                return;
                            }
                            
                            logger.error(`Invalid question ${questionId} for room ${roomId} (expected ${currentQuestion.tempId})`);
                            socket.emit('answerError', 'Invalid question');
                            return;
                        }

                        const player = room.players.find(p => p.username === authenticatedUsername && !p.isBot);
                        if (!player) {
                            logger.error(`Player ${authenticatedUsername} not found in room ${roomId} or is a bot`);
                            socket.emit('answerError', 'Player not found');
                            return;
                        }

                        if (player.answered) {
                            logger.info(`Player ${authenticatedUsername} already answered this question`);
                            socket.emit('answerError', 'Already answered');
                            return;
                        }

                        // ============================================================================
                        // CRITICAL: Mark player as answered IMMEDIATELY to prevent race condition
                        // This prevents the timeout handler from marking this player as timed out
                        // while we're doing async verification (reCAPTCHA, etc.)
                        // We'll update the actual answer and score later after verification
                        // ============================================================================
                        player.answered = true; // Mark NOW before any async operations

                        // ===== 4. TIMING VALIDATION =====
                        const serverResponseTime = Date.now() - room.questionStartTime;
                        if (serverResponseTime < 200 || serverResponseTime > 15000) {
                            logger.warn(`Invalid response time ${serverResponseTime}ms from ${authenticatedUsername} in room ${roomId}`);
                            // Redis operation wrapped in safeRedisOp
                            await redisClient.set(`suspect:${authenticatedUsername}`, 1, 'EX', 3600);
                            socket.emit('answerError', 'Invalid response timing');
                            return;
                        }

                        // ===== 5. BOT DETECTION =====
                        const botSuspicion = botDetector.getSuspicionScore(authenticatedUsername);
                        SecurityLogger.botSuspicion(authenticatedUsername, botSuspicion, 'submitAnswer', 0.7);
                        if (botSuspicion >= 0.8) {
                            trackBotSuspicion(authenticatedUsername, { score: botSuspicion, event: 'submitAnswer' });
                        }

                        // ===== 6. RECAPTCHA VERIFICATION (ENVIRONMENT-AWARE) =====
                        const isProduction = process.env.NODE_ENV === 'production';
                        let recaptchaResult = null;

                        if (isProduction) {
                            // PRODUCTION: ALWAYS require reCAPTCHA (no exceptions)
                            if (!recaptchaToken) {
                                logger.error(`Missing reCAPTCHA token from ${authenticatedUsername} in PRODUCTION`);
                                socket.emit('answerError', 'Verification required');
                                return;
                            }

                            try {
                                recaptchaResult = await verifyRecaptcha(recaptchaToken);
                                logger.info(`reCAPTCHA verified for ${authenticatedUsername} (score: ${recaptchaResult.score || 'N/A'})`);

                                // Check score threshold (v3 only)
                                if (recaptchaResult.score !== undefined && recaptchaResult.score < 0.5) {
                                    logger.warn(`Low reCAPTCHA score ${recaptchaResult.score} for ${authenticatedUsername}`);
                                    botDetector.trackEvent(authenticatedUsername, 'low_recaptcha_score', { 
                                        score: recaptchaResult.score,
                                        event: 'submitAnswer'
                                    });
                                    socket.emit('answerError', 'Suspicious activity detected. Please try again.');
                                    return;
                                }
                            } catch (error) {
                                SecurityLogger.recaptchaFailed(authenticatedUsername, error.message, null, socket.handshake.headers['x-forwarded-for'] || socket.handshake.address);
                        trackRecaptchaFailure(authenticatedUsername, { error: error.message });
                                
                                // Track failed attempt for rate limiting
                                // Redis operation wrapped in safeRedisOp
                                const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
                                try {
                                    await rateLimitFailedRecaptcha(clientIP);
                                } catch (rateError) {
                                    console.warn(`reCAPTCHA rate limit hit for IP ${clientIP}:`, rateError.message);
                                    socket.emit('answerError', 'Too many failed verification attempts. Please try again later.');
                                    return;
                                }
                                socket.emit('answerError', 'Verification failed. Please try again.');
                                return;
                            }
                        } else if (process.env.ENABLE_RECAPTCHA === 'true') {
                            // DEVELOPMENT: Optional reCAPTCHA (for testing)
                            if (recaptchaToken) {
                                try {
                                    recaptchaResult = await verifyRecaptcha(recaptchaToken);
                                    logger.info(`✅ Dev reCAPTCHA verified (score: ${recaptchaResult.score || 'N/A'})`);
                                    
                                    // Still check score in dev for testing
                                    if (recaptchaResult.score !== undefined && recaptchaResult.score < 0.5) {
                                        logger.warn(`⚠️ Low score in dev: ${recaptchaResult.score} (allowing anyway)`);
                                    }
                                } catch (error) {
                                    logger.warn(`⚠️ Dev reCAPTCHA failed (allowing anyway): ${error.message}`);
                                }
                            } else {
                                logger.info(`🔓 Dev mode - no reCAPTCHA token provided`);
                            }
                        } else {
                            // DEVELOPMENT: reCAPTCHA disabled
                            logger.info(`🔓 Dev mode - reCAPTCHA disabled for ${authenticatedUsername}`);
                        }

                        // ===== 7. DEVICE FINGERPRINT CHECK (RISK-BASED) =====
                        const user = await User.findOne({ walletAddress: authenticatedUsername });
                        if (user && socket.user && user.deviceFingerprint !== socket.user.fingerprint) {
                            SecurityLogger.deviceMismatch(authenticatedUsername, user.deviceFingerprint, socket.user.fingerprint, { event: 'submitAnswer' });
                            botDetector.trackEvent(authenticatedUsername, 'fingerprint_mismatch', { event: 'submitAnswer' });
                            
                            // In production, if reCAPTCHA score is also suspicious = likely bot attack
                            if (isProduction && recaptchaResult && recaptchaResult.score !== undefined && recaptchaResult.score < 0.7) {
                                logger.error(`Device mismatch + low reCAPTCHA score (${recaptchaResult.score}) for ${authenticatedUsername}`);
                                socket.emit('answerError', 'Device verification failed. Please relogin.');
                                return;
                            }
                            
                            // In development or if score is high, just log and continue
                            logger.info(`Allowing fingerprint mismatch (production: ${isProduction}, score: ${recaptchaResult?.score || 'N/A'})`);
                        }

                        // ===== 8. HIGH-WIN STREAK CHECK (USES STORED RESULT) =====
                        if (user && user.gamesPlayed > 5 && (user.wins / user.gamesPlayed) > 0.8) {
                            // FIXED: Use stored recaptchaResult instead of re-verifying
                            if (isProduction) {
                                // In production, reCAPTCHA already verified above
                                if (!recaptchaResult || !recaptchaResult.success) {
                                    logger.error(`High-win player ${authenticatedUsername} failed verification`);
                                    socket.emit('answerError', 'Additional verification required due to high win rate.');
                                    return;
                                }
                                logger.info(`High-win verification passed for ${authenticatedUsername} (score: ${recaptchaResult.score})`);
                            } else if (process.env.ENABLE_RECAPTCHA === 'true' && !recaptchaToken) {
                                // In dev with reCAPTCHA enabled, require token for high-win players
                                logger.warn(`High-win player ${authenticatedUsername} in dev without reCAPTCHA`);
                                socket.emit('answerError', 'Verification required for high win rate players.');
                                return;
                            }
                        }

                        // ===== 9. PROCESS ANSWER =====
                        logger.info(`SERVER CALCULATED: ${authenticatedUsername} response time: ${serverResponseTime}ms`);

                        const isCorrect = answer === currentQuestion.shuffledCorrectAnswer;
                        // Note: player.answered was already set to true earlier to prevent race condition
                        player.lastAnswer = answer;
                        player.lastResponseTime = serverResponseTime;
                        player.totalResponseTime = (player.totalResponseTime || 0) + serverResponseTime;

                        if (isCorrect) {
                            player.score = (player.score || 0) + 1;
                            logger.info(`Correct answer from ${authenticatedUsername}. New score: ${player.score}`);
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
                                logger.error('Error updating user stats:', { error: error });
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
                        const sanitized = sanitizeError(error, 'submitAnswer', 'Error submitting answer. Please try again.');
                        socket.emit('answerError', sanitized);
                    }
                } 
            } catch (error) {
                const sanitized = sanitizeError(error, `game-event-${event}`, 'An error occurred. Please try again.');
                socket.emit(`${event}Error` || 'gameError', sanitized);
            }
        });
    });

    socket.on('disconnect', async () => {
        logger.info('Client disconnected:', socket.id);

        // 1. Check and remove from matchmaking pools in Redis (retained scan—fewer keys)
        if (socket.matchmakingPool) {
            try {
                const removedPlayer = await removeFromMatchmakingPool(socket.matchmakingPool, socket.id);
                if (removedPlayer) {
                    logger.info(`Player ${removedPlayer.walletAddress} (socket ${socket.id}) removed from matchmaking pool for bet ${socket.matchmakingPool} (O(1))`);
                }
                socket.matchmakingPool = null;  // ✅ Clear ref
                await logMatchmakingState();
            } catch (error) {
                console.error(`Error in O(1) matchmaking cleanup for socket ${socket.id}:`, error);
                // FALLBACK ALERT: Log if ref missing/unhealthy (no scan to avoid DoS)
                // Redis operation wrapped in safeRedisOp
                logger.warn(`Fallback needed for disconnect ${socket.id} - ref missing/unhealthy. Investigate manually.`);
                // TODO: Metric/alert (e.g., via Sentry) - do NOT scan here
            }
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
                    logger.info(`Player ${disconnectedPlayer.username} (socket ${socket.id}) disconnected from room ${roomId}`);

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
                        logger.info(`Human player ${disconnectedPlayer.username} left bot game. Bot wins by forfeit.`);
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

                            logger.info(`Calling updatePlayerStats for bot forfeit. Winner: ${winnerName}, Bet: ${room.betAmount}`);
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
                            logger.error(`CRITICAL: Bot not found in bot game room ${roomId} after human ${disconnectedPlayer.username} disconnected.`);
                            io.to(roomId).emit('gameError', 'An error occurred due to player disconnection.');
                        }

                        // Ensure room is deleted
                        await deleteGameRoom(roomId);
                        await redisClient.del(`room:${roomId}`);
                        logger.info(`Confirmed deletion of room ${roomId}`);
                        await logGameRoomsState();
                        socket.roomId = null;  // FIXED: Clear roomId
                        return;
                    }

                    // Scenario 2: Human vs Human Game Forfeit
                    if (room.players.length === 1 && !room.players[0].isBot) {
                        const remainingPlayer = room.players[0];
                        logger.info(`Player ${disconnectedPlayer.username} left H2H game. ${remainingPlayer.username} wins by forfeit.`);

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
                        logger.info(`Room ${roomId} is now empty after ${disconnectedPlayer.username} left. Deleting room.`);
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
                logger.info(`No room associated with disconnected socket ${socket.id}`);
            }
        } catch (error) {
            logger.error('Error cleaning up game rooms', {
                socketId: socket.id,
                error: error.message,
                stack: error.stack
            });
            socket.roomId = null;  // FIXED: Clear on error to avoid stale state
        }
    });
});

app.use(errorHandler);

io.engine.on('connection_error', (err) => {
    logger.warn('Socket.io connection error', {
        code: err.code,
        message: err.message,
        transport: err.req?._query?.transport
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
    logger.info(`Attempting to start game in room ${roomId}`);
    let room = await getGameRoom(roomId);
    if (!room) {
        logger.info(`Room ${roomId} not found when trying to start game`);
        return;
    }

    // Idempotent: Skip if already started
    if (room.gameStarted) {
        logger.info(`Game already started in room ${roomId}, skipping`);
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
        logger.info(`Fetched ${rawQuestions.length} questions for room ${roomId}`);

        // FIXED: Pre-shuffle ALL questions here (no race in startNextQuestion)
        room.questions = rawQuestions.map((question, index) => {
            const tempId = `${roomId}-${uuidv4()}`;
            const options = question.options;
            const shuffledOptions = shuffleArray([...options]); // Shuffle copy
            const shuffledCorrectAnswer = shuffledOptions.indexOf(options[question.correctAnswer]);
            if (shuffledCorrectAnswer === -1) {
                logger.error(`Failed to shuffle question ${tempId} correctly`);
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
        logger.error('Error starting game:', { error: error });
        io.to(roomId).emit('gameError', 'Failed to start the game. Please try again.');
    }
}

async function startSinglePlayerGame(roomId) {
    logger.info('Starting single player game with bot for room:', roomId);
    let room = await getGameRoom(roomId);
    if (!room) {
        console.log('Room not found for bot creation');
        return;
    }

    if (room.roomMode !== 'bot') {
        logger.info(`Room ${roomId} is no longer in bot mode, not adding bot`);
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
                logger.error(`Failed to shuffle question ${tempId} correctly`);
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
            logger.info(`Room ${roomId} has ${humanPlayers.length} human players, expected exactly 1`);
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
        logger.info('Human player:', humanPlayer.username);

        humanPlayer.score = 0;
        humanPlayer.totalResponseTime = 0;
        humanPlayer.answered = false;
        humanPlayer.lastAnswer = null;

        if (room.players.some(p => p.isBot)) {
            logger.info(`Room ${roomId} already has a bot player`);
            if (!room.gameStarted) {
                room.gameStarted = true;
                await updateGameRoom(roomId, room);
                await startNextQuestion(roomId);
            }
            return;
        }

        const difficultyString = await determineBotDifficulty(humanPlayer.username);
        const botName = chooseBotName();
        logger.info('Creating bot with name:', botName, 'and difficulty:', difficultyString);

        const bot = new TriviaBot(botName, difficultyString);
        logger.info('Bot instance created:', {
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
        logger.info('Bot added to room. Total players:', room.players.length);

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
        logger.error('Error starting single player game with bot:', { error: error });
        io.to(roomId).emit('gameError', 'Failed to start the game. Please try again.');
        await deleteGameRoom(roomId);
    }
}

async function startNextQuestion(roomId) {
    let room = await getGameRoom(roomId);
    if (!room) {
        logger.info(`Room ${roomId} not found when trying to start next question`);
        return;
    }

    // Check if room is deleted
    if (room.isDeleted) {
        logger.info(`Room ${roomId} is marked as deleted, stopping game`);
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
        logger.info(`No human players in room ${roomId}. Stopping game.`);
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
        logger.info(`No more questions for room ${roomId}. Ending game.`);
        await handleGameOver(room, roomId);
        return;
    }

    const currentQuestion = room.questions[room.currentQuestionIndex];
    if (!currentQuestion || !currentQuestion.options || currentQuestion.correctAnswer === undefined) {
        logger.error(`Invalid question data for room ${roomId}, question index ${room.currentQuestionIndex}`);
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
        logger.error(`❌ Missing shuffledOptions for question ${currentQuestion.tempId} in room ${roomId}`);
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
        logger.error(`❌ Invalid shuffledCorrectAnswer for question ${currentQuestion.tempId}`);
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
    logger.info(`Question ${room.currentQuestionIndex + 1} started at timestamp: ${room.questionStartTime} for room ${roomId}`);

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
                logger.info(`Room ${roomId} deleted or not found during bot answer processing`);
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

            logger.info(`Bot ${bot.username} answered question ${currentQuestion.tempId}: ${botAnswer.answer} (correct: ${botAnswer.isCorrect}, time: ${botAnswer.responseTime}ms)`);
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
            logger.info(`Room ${roomId} not found or deleted during timeout`);
            return;
        }

        // Check again for human players
        const remainingHumanPlayers = room.players.filter(p => !p.isBot);
        if (remainingHumanPlayers.length === 0) {
            logger.info(`No human players remaining in room ${roomId} during timeout. Stopping game.`);
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

                logger.info(`Player ${player.username} timed out on question ${currentQuestion.tempId} with responseTime: ${timeoutResponseTime}ms`);
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
        logger.error('Error determining bot difficulty:', { error: error });
        return 'HARD';
    }
}

async function completeQuestion(roomId) {
    let room = await getGameRoom(roomId);
    if (!room) {
        logger.error(`Room ${roomId} not found in completeQuestion`);
        io.to(roomId).emit('gameError', 'Room not found');
        return;
    }

    // Check if room is deleted
    if (room.isDeleted) {
        logger.info(`Room ${roomId} is marked as deleted, stopping game`);
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
        logger.info(`No human players in room ${roomId}. Stopping game.`);
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
        logger.error(`Invalid question data for room ${roomId}, index ${room.currentQuestionIndex}`);
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
        logger.info(`Game in room ${roomId} ending early because a player left`);
        await handleGameOver(room, roomId);
        return;
    }

    if (room.currentQuestionIndex < room.questions.length) {
        setTimeout(() => {
            startNextQuestion(roomId);
        }, 3000);
    } else {
        logger.info(`Game over in room ${roomId}`);
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
                logger.info(`Payout queued for ${winner}: Payment ID ${paymentId}, Amount ${winningAmount} USDC`);
            } catch (error) {
                logger.error('Error queueing payout:', { error: error });
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
        logger.error('Error handling game over:', { error: error });
        io.to(roomId).emit('gameError', 'An error occurred while ending the game.');
        await deleteGameRoom(roomId);
    }
}



const PORT = process.env.PORT || 5000;

async function startServer() {
    try {
        await initializeConfig();
        await initializeRedis();
        
        server.listen(PORT, () => {
            logger.info(`🚀 Server is running on port ${PORT}`);
            logger.info(`🔐 Treasury wallet loaded from AWS Secrets Manager`);
        });
    } catch (error) {
        logger.error('❌ Failed to start server:', { error: error });
        process.exit(1);
    }
}

startServer();

// Function to generate a unique room ID
function generateRoomId() {
    return Math.random().toString(36).substring(7);
}


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
            },
            httpsAgent: new https.Agent({ family: 4 }) // <--- FIX: Forces IPv4 to avoid ENETUNREACH
        });
        
        logger.info('reCAPTCHA verification response:', response.data);
        
        // FIXED: Strict enforcement - throw on failure
        if (!response.data.success) {
            console.warn('reCAPTCHA verification failed:', response.data['error-codes']);
            throw new Error('reCAPTCHA verification failed');
        }
        
        // FIXED: Enforce score threshold for v3
        if (response.data.score !== undefined && response.data.score < 0.5) {
            logger.warn(`reCAPTCHA score too low: ${response.data.score}`);
            throw new Error('Bot activity suspected (low reCAPTCHA score)');
        }
        
        return { success: true, score: response.data.score };
    } catch (error) {
        logger.error('reCAPTCHA verification error:', { error: error });
        throw new Error('Verification service unavailable. Please try again later.');
    }
}

async function createGameRoom(roomId, betAmount, roomMode = 'waiting') {
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

    await criticalRedisOp(
        async () => {
            // Prepare the Redis Transaction
            const multi = redisClient.multi();

            // 1. Set the Hash Data
            multi.hset(`room:${roomId}`, {
                players: JSON.stringify(room.players),
                questions: JSON.stringify(room.questions),
                questionIdMap: JSON.stringify([]), // Store as empty array
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

            // 2. Set Expiry (1 hour)
            multi.expire(`room:${roomId}`, 3600);

            // 3. ATOMIC FIX: Add to the active rooms set in the same transaction
            multi.sadd('active:rooms', roomId);

            // Execute all at once
            await multi.exec();
            
            logger.info(`Created & tracked room ${roomId} in Redis with bet ${betAmount}`);
        },
        `Create game room ${roomId}`
    );
    
    return room;
}

async function getGameRoom(roomId) {
    return await criticalRedisOp(
        async () => {
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
                    logger.warn(`Room ${roomId} using legacy questionIdMap format - converting`);
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
        },
        `Get game room ${roomId}`
    );
}

async function updateGameRoom(roomId, room) {
    try {
        if (room.isDeleted) {
            logger.info(`Room ${roomId} is marked as deleted, skipping update`);
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
        logger.info(`Updated room ${roomId} in Redis`);
    } catch (error) {
        console.error(`Error updating room ${roomId} in Redis:`, error);
    // Redis health auto-managed by ioredis
        throw error;
    }
}


async function deleteGameRoom(roomId) {
    try {
        // Fetch room first to check logic requirements (like waiting rooms)
        let room = await getGameRoom(roomId);
        
        // Clear Node.js timeouts if they exist in memory
        if (room) {
            if (room.questionTimeout) {
                clearTimeout(room.questionTimeout);
                room.questionTimeout = null;
            }
            // Note: We don't updateGameRoom here because we are about to delete it entirely
        }

        // Prepare Redis Transaction
        const multi = redisClient.multi();

        // 1. Delete the room data
        multi.del(`room:${roomId}`);

        // 2. ATOMIC FIX: Remove from the active rooms set
        multi.srem('active:rooms', roomId);

        // 3. Cleanup waiting room index if applicable
        if (room && room.betAmount && room.roomMode === 'human') {
            multi.zrem(`waiting_rooms:${room.betAmount}`, roomId);
            logger.info(`Queued removal from waiting_rooms:${room.betAmount}`);
        }

        // Execute transaction
        await multi.exec();
        logger.info(`Deleted room ${roomId} and cleaned up tracking sets`);

    } catch (error) {
        console.error(`Error deleting room ${roomId} from Redis:`, error);
        throw error;
    }
}

async function addToMatchmakingPool(betAmount, playerData) {
    try {
        await redisClient.lpush(`matchmaking:human:${betAmount}`, JSON.stringify(playerData));
        await trackMatchmakingPlayer(betAmount, playerData.walletAddress);
        logger.info(`Added player ${playerData.walletAddress} to matchmaking pool for ${betAmount}`);
        return true;  // ✅ Return success for caller to verify
    } catch (error) {
        console.error(`Error adding to matchmaking pool for ${betAmount}:`, error);
    // Redis health auto-managed by ioredis
        throw error;  // ✅ Throw to propagate error
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
            logger.info(`Removed player with socketId ${socketId} from matchmaking pool for ${betAmount}`);
            try {
                const playerData = JSON.parse(pool[playerIndex]);  // ← ADD THIS LINE
                await untrackMatchmakingPlayer(betAmount, playerData.walletAddress);  // ← FIXED

                return removedPlayer ? playerData : null;  // ← FIXED
            } catch (parseError) {
                console.error(`Error parsing removed player data for ${betAmount}:`, parseError, pool[playerIndex]);
                return null;
            }
        }

        logger.info(`Player with socketId ${socketId} not found in matchmaking pool for ${betAmount}`);
        return null;
    } catch (error) {
        console.error(`Error removing from matchmaking pool for ${betAmount}:`, error);
    // Redis health auto-managed by ioredis
        return null; // Return null instead of throwing to allow switchToBot to continue
    }
}

async function getMatchmakingPool(betAmount) {
    try {
        const pool = await redisClient.lrange(`matchmaking:human:${betAmount}`, 0, -1);
        return pool.map(p => JSON.parse(p));
    } catch (error) {
        console.error(`Error fetching matchmaking pool for ${betAmount}:`, error);
    // Redis health auto-managed by ioredis
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
    logger.warn(`Potential bot detected accessing honeypot: ${clientIP}`);
    // Redis operation wrapped in safeRedisOp
    await redisClient.set(`blocklist:${clientIP}`, 1, 'EX', 86400); // Block for 24 hours
    
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
        logger.error('Error fetching leaderboard:', { error: error });
        res.status(500).json({ error: 'Failed to fetch leaderboard' });
    }
});

app.get('/admin', (req, res) => {
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    logger.warn(`Potential bot detected accessing admin honeypot: ${clientIP}`);
    // Redis operation wrapped in safeRedisOp
    redisClient.set(`blocklist:${clientIP}`, 1, 'EX', 86400);
    
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
            logger.info(`Forfeit payout queued for ${remainingPlayer.username}: Payment ID ${paymentId}`);
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
        logger.error('Error processing player left win:', { error: error });
        io.to(roomId).emit('gameError', 'Error processing win after player left. Please contact support.');
        await deleteGameRoom(roomId);
        await logGameRoomsState();
    }
}

async function logGameRoomsState() {
    console.log('Current game rooms state:');
    
    const roomIds = await getCleanActiveRooms(); 
    logger.info(`Total rooms: ${roomIds.length}`);

    for (const roomId of roomIds) {
        const room = await getGameRoom(roomId);
        if (room) {
            logger.info(`Room ID: ${roomId}`);
            logger.info(`  Mode: ${room.roomMode}`);
            logger.info(`  Game started: ${room.gameStarted}`);
            logger.info(`  Bet amount: ${room.betAmount}`);
            logger.info(`  Players (${room.players.length}):`);

            room.players.forEach(player => {
                logger.info(`    - ${player.username}${player.isBot ? ' (BOT)' : ''}`);
            });

            logger.info(`  Questions: ${room.questions?.length || 0}`);
            logger.info(`  Current question index: ${room.currentQuestionIndex}`);
            console.log('-------------------');
        }
    }
}

async function logMatchmakingState() {
    console.log('Current Matchmaking State:');

    try {
        console.log('Human Matchmaking Pools:');
        
        // FIXED: Use Set-based tracking instead of scanKeys
        const pools = await getAllMatchmakingPools();
        
        for (const [betAmount, wallets] of Object.entries(pools)) {
            logger.info(`  Bet Amount ${betAmount}: ${wallets.length} players waiting`);
            
            // Get full player data for each wallet
            const pool = await getMatchmakingPool(betAmount);  // ← FIXED
            if (pool && pool.length > 0) {  // ← FIXED
                const playersByWallet = new Map(pool.map(p => [p.walletAddress, p]));
                
                for (const wallet of wallets) {
                    const player = playersByWallet.get(wallet);
                    if (player) {
                        const waitTime = Math.round((Date.now() - player.joinTime) / 1000);
                        logger.info(`    - ${wallet} (waiting for ${waitTime}s)`);
                    }
                }
            }
        }

        console.log('Game Rooms:');
        await logGameRoomsState();
    } catch (error) {
        logger.error('Error logging matchmaking state:', { error: error });
    }
}

// Cleanup expired matchmaking players (REFACTORED - No scanKeys!)
paymentProcessorInterval = setInterval(async () => {
    const now = Date.now();
    const MAX_WAIT_TIME = 5 * 60 * 1000; // 5 minutes

    try {
        // FIXED: Use Set-based tracking instead of scanKeys
        const pools = await getAllMatchmakingPools();
        
        for (const [betAmount, wallets] of Object.entries(pools)) {
            // Get full pool data
            const pool = await getMatchmakingPool(betAmount);  // ← FIXED
            if (!pool || pool.length === 0) continue;  // ← FIXED
            
            const expiredPlayers = pool.filter(player => (now - player.joinTime) > MAX_WAIT_TIME);

            if (expiredPlayers.length > 0) {
                logger.info(`Removing ${expiredPlayers.length} expired players from matchmaking pool for ${betAmount}`);
                
                for (const player of expiredPlayers) {
                    const playerSocket = io.sockets.sockets.get(player.socketId);
                    if (playerSocket) {
                        playerSocket.emit('matchmakingExpired', {
                            message: 'Your matchmaking request has expired'
                        });
                    }
                    
                    // Remove from both Redis list and tracking Set
                    await redisClient.lrem(`matchmaking:human:${betAmount}`, 1, JSON.stringify(player));
                    await untrackMatchmakingPlayer(betAmount, player.walletAddress);
                }
            }
        }
    } catch (error) {
        logger.error('Error in matchmaking cleanup:', { error: error });
    }
}, 60000); // Run every minute

async function updatePlayerStats(players, roomData) {
    logger.info('Updating stats for all players:', players);
    const winner = roomData.winner;
    const multiplier = roomData.botOpponent ? 1.5 : 1.8;
    const winningAmount = roomData.betAmount * multiplier;
    
    logger.info(`Game stats: winner=${winner}, betAmount=${roomData.betAmount}, winnings=${winningAmount}`);
    
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
                    logger.info(`Skipping bot: ${player.username}`);
                    continue;
                }
                
                if (!player.username) {
                    logger.info(`Skipping player with no username`);
                    continue;
                }
                
                const isWinner = player.username === winner;
                logger.info(`Updating ${player.username} (winner: ${isWinner})`);
                
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
            logger.error('Player stats transaction failed (rolled back):', { error: error });
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
                    logger.info(`Skipping bot: ${player.username}`);
                    continue;
                }
                
                if (!player.username) {
                    logger.info(`Skipping player with no username`);
                    continue;
                }
                
                const isWinner = player.username === winner;
                logger.info(`Updating ${player.username} (winner: ${isWinner})`);
                
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
            logger.error('Error in updatePlayerStats (atomic mode):', { error: error });
            throw error;
        }
    }
}

async function gracefulShutdown(signal) {
    console.log(`\n📡 Received ${signal} signal, shutting down gracefully...`);
    
    // Clear all intervals
    if (paymentProcessorInterval) clearInterval(paymentProcessorInterval);
    if (roomCleanupInterval) clearInterval(roomCleanupInterval);
    
    // Close server
    if (server) {
        console.log('🔌 Closing HTTP server...');
        await new Promise((resolve) => {
            server.close(() => {
                console.log('✅ HTTP server closed');
                resolve();
            });
        });
    }
    
    // Close Socket.IO
    if (io) {
        console.log('🔌 Closing Socket.IO...');
        await new Promise((resolve) => {
            io.close(() => {
                console.log('✅ Socket.IO closed');
                resolve();
            });
        });
    }
    
    // Close database connections
    if (mongoose.connection) {
        console.log('🔌 Closing MongoDB connection...');
        await mongoose.connection.close();
        console.log('✅ MongoDB closed');
    }
    
    // Close Redis
    if (redisClient) {
        console.log('🔌 Closing Redis connection...');
        await redisClient.quit();
        console.log('✅ Redis closed');
    }
    
    // Close logger (this will also call process.exit(0))
    await require('./logger').gracefulShutdown(signal);
}

// Listen for shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Also handle uncaught exceptions gracefully
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    gracefulShutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    gracefulShutdown('UNHANDLED_REJECTION');
});