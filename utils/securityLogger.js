// utils/securityLogger.js
// Pre-built security event logging templates
// Drop-in replacements for existing console.log statements

const logger = require('../logger');

// ============================================================================
// AUTHENTICATION EVENTS
// ============================================================================

const SecurityLogger = {
    
    // Login success
    loginSuccess: (walletAddress, sessionData, req) => {
        logger.auth('login_success', {
            walletAddress,
            sessionId: sessionData.sessionId?.substring(0, 8),
            ip: req.headers['x-forwarded-for'] || req.ip,
            userAgent: req.headers['user-agent'],
            deviceFingerprint: sessionData.fingerprint,
            loginTime: new Date().toISOString()
        });
    },
    
    // Login failed
    loginFailed: (walletAddress, reason, req) => {
        logger.security('auth_failed', {
            walletAddress,
            reason,
            ip: req.headers['x-forwarded-for'] || req.ip,
            userAgent: req.headers['user-agent'],
            timestamp: new Date().toISOString()
        });
    },
    
    // Session expired
    sessionExpired: (walletAddress, sessionAge) => {
        logger.security('session_expired', {
            walletAddress,
            sessionAge,
            sessionAgeMinutes: Math.round(sessionAge / 60000),
            timestamp: new Date().toISOString()
        });
    },
    
    // Session too old
    sessionTooOld: (walletAddress, sessionAge, maxAge) => {
        logger.security('session_too_old', {
            walletAddress,
            sessionAge,
            maxAge,
            sessionAgeMinutes: Math.round(sessionAge / 60000),
            timestamp: new Date().toISOString()
        });
    },
    
    // Invalid token
    invalidToken: (walletAddress, reason, context = {}) => {
        logger.security('invalid_token', {
            walletAddress,
            reason,
            ...context,
            timestamp: new Date().toISOString()
        });
    },
    
    // Socket connection authenticated
    socketAuthSuccess: (walletAddress, socket) => {
        logger.auth('socket_authenticated', {
            walletAddress,
            socketId: socket.id,
            ip: socket.handshake.headers['x-forwarded-for'] || socket.handshake.address,
            userAgent: socket.handshake.headers['user-agent'],
            transport: socket.conn.transport.name,
            timestamp: new Date().toISOString()
        });
    },
    
    // Socket connection failed auth
    socketAuthFailed: (reason, socket, walletAddress = null) => {
        logger.security('socket_auth_failed', {
            reason,
            walletAddress,
            socketId: socket.id,
            ip: socket.handshake.headers['x-forwarded-for'] || socket.handshake.address,
            timestamp: new Date().toISOString()
        });
    },
    
    // Device fingerprint mismatch
    deviceMismatch: (walletAddress, storedFingerprint, currentFingerprint, context = {}) => {
        logger.security('device_mismatch', {
            walletAddress,
            storedFingerprint,
            currentFingerprint,
            ...context,
            timestamp: new Date().toISOString()
        });
    },
    
    // ========================================================================
    // VALIDATION EVENTS
    // ========================================================================
    
    // Validation failure
    validationFailure: (identifier, eventName, error, failureCount = 1) => {
        logger.security('validation_failure', {
            identifier,
            eventName,
            error,
            failureCount,
            timestamp: new Date().toISOString()
        });
    },
    
    // Auto-block due to validation abuse
    autoBlocked: (identifier, reason, violationCount, recentEvents = []) => {
        logger.security('auto_blocked', {
            identifier,
            reason,
            violationCount,
            recentEvents: recentEvents.slice(-10), // Last 10 events
            timestamp: new Date().toISOString()
        });
    },
    
    // Input validation error
    inputValidationError: (eventName, fields, walletAddress = null) => {
        logger.security('input_validation_error', {
            eventName,
            invalidFields: fields,
            walletAddress,
            timestamp: new Date().toISOString()
        });
    },
    
    // ========================================================================
    // RATE LIMITING
    // ========================================================================
    
    // Rate limit exceeded
    rateLimitExceeded: (identifier, eventName, limit, window, consumedPoints = null) => {
        logger.security('rate_limit_exceeded', {
            identifier,
            eventName,
            limit,
            window,
            consumedPoints,
            timestamp: new Date().toISOString()
        });
    },
    
    // Rate limit warning (approaching limit)
    rateLimitWarning: (identifier, eventName, consumedPoints, limit) => {
        logger.security('rate_limit_warning', {
            identifier,
            eventName,
            consumedPoints,
            limit,
            percentage: Math.round((consumedPoints / limit) * 100),
            timestamp: new Date().toISOString()
        });
    },
    
    // ========================================================================
    // RECAPTCHA / BOT DETECTION
    // ========================================================================
    
    // reCAPTCHA failed
    recaptchaFailed: (walletAddress, reason, score = null, ip = null) => {
        logger.security('recaptcha_failed', {
            walletAddress,
            reason,
            score,
            ip,
            timestamp: new Date().toISOString()
        });
    },
    
    // reCAPTCHA low score
    recaptchaLowScore: (walletAddress, score, threshold, eventName) => {
        logger.security('recaptcha_low_score', {
            walletAddress,
            score,
            threshold,
            eventName,
            timestamp: new Date().toISOString()
        });
    },
    
    // Bot suspicion detected
    botSuspicion: (walletAddress, suspicionScore, eventName, threshold = 0.7) => {
        logger.security('bot_suspicion_detected', {
            walletAddress,
            suspicionScore,
            eventName,
            threshold,
            timestamp: new Date().toISOString()
        });
    },
    
    // High win rate suspicion
    highWinRateSuspicion: (walletAddress, winRate, gamesPlayed) => {
        logger.security('high_win_rate_suspicion', {
            walletAddress,
            winRate: (winRate * 100).toFixed(2) + '%',
            gamesPlayed,
            timestamp: new Date().toISOString()
        });
    },
    
    // Invalid timing (too fast or too slow)
    invalidTiming: (walletAddress, responseTime, min, max, eventName) => {
        logger.security('invalid_timing', {
            walletAddress,
            responseTime,
            minAllowed: min,
            maxAllowed: max,
            eventName,
            timestamp: new Date().toISOString()
        });
    },
    
    // ========================================================================
    // TRANSACTION SECURITY
    // ========================================================================
    
    // Transaction verification failed
    transactionVerificationFailed: (signature, reason, walletAddress, retries = 0) => {
        logger.security('transaction_verification_failed', {
            signature,
            reason,
            walletAddress,
            retries,
            timestamp: new Date().toISOString()
        });
    },
    
    // Duplicate transaction attempt
    duplicateTransaction: (signature, walletAddress, originalTimestamp) => {
        logger.security('duplicate_transaction', {
            signature,
            walletAddress,
            originalTimestamp,
            timeSinceOriginal: Date.now() - new Date(originalTimestamp).getTime(),
            timestamp: new Date().toISOString()
        });
    },
    
    // Missing transaction memo
    missingMemo: (signature, walletAddress) => {
        logger.security('missing_transaction_memo', {
            signature,
            walletAddress,
            timestamp: new Date().toISOString()
        });
    },
    
    // ========================================================================
    // SUSPICIOUS ACTIVITY
    // ========================================================================
    
    // Multiple failed attempts
    multipleFailedAttempts: (identifier, eventName, count, timeWindow) => {
        logger.security('multiple_failed_attempts', {
            identifier,
            eventName,
            attemptCount: count,
            timeWindow,
            timestamp: new Date().toISOString()
        });
    },
    
    // Concurrent sessions detected
    concurrentSessions: (walletAddress, sessionIds, ips) => {
        logger.security('concurrent_sessions', {
            walletAddress,
            sessionCount: sessionIds.length,
            sessionIds: sessionIds.map(s => s.substring(0, 8)),
            ips,
            timestamp: new Date().toISOString()
        });
    },
    
    // Unauthorized access attempt
    unauthorizedAccess: (walletAddress, resource, action, ip = null) => {
        logger.security('unauthorized_access', {
            walletAddress,
            resource,
            action,
            ip,
            timestamp: new Date().toISOString()
        });
    },
    
    // Repeat offender
    repeatOffender: (identifier, offenseCount, offenseType) => {
        logger.security('repeat_offender', {
            identifier,
            offenseCount,
            offenseType,
            timestamp: new Date().toISOString()
        });
    }
};

// ============================================================================
// AUDIT EVENT TEMPLATES
// ============================================================================

const AuditLogger = {
    
    // Transaction verified
    transactionVerified: (walletAddress, amount, signature, treasuryWallet, nonce = null, ip = null) => {
        logger.audit('transaction_verified', {
            walletAddress,
            amount,
            signature,
            treasuryWallet,
            nonce,
            ip,
            timestamp: new Date().toISOString()
        });
    },
    
    // Game started
    gameStarted: (roomId, players, betAmount, gameMode) => {
        logger.audit('game_started', {
            roomId,
            playerCount: players.length,
            players: players.map(p => ({
                wallet: p.username,
                isBot: p.isBot || false
            })),
            betAmount,
            gameMode,
            timestamp: new Date().toISOString()
        });
    },
    
    // Game completed
    gameCompleted: (roomId, winner, loser, betAmount, winnings, gameMode, duration) => {
        logger.audit('game_completed', {
            roomId,
            winner,
            loser,
            betAmount,
            winnings,
            gameMode,
            duration,
            timestamp: new Date().toISOString()
        });
    },
    
    // Payment processed
    paymentProcessed: (walletAddress, amount, signature, status) => {
        logger.audit('payment_processed', {
            walletAddress,
            amount,
            signature,
            status,
            timestamp: new Date().toISOString()
        });
    },
    
    // Virtual balance updated
    balanceUpdated: (walletAddress, oldBalance, newBalance, reason, amount) => {
        logger.audit('balance_updated', {
            walletAddress,
            oldBalance,
            newBalance,
            change: newBalance - oldBalance,
            reason,
            amount,
            timestamp: new Date().toISOString()
        });
    },
    
    // User stats updated
    statsUpdated: (walletAddress, gamesPlayed, wins, totalWinnings) => {
        logger.audit('stats_updated', {
            walletAddress,
            gamesPlayed,
            wins,
            totalWinnings,
            winRate: gamesPlayed > 0 ? ((wins / gamesPlayed) * 100).toFixed(2) + '%' : '0%',
            timestamp: new Date().toISOString()
        });
    }
};

// ============================================================================
// PERFORMANCE TEMPLATES
// ============================================================================

const PerformanceLogger = {
    
    // Game start performance
    gameStart: (roomId, duration, questionCount, playerCount) => {
        logger.performance('game_start', duration, {
            roomId,
            questionCount,
            playerCount,
            timestamp: new Date().toISOString()
        });
    },
    
    // Answer processing performance
    answerProcessed: (roomId, walletAddress, duration, correct) => {
        logger.performance('answer_processed', duration, {
            roomId,
            walletAddress,
            correct,
            timestamp: new Date().toISOString()
        });
    },
    
    // Database query performance
    dbQuery: (operation, collection, duration, recordCount = null) => {
        logger.performance('db_query', duration, {
            operation,
            collection,
            recordCount,
            timestamp: new Date().toISOString()
        });
    },
    
    // Redis operation performance
    redisOp: (operation, key, duration) => {
        logger.performance('redis_operation', duration, {
            operation,
            key,
            timestamp: new Date().toISOString()
        });
    },
    
    // Transaction verification performance
    transactionVerification: (signature, duration, retries) => {
        logger.performance('transaction_verification', duration, {
            signature: signature.substring(0, 10) + '...',
            retries,
            timestamp: new Date().toISOString()
        });
    },
    
    // Slow operation warning
    slowOperation: (operation, duration, threshold, context = {}) => {
        logger.warn('Slow operation detected', {
            category: 'PERFORMANCE',
            operation,
            duration,
            threshold,
            slowBy: duration - threshold,
            ...context,
            timestamp: new Date().toISOString()
        });
    }
};

// ============================================================================
// EXPORT
// ============================================================================

module.exports = {
    SecurityLogger,
    AuditLogger,
    PerformanceLogger
};