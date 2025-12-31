// logger.js
// Production-ready Winston logging system for Trivia Game
// Complete implementation with security, audit, performance, and metric logging

const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');
const fs = require('fs');

// ============================================================================
// CONFIGURATION
// ============================================================================

const LOG_DIR = process.env.LOG_DIR || 'logs';
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const NODE_ENV = process.env.NODE_ENV || 'development';
const APP_VERSION = process.env.APP_VERSION || '1.0.0';
const SERVICE_NAME = 'trivia-game';

// Create logs directory if it doesn't exist
if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}

// ============================================================================
// CUSTOM LOG LEVELS
// ============================================================================

const customLevels = {
    levels: {
        fatal: 0,
        error: 1,
        warn: 2,
        security: 3,
        audit: 4,
        info: 5,
        performance: 6,
        debug: 7
    },
    colors: {
        fatal: 'red bold',
        error: 'red',
        warn: 'yellow',
        security: 'magenta',
        audit: 'cyan',
        info: 'green',
        performance: 'blue',
        debug: 'gray'
    }
};

winston.addColors(customLevels.colors);

// ============================================================================
// FORMATS
// ============================================================================

// Add hostname and process ID
const addMetadata = winston.format((info) => {
    info.hostname = require('os').hostname();
    info.pid = process.pid;
    return info;
});

// JSON format for production (structured, parseable)
const jsonFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
    addMetadata(),
    winston.format.errors({ stack: true }),
    winston.format.json()
);

// Human-readable format for development
const consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp({ format: 'HH:mm:ss.SSS' }),
    winston.format.errors({ stack: true }),
    winston.format.printf(({ timestamp, level, message, category, event, correlationId, walletAddress, ...meta }) => {
        let msg = `${timestamp} [${level}]`;
        
        // Add correlation ID (first 8 chars)
        if (correlationId) {
            msg += ` [${correlationId.substring(0, 8)}]`;
        }
        
        // Add category
        if (category) {
            msg += ` [${category}]`;
        }
        
        // Add event
        if (event) {
            msg += ` ${event}`;
        } else {
            msg += ` ${message}`;
        }
        
        // Add wallet if present
        if (walletAddress) {
            msg += ` (${walletAddress.substring(0, 6)}...)`;
        }
        
        // Add other metadata
        const metaKeys = Object.keys(meta).filter(k => 
            !['service', 'environment', 'version', 'timestamp', 'level', 'hostname', 'pid', 'stack'].includes(k)
        );
        if (metaKeys.length > 0) {
            const cleanMeta = {};
            metaKeys.forEach(k => cleanMeta[k] = meta[k]);
            msg += ` ${JSON.stringify(cleanMeta)}`;
        }
        
        // Add stack trace if present
        if (meta.stack) {
            msg += `\n${meta.stack}`;
        }
        
        return msg;
    })
);

// ============================================================================
// TRANSPORTS
// ============================================================================

const transports = [];

// 1. Console (always enabled)
transports.push(
    new winston.transports.Console({
        format: NODE_ENV === 'production' ? jsonFormat : consoleFormat,
        level: LOG_LEVEL
    })
);

// 2. File transports (production or if LOG_TO_FILE=true)
if (NODE_ENV === 'production' || process.env.LOG_TO_FILE === 'true') {
    
    // Application logs (all levels)
    transports.push(
        new DailyRotateFile({
            dirname: LOG_DIR,
            filename: 'app-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            maxSize: '50m',
            maxFiles: '30d',
            format: jsonFormat,
            level: 'info'
        })
    );
    
    // Error logs only
    transports.push(
        new DailyRotateFile({
            dirname: LOG_DIR,
            filename: 'error-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            maxSize: '50m',
            maxFiles: '30d',
            format: jsonFormat,
            level: 'error'
        })
    );
    
    // Security logs (auth, validation, suspicious activity)
    transports.push(
        new DailyRotateFile({
            dirname: LOG_DIR,
            filename: 'security-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            maxSize: '50m',
            maxFiles: '90d', // Keep longer for security compliance
            format: jsonFormat,
            level: 'security'
        })
    );
    
    // Audit logs (financial transactions, critical actions)
    transports.push(
        new DailyRotateFile({
            dirname: LOG_DIR,
            filename: 'audit-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            maxSize: '50m',
            maxFiles: '365d', // Keep 1 year for compliance
            format: jsonFormat,
            level: 'audit'
        })
    );
    
    // Performance logs
    transports.push(
        new DailyRotateFile({
            dirname: LOG_DIR,
            filename: 'performance-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            maxSize: '50m',
            maxFiles: '7d',
            format: jsonFormat,
            level: 'performance'
        })
    );
    
    // Debug logs (only if debug enabled)
    if (LOG_LEVEL === 'debug') {
        transports.push(
            new DailyRotateFile({
                dirname: LOG_DIR,
                filename: 'debug-%DATE%.log',
                datePattern: 'YYYY-MM-DD',
                maxSize: '100m',
                maxFiles: '3d',
                format: jsonFormat,
                level: 'debug'
            })
        );
    }
}

// ============================================================================
// LOGGER INSTANCE
// ============================================================================

const logger = winston.createLogger({
    levels: customLevels.levels,
    level: LOG_LEVEL,
    format: jsonFormat,
    defaultMeta: {
        service: SERVICE_NAME,
        environment: NODE_ENV,
        version: APP_VERSION
    },
    transports,
    
    // Exception handlers
    exceptionHandlers: [
        new winston.transports.File({ 
            filename: path.join(LOG_DIR, 'exceptions.log'),
            maxsize: 10485760, // 10MB
            maxFiles: 5
        })
    ],
    
    // Rejection handlers
    rejectionHandlers: [
        new winston.transports.File({ 
            filename: path.join(LOG_DIR, 'rejections.log'),
            maxsize: 10485760, // 10MB
            maxFiles: 5
        })
    ],
    
    exitOnError: false
});

// ============================================================================
// PREVENT WRITES AFTER SHUTDOWN
// ============================================================================

// Track logger state to prevent writes after shutdown
let loggerClosed = false;

// Wrap the original log method to check if logger is closed
const originalLog = logger.log.bind(logger);
logger.log = function(level, message, meta) {
    if (loggerClosed) {
        // Fallback to console if logger is closed
        try {
            console.log(`[${level.toUpperCase()}] ${message}`, meta || '');
        } catch (err) {
            // Silently ignore if console also fails
        }
        return;
    }
    try {
        return originalLog(level, message, meta);
    } catch (err) {
        // If Winston fails, fallback to console
        try {
            console.error('Logger error:', err.message);
            console.log(`[${level.toUpperCase()}] ${message}`, meta || '');
        } catch (consoleErr) {
            // Silently ignore
        }
    }
};

// Add a method to check if logger is available
logger.isAvailable = () => !loggerClosed;

// ============================================================================
// SPECIALIZED LOGGING METHODS
// ============================================================================

/**
 * Log fatal errors (system shutdown required)
 */
logger.fatal = (message, meta = {}) => {
    logger.log('fatal', message, {
        ...meta,
        timestamp: new Date().toISOString()
    });
};

/**
 * Log security events
 * Categories: auth_failed, validation_error, suspicious_activity, auto_blocked, etc.
 */
logger.security = (event, data = {}) => {
    logger.log('security', event, {
        category: 'SECURITY',
        event,
        timestamp: new Date().toISOString(),
        ...data
    });
};

/**
 * Log audit events (financial transactions, critical user actions)
 * Categories: transaction_verified, game_won, payment_processed, etc.
 */
logger.audit = (event, data = {}) => {
    logger.log('audit', event, {
        category: 'AUDIT',
        event,
        timestamp: new Date().toISOString(),
        ...data
    });
};

/**
 * Log authentication events
 */
logger.auth = (event, data = {}) => {
    logger.log('security', event, {
        category: 'AUTH',
        event,
        timestamp: new Date().toISOString(),
        ...data
    });
};

/**
 * Log performance metrics
 */
logger.performance = (event, duration, data = {}) => {
    logger.log('performance', event, {
        category: 'PERFORMANCE',
        event,
        duration,
        timestamp: new Date().toISOString(),
        ...data
    });
};

/**
 * Log business metrics
 */
logger.metric = (event, data = {}) => {
    logger.log('info', event, {
        category: 'METRIC',
        event,
        timestamp: new Date().toISOString(),
        ...data
    });
};

// ============================================================================
// CONTEXT MANAGEMENT
// ============================================================================

/**
 * Create child logger with request context
 */
logger.withContext = (context = {}) => {
    return logger.child(context);
};

/**
 * Create child logger for a specific user
 */
logger.forUser = (walletAddress, additionalContext = {}) => {
    return logger.child({
        walletAddress,
        ...additionalContext
    });
};

/**
 * Create child logger for a specific room
 */
logger.forRoom = (roomId, additionalContext = {}) => {
    return logger.child({
        roomId,
        ...additionalContext
    });
};

// ============================================================================
// HELPER METHODS
// ============================================================================

/**
 * Sanitize sensitive data before logging
 */
logger.sanitize = (data) => {
    const sanitized = { ...data };
    
    // Remove or redact sensitive fields
    const sensitiveFields = ['password', 'secretKey', 'privateKey', 'token', 'apiKey'];
    sensitiveFields.forEach(field => {
        if (sanitized[field]) {
            sanitized[field] = '[REDACTED]';
        }
    });
    
    // Truncate long wallet addresses
    if (sanitized.walletAddress && sanitized.walletAddress.length > 10) {
        sanitized.walletAddress = `${sanitized.walletAddress.substring(0, 6)}...${sanitized.walletAddress.slice(-4)}`;
    }
    
    return sanitized;
};

/**
 * Log HTTP request/response
 */
logger.http = (method, path, statusCode, duration, meta = {}) => {
    const level = statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warn' : 'info';
    logger[level]('HTTP request', {
        category: 'HTTP',
        method,
        path,
        statusCode,
        duration,
        ...meta
    });
};

/**
 * Log database query
 */
logger.query = (operation, collection, duration, meta = {}) => {
    logger.debug('Database query', {
        category: 'DATABASE',
        operation,
        collection,
        duration,
        ...meta
    });
};

/**
 * Log Redis operation
 */
logger.redis = (operation, key, duration, meta = {}) => {
    logger.debug('Redis operation', {
        category: 'REDIS',
        operation,
        key,
        duration,
        ...meta
    });
};

// ============================================================================
// ERROR TRACKING
// ============================================================================

/**
 * Track errors with unique IDs
 */
const errorTracker = new Map();

logger.trackError = (error, context = {}) => {
    const { v4: uuidv4 } = require('uuid');
    const errorId = uuidv4().substring(0, 8);
    
    // Store error for correlation
    errorTracker.set(errorId, {
        error,
        context,
        timestamp: Date.now()
    });
    
    // Log error
    logger.error('Error occurred', {
        errorId,
        message: error.message,
        stack: error.stack,
        code: error.code,
        ...context
    });
    
    // Clean up old errors (keep last 1000)
    if (errorTracker.size > 1000) {
        const oldestKey = errorTracker.keys().next().value;
        errorTracker.delete(oldestKey);
    }
    
    return errorId;
};

logger.getError = (errorId) => {
    return errorTracker.get(errorId);
};

// ============================================================================
// LOG SAMPLING (for high-volume events)
// ============================================================================

const samplingCounters = new Map();

/**
 * Log with sampling (only log 1 in N events)
 * Useful for high-volume events like answer submissions
 */
logger.sample = (sampleRate, level, message, meta = {}) => {
    const key = `${level}:${message}`;
    const counter = (samplingCounters.get(key) || 0) + 1;
    samplingCounters.set(key, counter);
    
    if (counter % sampleRate === 0) {
        logger[level](message, {
            ...meta,
            sampleRate,
            totalCount: counter
        });
    }
};

// Clean up sampling counters periodically
const samplingCleanupInterval = setInterval(() => {
    samplingCounters.clear();
}, 3600000); // Every hour

// Prevent this interval from keeping the process alive
samplingCleanupInterval.unref();

// ============================================================================
// STARTUP MESSAGE
// ============================================================================

logger.info('Logger initialized', {
    logLevel: LOG_LEVEL,
    environment: NODE_ENV,
    logDir: LOG_DIR,
    version: APP_VERSION,
    transports: transports.map(t => t.constructor.name)
});

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================

const gracefulShutdown = async (signal) => {
    if (loggerClosed) {
        return;
    }
    
    console.log(`\n📡 Received ${signal} signal, shutting down gracefully...`);
    
    loggerClosed = true;
    
    // Clear the sampling cleanup interval
    if (samplingCleanupInterval) {
        clearInterval(samplingCleanupInterval);
    }
    
    // Log shutdown message
    logger.info('Logger shutting down gracefully', { signal });
    
    // Close all transports
    await new Promise((resolve) => {
        setTimeout(resolve, 100); // Give logger time to flush
        logger.on('finish', resolve);
        logger.end();
    });
    
    console.log('✅ Logger closed');
    
    // Exit the process
    process.exit(0);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ============================================================================
// EXPORT
// ============================================================================

module.exports = logger;
module.exports.gracefulShutdown = gracefulShutdown;