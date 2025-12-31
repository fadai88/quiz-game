// middleware/requestLogger.js
// Request logging middleware for Express and Socket.IO
// Adds correlation IDs and context to all logs

const { v4: uuidv4 } = require('uuid');
const logger = require('../logger');

// ============================================================================
// HTTP REQUEST LOGGER MIDDLEWARE
// ============================================================================

/**
 * Express middleware to log HTTP requests and add request context
 */
function httpRequestLogger(req, res, next) {
    // Generate or extract correlation ID
    req.correlationId = req.headers['x-correlation-id'] || 
                        req.headers['x-request-id'] || 
                        uuidv4();
    
    // Extract client information
    const ip = req.headers['x-forwarded-for'] || 
               req.headers['x-real-ip'] || 
               req.connection.remoteAddress || 
               req.socket.remoteAddress;
    
    const userAgent = req.headers['user-agent'];
    const sessionId = req.cookies?.sessionToken?.substring(0, 8);
    
    // Create request-scoped logger
    req.logger = logger.withContext({
        correlationId: req.correlationId,
        ip,
        userAgent,
        sessionId,
        method: req.method,
        path: req.path
    });
    
    // Add correlation ID to response headers (for client-side debugging)
    res.setHeader('X-Correlation-ID', req.correlationId);
    
    // Log incoming request
    req.logger.info('HTTP request received', {
        category: 'HTTP',
        method: req.method,
        path: req.path,
        query: Object.keys(req.query).length > 0 ? req.query : undefined,
        contentLength: req.headers['content-length'],
        referer: req.headers.referer
    });
    
    // Track request timing
    const startTime = Date.now();
    
    // Log response when finished
    const originalSend = res.send;
    res.send = function(data) {
        const duration = Date.now() - startTime;
        
        // Log response
        req.logger.http(
            req.method,
            req.path,
            res.statusCode,
            duration,
            {
                contentLength: res.get('Content-Length'),
                correlationId: req.correlationId
            }
        );
        
        // Log slow requests as warnings
        if (duration > 3000) {
            req.logger.warn('Slow HTTP request', {
                method: req.method,
                path: req.path,
                duration,
                threshold: 3000
            });
        }
        
        // Track performance metrics
        logger.performance('http_request', duration, {
            method: req.method,
            path: req.path,
            statusCode: res.statusCode,
            correlationId: req.correlationId
        });
        
        return originalSend.call(this, data);
    };
    
    // Handle errors
    res.on('error', (error) => {
        req.logger.error('HTTP response error', {
            error: error.message,
            stack: error.stack,
            correlationId: req.correlationId
        });
    });
    
    next();
}

// ============================================================================
// SOCKET.IO LOGGER MIDDLEWARE
// ============================================================================

/**
 * Socket.IO middleware to add logging context to sockets
 */
function socketLogger(socket, next) {
    // Generate correlation ID for this connection
    socket.correlationId = uuidv4();
    
    // Extract client information
    const ip = socket.handshake.headers['x-forwarded-for'] || 
               socket.handshake.headers['x-real-ip'] || 
               socket.handshake.address;
    
    const userAgent = socket.handshake.headers['user-agent'];
    
    // Create socket-scoped logger
    socket.logger = logger.withContext({
        correlationId: socket.correlationId,
        socketId: socket.id,
        ip,
        userAgent,
        transport: socket.conn.transport.name
    });
    
    // Log connection
    socket.logger.info('Socket connected', {
        category: 'SOCKET',
        event: 'connect',
        transport: socket.conn.transport.name
    });
    
    // Track connection time
    socket.connectedAt = Date.now();
    
    // Log disconnection
    socket.on('disconnect', (reason) => {
        const duration = Date.now() - socket.connectedAt;
        
        socket.logger.info('Socket disconnected', {
            category: 'SOCKET',
            event: 'disconnect',
            reason,
            duration,
            walletAddress: socket.user?.walletAddress
        });
        
        logger.metric('socket_session', {
            duration,
            reason,
            walletAddress: socket.user?.walletAddress
        });
    });
    
    // Log errors
    socket.on('error', (error) => {
        socket.logger.error('Socket error', {
            error: error.message,
            stack: error.stack,
            walletAddress: socket.user?.walletAddress
        });
    });
    
    next();
}

/**
 * Socket.IO event logger wrapper
 * Logs all socket events with timing and context
 */
function logSocketEvent(eventName) {
    return function(socket, next) {
        const originalEmit = socket.emit;
        
        socket.emit = function(event, ...args) {
            // Log outgoing events (from server to client)
            if (!event.startsWith('$')) { // Skip internal events
                socket.logger.debug('Socket event emitted', {
                    category: 'SOCKET',
                    event,
                    direction: 'outgoing',
                    argsCount: args.length
                });
            }
            
            return originalEmit.apply(this, [event, ...args]);
        };
        
        next();
    };
}

/**
 * Wrap socket event handler with logging
 */
function wrapSocketHandler(eventName, handler) {
    return async function(socket, data, callback) {
        const startTime = Date.now();
        
        // Update logger context with user info if available
        if (socket.user) {
            socket.logger = socket.logger.withContext({
                walletAddress: socket.user.walletAddress,
                sessionId: socket.sessionId?.substring(0, 8)
            });
        }
        
        // Log incoming event
        socket.logger.debug('Socket event received', {
            category: 'SOCKET',
            event: eventName,
            direction: 'incoming',
            walletAddress: socket.user?.walletAddress,
            hasCallback: !!callback
        });
        
        try {
            // Execute handler
            const result = await handler(socket, data, callback);
            
            // Log success
            const duration = Date.now() - startTime;
            
            socket.logger.performance(
                `socket_event_${eventName}`,
                duration,
                {
                    event: eventName,
                    success: true,
                    walletAddress: socket.user?.walletAddress
                }
            );
            
            // Warn on slow events
            if (duration > 1000) {
                socket.logger.warn('Slow socket event', {
                    event: eventName,
                    duration,
                    threshold: 1000,
                    walletAddress: socket.user?.walletAddress
                });
            }
            
            return result;
        } catch (error) {
            // Log error
            const duration = Date.now() - startTime;
            let errorId = 'unknown';
            
            try {
                if (logger.isAvailable && logger.isAvailable()) {
                    errorId = logger.trackError(error, {
                        event: eventName,
                        walletAddress: socket.user?.walletAddress,
                        socketId: socket.id,
                        correlationId: socket.correlationId,
                        duration
                    });
                } else {
                    console.error('Socket event error (logger unavailable):', error.message);
                    errorId = Date.now().toString(36);
                }
            } catch (logError) {
                console.error('Failed to log socket error:', logError.message);
                errorId = Date.now().toString(36);
            }
            
            try {
                socket.logger.error('Socket event error', {
                    event: eventName,
                    errorId,
                    error: error.message,
                    walletAddress: socket.user?.walletAddress,
                    duration
                });
            } catch (logError) {
                // Ignore logging errors
                console.error('Failed to log to socket logger:', logError.message);
            }
            
            throw error;
        }
    };
}

// ============================================================================
// ERROR HANDLER MIDDLEWARE
// ============================================================================

/**
 * Express error handler middleware
 * Must be added AFTER all routes
 */
function errorHandler(err, req, res, next) {
    let errorId = 'unknown';
    
    // Try to track error with logger
    try {
        if (logger.isAvailable && logger.isAvailable()) {
            errorId = logger.trackError(err, {
                method: req.method,
                path: req.path,
                query: req.query,
                body: req.body,
                correlationId: req.correlationId,
                walletAddress: req.user?.walletAddress,
                ip: req.ip
            });
        } else {
            // Logger not available, use console
            console.error('Error occurred (logger unavailable):', err.message);
            errorId = Date.now().toString(36);
        }
    } catch (logError) {
        // If logging fails, fallback to console
        console.error('Failed to log error:', logError.message);
        console.error('Original error:', err.message);
        errorId = Date.now().toString(36);
    }
    
    // Try to log to request logger
    try {
        if (req.logger) {
            req.logger.error('Request error', {
                errorId,
                error: err.message,
                stack: err.stack,
                code: err.code,
                statusCode: err.statusCode || 500
            });
        }
    } catch (logError) {
        // Ignore logging errors
        console.error('Failed to log request error:', logError.message);
    }
    
    // Send error response
    const statusCode = err.statusCode || 500;
    const isDev = process.env.NODE_ENV !== 'production';
    
    // Make sure response hasn't been sent already
    if (!res.headersSent) {
        res.status(statusCode).json({
            error: isDev ? err.message : 'Internal server error',
            errorId,
            correlationId: req.correlationId,
            ...(isDev && { stack: err.stack })
        });
    }
}

// ============================================================================
// REQUEST SANITIZATION
// ============================================================================

/**
 * Sanitize request data for logging
 */
function sanitizeRequest(req) {
    const sanitized = {
        method: req.method,
        path: req.path,
        query: req.query,
        headers: { ...req.headers }
    };
    
    // Remove sensitive headers
    delete sanitized.headers.authorization;
    delete sanitized.headers.cookie;
    delete sanitized.headers['x-api-key'];
    
    // Add body if present (but sanitize sensitive fields)
    if (req.body && Object.keys(req.body).length > 0) {
        sanitized.body = { ...req.body };
        
        // Remove sensitive fields
        const sensitiveFields = ['password', 'token', 'secret', 'privateKey'];
        sensitiveFields.forEach(field => {
            if (sanitized.body[field]) {
                sanitized.body[field] = '[REDACTED]';
            }
        });
    }
    
    return sanitized;
}

// ============================================================================
// EXPORT
// ============================================================================

module.exports = {
    httpRequestLogger,
    socketLogger,
    logSocketEvent,
    wrapSocketHandler,
    errorHandler,
    sanitizeRequest
};