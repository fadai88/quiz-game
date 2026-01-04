// config/alerts.js
// Alert configuration for security monitoring
// Define thresholds and alert rules for different security events

const logger = require('../logger');

// ============================================================================
// ALERT THRESHOLDS
// ============================================================================

const ALERT_THRESHOLDS = {
    // Authentication
    FAILED_LOGIN_ATTEMPTS: {
        count: 5,
        window: 300000, // 5 minutes
        severity: 'high'
    },
    
    // Rate limiting
    RATE_LIMIT_VIOLATIONS: {
        count: 3,
        window: 600000, // 10 minutes
        severity: 'medium'
    },
    
    // Validation - Per IP thresholds
    VALIDATION_FAILURES_PER_MINUTE: {
        count: 10,
        window: 60000, // 1 minute
        severity: 'high'
    },
    
    VALIDATION_FAILURES_PER_HOUR: {
        count: 50,
        window: 3600000, // 1 hour
        severity: 'medium'
    },
    
    // ✅ NEW: NoSQL Injection Detection
    NOSQL_INJECTION_ATTEMPTS: {
        count: 3,
        window: 60000, // 1 minute
        severity: 'critical'
    },
    
    // reCAPTCHA
    RECAPTCHA_FAILURES: {
        count: 5,
        window: 300000, // 5 minutes
        severity: 'high'
    },
    
    // Bot detection
    BOT_SUSPICION: {
        score: 0.8,
        severity: 'high'
    },
    
    // Transaction
    FAILED_TRANSACTIONS: {
        count: 3,
        window: 600000, // 10 minutes
        severity: 'critical'
    },
    
    // Performance
    SLOW_REQUESTS: {
        duration: 3000, // 3 seconds
        count: 10,
        window: 300000, // 5 minutes
        severity: 'medium'
    },
    
    // Error rate
    ERROR_RATE: {
        count: 50,
        window: 300000, // 5 minutes
        severity: 'critical'
    }
};

// ============================================================================
// NOSQL INJECTION PATTERN DETECTION
// ============================================================================

/**
 * Detect NoSQL injection patterns in error details
 */
function isNoSQLInjection(errorDetails) {
    const patterns = [
        /\$ne/i,
        /\$gt/i,
        /\$lt/i,
        /\$gte/i,
        /\$lte/i,
        /\$regex/i,
        /\$where/i,
        /\$exists/i,
        /\$in/i,
        /\$nin/i,
        /\$or/i,
        /\$and/i,
    ];
    
    return patterns.some(pattern => pattern.test(errorDetails));
}

// ============================================================================
// ALERT TRACKING
// ============================================================================

class AlertManager {
    constructor() {
        this.alertCounters = new Map();
        this.sentAlerts = new Map();
        this.cooldownPeriod = 300000; // 5 minutes cooldown
        
        // ✅ NEW: Track global validation failures
        this.globalValidationFailures = [];
        
        // Clean up old data every 5 minutes
        setInterval(() => this.cleanup(), 300000);
    }
    
    /**
     * Track an event and trigger alert if threshold exceeded
     * ✅ FIXED: Made async to support await sendAlert()
     */
    async track(alertType, identifier, data = {}) {
        const threshold = ALERT_THRESHOLDS[alertType];
        if (!threshold) {
            logger.warn('Unknown alert type', { alertType });
            return;
        }
        
        const key = `${alertType}:${identifier}`;
        const now = Date.now();
        
        // Get or create counter
        let counter = this.alertCounters.get(key);
        if (!counter) {
            counter = { events: [], firstEvent: now };
            this.alertCounters.set(key, counter);
        }
        
        // Add event
        counter.events.push({ timestamp: now, data });
        
        // Remove old events outside the window
        if (threshold.window) {
            counter.events = counter.events.filter(
                e => now - e.timestamp < threshold.window
            );
        }
        
        // Check if threshold exceeded
        const shouldAlert = this.shouldAlert(alertType, counter, threshold);
        
        if (shouldAlert) {
            await this.sendAlert(alertType, identifier, counter, threshold);
        }
        
        return shouldAlert;
    }
    
    /**
     * ✅ NEW: Track validation failure with enhanced detection
     * ✅ FIXED: Made async to support await track()
     */
    async trackValidationFailure(ip, endpoint, errorDetails) {
        const now = Date.now();
        
        // Track globally
        this.globalValidationFailures.push({
            timestamp: now,
            ip,
            endpoint,
            details: errorDetails
        });
        
        // Clean old global failures (older than 1 hour)
        this.globalValidationFailures = this.globalValidationFailures.filter(
            f => now - f.timestamp < 3600000
        );
        
        // Check for NoSQL injection pattern
        const isNoSQL = isNoSQLInjection(errorDetails);
        
        if (isNoSQL) {
            // Track NoSQL injection specifically
            await this.track('NOSQL_INJECTION_ATTEMPTS', ip, {
                endpoint,
                pattern: errorDetails,
                timestamp: now
            });
        }
        
        // Track per-minute rate
        await this.track('VALIDATION_FAILURES_PER_MINUTE', ip, {
            endpoint,
            details: errorDetails,
            isNoSQL
        });
        
        // Check global hourly rate
        const recentGlobalFailures = this.globalValidationFailures.filter(
            f => now - f.timestamp < 3600000
        );
        
        if (recentGlobalFailures.length >= ALERT_THRESHOLDS.VALIDATION_FAILURES_PER_HOUR.count) {
            const alertKey = 'VALIDATION_FAILURES_PER_HOUR:global';
            const lastAlertTime = this.sentAlerts.get(alertKey);
            
            if (!lastAlertTime || now - lastAlertTime >= this.cooldownPeriod) {
                await this.sendGlobalAlert(recentGlobalFailures);
                this.sentAlerts.set(alertKey, now);
            }
        }
    }
    
    /**
     * ✅ NEW: Send global validation failure alert
     * ✅ FIXED: Made async
     */
    async sendGlobalAlert(failures) {
        const now = Date.now();
        
        // Count unique IPs
        const ipCounts = {};
        failures.forEach(f => {
            ipCounts[f.ip] = (ipCounts[f.ip] || 0) + 1;
        });
        
        const topIPs = Object.entries(ipCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([ip, count]) => ({ ip, count }));
        
        const alertData = {
            alertType: 'VALIDATION_FAILURES_PER_HOUR',
            identifier: 'global',
            severity: 'medium',
            threshold: ALERT_THRESHOLDS.VALIDATION_FAILURES_PER_HOUR.count,
            actualValue: failures.length,
            window: '1 hour',
            uniqueIPs: Object.keys(ipCounts).length,
            topAttackers: topIPs,
            recentEvents: failures.slice(-5).map(f => ({
                timestamp: new Date(f.timestamp).toISOString(),
                ip: f.ip,
                endpoint: f.endpoint,
                error: f.details.substring(0, 100)
            })),
            timestamp: new Date().toISOString(),
            recommendation: 'Possible DDoS or coordinated attack'
        };
        
        // Log alert
        logger.error('🚨 ALERT TRIGGERED: High Global Rate of Validation Failures', {
            category: 'ALERT',
            ...alertData
        });
        
        // Send to external systems
        await this.sendExternalAlert(alertData);
    }
    
    /**
     * Check if alert should be triggered
     */
    shouldAlert(alertType, counter, threshold) {
        // Check count threshold (if applicable)
        if (threshold.count && counter.events.length >= threshold.count) {
            return true;
        }
        
        // Check score threshold (for bot detection)
        if (threshold.score && counter.events.length > 0) {
            const latestEvent = counter.events[counter.events.length - 1];
            if (latestEvent.data.score >= threshold.score) {
                return true;
            }
        }
        
        // Check duration threshold (for performance)
        if (threshold.duration && counter.events.length > 0) {
            const latestEvent = counter.events[counter.events.length - 1];
            if (latestEvent.data.duration >= threshold.duration) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Send alert
     * ✅ FIXED: Already async
     */
    async sendAlert(alertType, identifier, counter, threshold) {
        const alertKey = `${alertType}:${identifier}`;
        const now = Date.now();
        
        // Check cooldown
        const lastAlertTime = this.sentAlerts.get(alertKey);
        if (lastAlertTime && now - lastAlertTime < this.cooldownPeriod) {
            logger.debug('Alert in cooldown period', { alertType, identifier });
            return;
        }
        
        // Mark alert as sent
        this.sentAlerts.set(alertKey, now);
        
        // ✅ ENHANCED: Add more context for validation failures
        let recommendation = 'Review and investigate';
        let alertTitle = alertType;
        let shouldBlock = false;
        let blockDuration = 3600; // 1 hour default
        
        if (alertType === 'NOSQL_INJECTION_ATTEMPTS') {
            recommendation = 'IMMEDIATE ACTION: IP auto-blocked and investigation required';
            alertTitle = 'NoSQL Injection Attack Detected';
            shouldBlock = true;
            blockDuration = 7200; // 2 hours for NoSQL injection
        } else if (alertType === 'VALIDATION_FAILURES_PER_MINUTE') {
            recommendation = 'IP auto-blocked due to high failure rate';
            alertTitle = 'High Rate of Validation Failures from Single IP';
            shouldBlock = true;
            blockDuration = 3600; // 1 hour
        }
        
        // Prepare alert data
        const alertData = {
            alertType,
            alertTitle,
            identifier,
            severity: threshold.severity,
            threshold: threshold.count || threshold.score || threshold.duration,
            actualValue: counter.events.length,
            window: this.formatWindow(threshold.window),
            firstEvent: new Date(counter.firstEvent).toISOString(),
            recentEvents: counter.events.slice(-5).map(e => ({
                timestamp: new Date(e.timestamp).toISOString(),
                ...e.data
            })),
            timestamp: new Date().toISOString(),
            recommendation,
            blocked: shouldBlock,
            blockDuration: shouldBlock ? blockDuration : null
        };
        
        // ✅ NEW: Auto-block IP if critical alert
        if (shouldBlock) {
            try {
                const Redis = require('ioredis');
                const redisClient = new Redis({
                    host: process.env.REDIS_HOST || 'localhost',
                    port: process.env.REDIS_PORT || 6379,
                    password: process.env.REDIS_PASSWORD || undefined,
                    retryStrategy: (times) => Math.min(times * 50, 2000)
                });
                
                await redisClient.set(
                    `blocklist:${identifier}`, 
                    JSON.stringify({
                        reason: alertType,
                        blockedAt: new Date().toISOString(),
                        severity: threshold.severity
                    }), 
                    'EX', 
                    blockDuration
                );
                
                logger.error(`🔒 AUTO-BLOCKED: ${identifier} for ${blockDuration}s (${alertType})`);
                
                // Close the Redis connection
                redisClient.disconnect();
            } catch (error) {
                logger.error('Failed to auto-block IP in Redis:', { error: error.message });
            }
        }
        
        // Log alert with emoji for visibility
        const emoji = threshold.severity === 'critical' ? '🔴' : 
                     threshold.severity === 'high' ? '🟠' : 
                     threshold.severity === 'medium' ? '🟡' : '🟢';
        
        logger.error(`${emoji} ALERT TRIGGERED: ${alertTitle}`, {
            category: 'ALERT',
            ...alertData
        });
        
        // Send to external alerting system
        await this.sendExternalAlert(alertData);
        
        return alertData;
    }
    
    /**
     * Format time window for display
     */
    formatWindow(ms) {
        if (ms === 60000) return '1 minute';
        if (ms === 300000) return '5 minutes';
        if (ms === 600000) return '10 minutes';
        if (ms === 3600000) return '1 hour';
        return `${ms / 1000} seconds`;
    }
    
    /**
     * Send to external alerting system
     */
    async sendExternalAlert(alertData) {
        // 1. SLACK
        if (process.env.SLACK_WEBHOOK_URL) {
            await this.sendSlackAlert(alertData);
        }
        
        // 2. DISCORD
        if (process.env.DISCORD_WEBHOOK_URL) {
            await this.sendDiscordAlert(alertData);
        }
        
        // Console output for immediate visibility
        console.log('\n' + '='.repeat(80));
        console.log(`🚨 SECURITY ALERT: ${alertData.alertTitle || alertData.alertType}`);
        console.log('='.repeat(80));
        console.log(`Severity: ${alertData.severity.toUpperCase()}`);
        console.log(`Time: ${alertData.timestamp}`);
        console.log(`\nDetails:`);
        console.log(JSON.stringify({
            identifier: alertData.identifier,
            threshold: alertData.threshold,
            actual: alertData.actualValue,
            window: alertData.window,
            recommendation: alertData.recommendation,
            blocked: alertData.blocked || false
        }, null, 2));
        console.log('='.repeat(80) + '\n');
    }
    
    /**
     * Send Slack alert
     */
    async sendSlackAlert(alertData) {
        if (!process.env.SLACK_WEBHOOK_URL) return;
        
        try {
            const response = await fetch(process.env.SLACK_WEBHOOK_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: 'Security Alert Bot',
                    icon_emoji: ':rotating_light:',
                    attachments: [{
                        color: {
                            critical: '#ff0000',
                            high: '#ff6600',
                            medium: '#ffaa00',
                            low: '#00ff00'
                        }[alertData.severity] || '#666666',
                        title: `🚨 ${alertData.alertTitle || alertData.alertType}`,
                        fields: [
                            {
                                title: 'Severity',
                                value: alertData.severity.toUpperCase(),
                                short: true
                            },
                            {
                                title: 'Identifier',
                                value: alertData.identifier,
                                short: true
                            },
                            {
                                title: 'Threshold',
                                value: `${alertData.threshold} events`,
                                short: true
                            },
                            {
                                title: 'Actual',
                                value: `${alertData.actualValue} events`,
                                short: true
                            },
                            {
                                title: 'Time Window',
                                value: alertData.window,
                                short: true
                            },
                            {
                                title: 'Blocked',
                                value: alertData.blocked ? `Yes (${alertData.blockDuration}s)` : 'No',
                                short: true
                            },
                            {
                                title: 'Recommendation',
                                value: alertData.recommendation,
                                short: false
                            }
                        ],
                        footer: 'Trivia Game Security',
                        ts: Math.floor(Date.now() / 1000)
                    }]
                })
            });
            
            if (response.ok) {
                logger.info('Slack alert sent', { alertType: alertData.alertType });
            }
        } catch (error) {
            logger.error('Failed to send Slack alert', { error: error.message });
        }
    }
    
    /**
     * Send Discord alert
     */
    async sendDiscordAlert(alertData) {
        if (!process.env.DISCORD_WEBHOOK_URL) return;
        
        try {
            const response = await fetch(process.env.DISCORD_WEBHOOK_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    embeds: [{
                        title: `🚨 ${alertData.alertTitle || alertData.alertType}`,
                        color: {
                            critical: 16711680, // red
                            high: 16744448,    // orange
                            medium: 16766720,  // yellow
                            low: 65280         // green
                        }[alertData.severity] || 6710886,
                        fields: [
                            {
                                name: 'Severity',
                                value: alertData.severity.toUpperCase(),
                                inline: true
                            },
                            {
                                name: 'Identifier',
                                value: alertData.identifier,
                                inline: true
                            },
                            {
                                name: 'Threshold',
                                value: `${alertData.threshold} events`,
                                inline: true
                            },
                            {
                                name: 'Actual',
                                value: `${alertData.actualValue} events`,
                                inline: true
                            },
                            {
                                name: 'Time Window',
                                value: alertData.window,
                                inline: true
                            },
                            {
                                name: 'Blocked',
                                value: alertData.blocked ? `Yes (${alertData.blockDuration}s)` : 'No',
                                inline: true
                            },
                            {
                                name: 'Recommendation',
                                value: alertData.recommendation,
                                inline: false
                            }
                        ],
                        footer: {
                            text: 'Trivia Game Security'
                        },
                        timestamp: new Date().toISOString()
                    }]
                })
            });
            
            if (response.ok) {
                logger.info('Discord alert sent', { alertType: alertData.alertType });
            }
        } catch (error) {
            logger.error('Failed to send Discord alert', { error: error.message });
        }
    }
    
    /**
     * Clean up old data
     */
    cleanup() {
        const now = Date.now();
        const maxAge = 3600000; // 1 hour
        
        // Clean alert counters
        for (const [key, counter] of this.alertCounters.entries()) {
            counter.events = counter.events.filter(
                e => now - e.timestamp < maxAge
            );
            
            if (counter.events.length === 0) {
                this.alertCounters.delete(key);
            }
        }
        
        // Clean sent alerts
        for (const [key, timestamp] of this.sentAlerts.entries()) {
            if (now - timestamp > this.cooldownPeriod * 2) {
                this.sentAlerts.delete(key);
            }
        }
        
        // Clean global failures
        this.globalValidationFailures = this.globalValidationFailures.filter(
            f => now - f.timestamp < maxAge
        );
        
        logger.debug('Alert manager cleaned up', {
            activeCounters: this.alertCounters.size,
            sentAlerts: this.sentAlerts.size,
            globalFailures: this.globalValidationFailures.length
        });
    }
    
    /**
     * Get current status
     */
    getStatus() {
        const now = Date.now();
        const oneHourAgo = now - 3600000;
        const oneMinuteAgo = now - 60000;
        
        const recentGlobalFailures = this.globalValidationFailures.filter(
            f => f.timestamp > oneHourAgo
        );
        const veryRecentFailures = this.globalValidationFailures.filter(
            f => f.timestamp > oneMinuteAgo
        );
        
        return {
            activeCounters: this.alertCounters.size,
            sentAlerts: this.sentAlerts.size,
            globalStats: {
                lastHour: {
                    totalFailures: recentGlobalFailures.length,
                    uniqueIPs: new Set(recentGlobalFailures.map(f => f.ip)).size
                },
                lastMinute: {
                    totalFailures: veryRecentFailures.length,
                    uniqueIPs: new Set(veryRecentFailures.map(f => f.ip)).size
                }
            },
            counters: Array.from(this.alertCounters.entries()).map(([key, counter]) => ({
                key,
                eventCount: counter.events.length,
                firstEvent: new Date(counter.firstEvent).toISOString()
            }))
        };
    }
}

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

const alertManager = new AlertManager();

// ============================================================================
// CONVENIENCE METHODS
// ============================================================================
// ✅ FIXED: All wrapper functions now properly handle async

const trackFailedLogin = (identifier, data) => 
    alertManager.track('FAILED_LOGIN_ATTEMPTS', identifier, data);

const trackRateLimitViolation = (identifier, data) => 
    alertManager.track('RATE_LIMIT_VIOLATIONS', identifier, data);

const trackValidationFailure = (ip, endpoint, errorDetails) => 
    alertManager.trackValidationFailure(ip, endpoint, errorDetails);

const trackRecaptchaFailure = (identifier, data) => 
    alertManager.track('RECAPTCHA_FAILURES', identifier, data);

const trackBotSuspicion = (identifier, data) => 
    alertManager.track('BOT_SUSPICION', identifier, data);

const trackFailedTransaction = (identifier, data) => 
    alertManager.track('FAILED_TRANSACTIONS', identifier, data);

const trackSlowRequest = (identifier, data) => 
    alertManager.track('SLOW_REQUESTS', identifier, data);

const trackError = (identifier, data) => 
    alertManager.track('ERROR_RATE', identifier, data);

// ============================================================================
// EXPORT
// ============================================================================

module.exports = {
    alertManager,
    ALERT_THRESHOLDS,
    trackFailedLogin,
    trackRateLimitViolation,
    trackValidationFailure,
    trackRecaptchaFailure,
    trackBotSuspicion,
    trackFailedTransaction,
    trackSlowRequest,
    trackError
};