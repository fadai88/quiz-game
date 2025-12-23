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
    
    // Validation
    VALIDATION_FAILURES: {
        count: 10,
        window: 300000, // 5 minutes
        severity: 'high'
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
// ALERT TRACKING
// ============================================================================

class AlertManager {
    constructor() {
        this.alertCounters = new Map();
        this.sentAlerts = new Set();
        this.cooldownPeriod = 3600000; // 1 hour cooldown between same alerts
        
        // Clean up old data every 5 minutes
        setInterval(() => this.cleanup(), 300000);
    }
    
    /**
     * Track an event and trigger alert if threshold exceeded
     */
    track(alertType, identifier, data = {}) {
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
            this.sendAlert(alertType, identifier, counter, threshold);
        }
        
        return shouldAlert;
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
     */
    sendAlert(alertType, identifier, counter, threshold) {
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
        
        // Prepare alert data
        const alertData = {
            alertType,
            identifier,
            severity: threshold.severity,
            threshold: threshold.count || threshold.score || threshold.duration,
            actualValue: counter.events.length,
            window: threshold.window,
            firstEvent: new Date(counter.firstEvent).toISOString(),
            recentEvents: counter.events.slice(-5).map(e => ({
                timestamp: new Date(e.timestamp).toISOString(),
                ...e.data
            })),
            timestamp: new Date().toISOString()
        };
        
        // Log alert
        logger.error('ALERT TRIGGERED', {
            category: 'ALERT',
            ...alertData
        });
        
        // Send to external alerting system
        this.sendExternalAlert(alertData);
        
        return alertData;
    }
    
    /**
     * Send to external alerting system
     * Override this method to integrate with your alerting service
     */
    async sendExternalAlert(alertData) {
        // IMPLEMENT YOUR ALERTING INTEGRATION HERE
        
        // Example integrations:
        
        // 1. SLACK
        // await this.sendSlackAlert(alertData);
        
        // 2. PAGERDUTY
        // await this.sendPagerDutyAlert(alertData);
        
        // 3. EMAIL
        // await this.sendEmailAlert(alertData);
        
        // 4. SMS (Twilio)
        // await this.sendSMSAlert(alertData);
        
        // 5. Discord
        // await this.sendDiscordAlert(alertData);
        
        // For now, just log
        logger.warn('Alert would be sent to external system', alertData);
    }
    
    /**
     * Send Slack alert (example implementation)
     */
    async sendSlackAlert(alertData) {
        if (!process.env.SLACK_WEBHOOK_URL) return;
        
        try {
            const axios = require('axios');
            
            const color = {
                critical: '#ff0000',
                high: '#ff6600',
                medium: '#ffaa00',
                low: '#00ff00'
            }[alertData.severity] || '#666666';
            
            const message = {
                username: 'Security Alert Bot',
                icon_emoji: ':rotating_light:',
                attachments: [{
                    color,
                    title: `🚨 ${alertData.alertType} Alert`,
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
                            title: 'First Event',
                            value: alertData.firstEvent,
                            short: false
                        }
                    ],
                    footer: 'Trivia Game Security',
                    ts: Math.floor(Date.now() / 1000)
                }]
            };
            
            await axios.post(process.env.SLACK_WEBHOOK_URL, message);
            logger.info('Slack alert sent', { alertType: alertData.alertType });
        } catch (error) {
            logger.error('Failed to send Slack alert', { error: error.message });
        }
    }
    
    /**
     * Send Discord alert (example implementation)
     */
    async sendDiscordAlert(alertData) {
        if (!process.env.DISCORD_WEBHOOK_URL) return;
        
        try {
            const axios = require('axios');
            
            const color = {
                critical: 16711680, // red
                high: 16744448,    // orange
                medium: 16766720,  // yellow
                low: 65280         // green
            }[alertData.severity] || 6710886;
            
            const embed = {
                title: `🚨 ${alertData.alertType} Alert`,
                color,
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
                    }
                ],
                footer: {
                    text: 'Trivia Game Security'
                },
                timestamp: new Date().toISOString()
            };
            
            await axios.post(process.env.DISCORD_WEBHOOK_URL, { embeds: [embed] });
            logger.info('Discord alert sent', { alertType: alertData.alertType });
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
        
        logger.debug('Alert manager cleaned up', {
            activeCounters: this.alertCounters.size,
            sentAlerts: this.sentAlerts.size
        });
    }
    
    /**
     * Get current status
     */
    getStatus() {
        return {
            activeCounters: this.alertCounters.size,
            sentAlerts: this.sentAlerts.size,
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

const trackFailedLogin = (identifier, data) => 
    alertManager.track('FAILED_LOGIN_ATTEMPTS', identifier, data);

const trackRateLimitViolation = (identifier, data) => 
    alertManager.track('RATE_LIMIT_VIOLATIONS', identifier, data);

const trackValidationFailure = (identifier, data) => 
    alertManager.track('VALIDATION_FAILURES', identifier, data);

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