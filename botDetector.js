// services/botDetector.js - IMPROVED VERSION
class BotDetector {
    constructor() {
        this.playerStats = new Map();
        this.suspiciousEvents = new Map(); // Track events per user
        this.blockedUsers = new Set();
        this.fingerprintHistory = new Map(); // Track fingerprints per user
    }

    trackConnection(ip, userAgent, socketId) {
        console.log(`BotDetector: Tracking connection from IP ${ip}, UserAgent: ${userAgent}, Socket: ${socketId}`);
        
        // Basic check: if userAgent is empty or suspicious
        if (!userAgent || userAgent.length < 10) {
            console.warn(`Suspicious connection detected: Empty or short UserAgent from ${ip}`);
            this.flagUser(ip, 'suspicious_ua');
        }
        
        // Check for common bot user agents
        const botPatterns = [
            /bot/i, /crawler/i, /spider/i, /scraper/i,
            /headless/i, /phantom/i, /selenium/i
        ];
        
        for (const pattern of botPatterns) {
            if (pattern.test(userAgent)) {
                console.warn(`Bot-like UserAgent detected: ${userAgent}`);
                this.flagUser(ip, 'bot_user_agent');
                break;
            }
        }
    }

    /**
     * NEW: Track device fingerprint for a user
     * Detects if user is switching devices/browsers frequently (bot behavior)
     */
    trackFingerprint(username, fingerprint, metadata = {}) {
        if (!fingerprint) {
            console.warn(`No fingerprint provided for ${username}`);
            return;
        }
        
        if (!this.fingerprintHistory.has(username)) {
            this.fingerprintHistory.set(username, new Set());
        }
        
        const userFingerprints = this.fingerprintHistory.get(username);
        const isNewFingerprint = !userFingerprints.has(fingerprint);
        
        userFingerprints.add(fingerprint);
        
        // Flag if using too many different fingerprints
        if (userFingerprints.size > 3) {
            console.warn(`Multiple fingerprints detected for ${username}: ${userFingerprints.size} unique`);
            this.flagUser(username, 'multiple_fingerprints');
            
            // Add to suspicion score
            if (this.playerStats.has(username)) {
                const stats = this.playerStats.get(username);
                stats.suspicionScore += 15;
            }
        }
        
        // Log fingerprint changes
        if (isNewFingerprint) {
            console.log({
                event: 'newFingerprint',
                username,
                totalFingerprints: userFingerprints.size,
                metadata
            });
        }
        
        return {
            isNew: isNewFingerprint,
            totalFingerprints: userFingerprints.size,
            suspicious: userFingerprints.size > 3
        };
    }

    trackEvent(username, eventType, metadata = {}) {
        console.log(`BotDetector: Tracking event ${eventType} for ${username}:`, metadata);
        
        if (!this.suspiciousEvents.has(username)) {
            this.suspiciousEvents.set(username, []);
        }
        
        this.suspiciousEvents.get(username).push({ 
            eventType, 
            timestamp: Date.now(), 
            metadata 
        });

        // Check for high event rate (potential bot)
        const events = this.suspiciousEvents.get(username);
        const recentEvents = events.filter(e => Date.now() - e.timestamp < 60000); // Last minute
        
        if (recentEvents.length > 20) {
            console.warn(`High event rate for ${username}: ${recentEvents.length} events in 1 minute`);
            this.flagUser(username, 'high_event_rate');
        }

        // Check for suspicious fast answers
        if (eventType === 'answer_submitted' && metadata.responseTime < 500) {
            console.warn(`Suspicious fast answer from ${username}: ${metadata.responseTime}ms`);
            this.flagUser(username, 'fast_answer');
        }
        
        // Check for extremely consistent response times (bot pattern)
        if (eventType === 'answer_submitted') {
            const answerEvents = recentEvents.filter(e => e.eventType === 'answer_submitted');
            if (answerEvents.length >= 5) {
                const times = answerEvents.map(e => e.metadata.responseTime);
                const variance = this.calculateVariance(times);
                
                if (variance < 50000) { // Very low variance = robotic
                    console.warn(`Very consistent response times for ${username}: variance ${variance}`);
                    this.flagUser(username, 'robotic_timing');
                }
            }
        }

        // Record answer for stats if it's an answer event
        if (eventType === 'answer_submitted' && 
            metadata.isCorrect !== undefined && 
            metadata.responseTime !== undefined) {
            this.recordAnswer(
                username, 
                metadata.isCorrect, 
                metadata.responseTime, 
                metadata.questionDifficulty || 'medium'
            );
        }
    }

    recordAnswer(username, isCorrect, responseTime, questionDifficulty = 'medium') {
        if (!this.playerStats.has(username)) {
            this.playerStats.set(username, {
                answers: [],
                suspicionScore: 0,
                lastAnswerTime: 0,
                firstAnswerTime: Date.now()
            });
        }

        const stats = this.playerStats.get(username);
        const now = Date.now();
        
        stats.answers.push({
            isCorrect,
            responseTime,
            timestamp: now,
            difficulty: questionDifficulty
        });

        // Keep only last 50 answers
        if (stats.answers.length > 50) {
            stats.answers.shift();
        }

        // ✅ FIXED: Calculate suspicion score more frequently
        this.updateSuspicionScore(username, stats);
        
        stats.lastAnswerTime = now;
    }

    /**
     * ✅ IMPROVED: Lower threshold and better scoring algorithm
     */
    updateSuspicionScore(username, stats) {
        const recent = stats.answers.slice(-20); // Last 20 answers
        
        // ✅ FIXED: Lower threshold from 10 to 5 answers
        if (recent.length < 5) {
            console.log(`Not enough data for ${username}: ${recent.length} answers (need 5+)`);
            return;
        }

        const correctCount = recent.filter(a => a.isCorrect).length;
        const avgResponseTime = recent.reduce((sum, a) => sum + a.responseTime, 0) / recent.length;
        const accuracy = correctCount / recent.length;
        
        // Red flags calculation
        let suspicion = 0;
        let flags = [];
        
        // 1. Suspiciously high accuracy (>85% correct)
        if (accuracy > 0.85) {
            const points = Math.floor((accuracy - 0.85) * 100);
            suspicion += points;
            flags.push(`high_accuracy(${(accuracy * 100).toFixed(0)}%)`);
        }
        
        // 2. Consistently fast responses (<2000ms average)
        if (avgResponseTime < 2000) {
            const points = Math.floor((2000 - avgResponseTime) / 100);
            suspicion += points;
            flags.push(`fast_response(${avgResponseTime.toFixed(0)}ms)`);
        }
        
        // 3. Very consistent response times (low variance = robotic)
        const variance = this.calculateVariance(recent.map(a => a.responseTime));
        if (variance < 200000) { // Lowered from 100000 to be less sensitive
            const points = Math.floor((200000 - variance) / 10000);
            suspicion += points;
            flags.push(`consistent_timing(var:${variance.toFixed(0)})`);
        }
        
        // 4. Perfect answers on difficult questions
        const hardQuestions = recent.filter(a => a.difficulty === 'hard');
        if (hardQuestions.length >= 3) {
            const hardAccuracy = hardQuestions.filter(a => a.isCorrect).length / hardQuestions.length;
            if (hardAccuracy > 0.8) {
                suspicion += 25;
                flags.push(`hard_question_ace(${(hardAccuracy * 100).toFixed(0)}%)`);
            }
        }
        
        // 5. NEW: Check for impossibly fast start (answering before question fully loads)
        const veryFast = recent.filter(a => a.responseTime < 1000).length;
        if (veryFast >= 3) {
            suspicion += 20;
            flags.push(`too_fast(${veryFast}x<1s)`);
        }
        
        // 6. NEW: Perfect accuracy with fast times (strongest bot signal)
        if (accuracy >= 1.0 && avgResponseTime < 3000) {
            suspicion += 30;
            flags.push('perfect_and_fast');
        }

        // Update score
        stats.suspicionScore = suspicion;
        
        // Log if suspicious
        if (suspicion > 50) {
            console.warn({
                event: 'highSuspicion',
                username,
                suspicionScore: suspicion,
                flags,
                stats: {
                    answers: recent.length,
                    correct: correctCount,
                    accuracy: `${(accuracy * 100).toFixed(1)}%`,
                    avgTime: `${avgResponseTime.toFixed(0)}ms`,
                    variance: variance.toFixed(0)
                }
            });
        } else if (suspicion > 30) {
            console.log({
                event: 'moderateSuspicion',
                username,
                suspicionScore: suspicion,
                flags
            });
        }
        
        // Auto-flag if score is very high
        if (suspicion > 70) {
            this.flagUser(username, 'high_bot_score');
        }
    }

    calculateVariance(numbers) {
        if (numbers.length === 0) return 0;
        const mean = numbers.reduce((a, b) => a + b, 0) / numbers.length;
        return numbers.reduce((sq, n) => sq + Math.pow(n - mean, 2), 0) / numbers.length;
    }

    /**
     * Check if user is suspicious based on threshold
     * @param {string} username 
     * @param {number} threshold - Default 70 (out of 100+)
     * @returns {boolean}
     */
    isSuspicious(username, threshold = 70) {
        const stats = this.playerStats.get(username);
        return stats ? stats.suspicionScore > threshold : false;
    }
    
    /**
     * NEW: Get detailed bot analysis for a user
     */
    getBotAnalysis(username) {
        const stats = this.playerStats.get(username);
        if (!stats) {
            return {
                found: false,
                message: 'No data for this user'
            };
        }
        
        const recent = stats.answers.slice(-20);
        if (recent.length === 0) {
            return {
                found: true,
                message: 'User found but no answers recorded',
                suspicionScore: 0
            };
        }
        
        const correctCount = recent.filter(a => a.isCorrect).length;
        const avgResponseTime = recent.reduce((sum, a) => sum + a.responseTime, 0) / recent.length;
        const variance = this.calculateVariance(recent.map(a => a.responseTime));
        
        return {
            found: true,
            username,
            suspicionScore: stats.suspicionScore,
            isSuspicious: stats.suspicionScore > 70,
            stats: {
                totalAnswers: recent.length,
                correctAnswers: correctCount,
                accuracy: `${((correctCount / recent.length) * 100).toFixed(1)}%`,
                avgResponseTime: `${avgResponseTime.toFixed(0)}ms`,
                variance: variance.toFixed(0),
                firstAnswer: new Date(stats.firstAnswerTime).toISOString(),
                lastAnswer: new Date(stats.lastAnswerTime).toISOString()
            },
            fingerprints: this.fingerprintHistory.has(username) 
                ? this.fingerprintHistory.get(username).size 
                : 0,
            flags: this.suspiciousEvents.has(username)
                ? this.suspiciousEvents.get(username)
                    .filter(e => ['suspicious_ua', 'bot_user_agent', 'high_event_rate', 
                                  'fast_answer', 'robotic_timing', 'multiple_fingerprints',
                                  'high_bot_score'].includes(e.metadata?.reason || e.eventType))
                    .map(e => e.metadata?.reason || e.eventType)
                : []
        };
    }

    flagUser(identifier, reason) {
        console.warn(`BotDetector: Flagging ${identifier} for ${reason}`);
        this.blockedUsers.add(identifier);
        
        // Track this flag in events
        if (!this.suspiciousEvents.has(identifier)) {
            this.suspiciousEvents.set(identifier, []);
        }
        this.suspiciousEvents.get(identifier).push({
            eventType: 'flag',
            timestamp: Date.now(),
            metadata: { reason }
        });
    }

    isBlocked(identifier) {
        return this.blockedUsers.has(identifier);
    }

    getSuspicionScore(username) {
        if (!this.playerStats.has(username)) return 0;
        return this.playerStats.get(username).suspicionScore;
    }
    
    /**
     * NEW: Clear old data to prevent memory leaks
     */
    cleanup(maxAgeMs = 24 * 60 * 60 * 1000) { // Default: 24 hours
        const now = Date.now();
        let cleaned = 0;
        
        // Clean player stats
        for (const [username, stats] of this.playerStats.entries()) {
            if (now - stats.lastAnswerTime > maxAgeMs) {
                this.playerStats.delete(username);
                cleaned++;
            }
        }
        
        // Clean suspicious events
        for (const [username, events] of this.suspiciousEvents.entries()) {
            const recentEvents = events.filter(e => now - e.timestamp < maxAgeMs);
            if (recentEvents.length === 0) {
                this.suspiciousEvents.delete(username);
            } else {
                this.suspiciousEvents.set(username, recentEvents);
            }
        }
        
        console.log(`BotDetector: Cleaned up ${cleaned} old user records`);
        return cleaned;
    }
}

module.exports = BotDetector;