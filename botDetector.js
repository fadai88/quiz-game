class BotDetector {
    constructor() {
        this.playerStats = new Map();
        this.suspiciousEvents = new Map(); // Track events per user
        this.blockedUsers = new Set();
    }

    trackConnection(ip, userAgent, socketId) {
        console.log(`BotDetector: Tracking connection from IP ${ip}, UserAgent: ${userAgent}, Socket: ${socketId}`);
        // Basic check: if userAgent is empty or suspicious
        if (!userAgent || userAgent.length < 10) {
            console.warn(`Suspicious connection detected: Empty or short UserAgent from ${ip}`);
            this.flagUser(ip, 'suspicious_ua');
        }
        // Add more checks as needed, e.g., known bot patterns
    }

    trackEvent(username, eventType, metadata = {}) {
        console.log(`BotDetector: Tracking event ${eventType} for ${username}:`, metadata);
        if (!this.suspiciousEvents.has(username)) {
            this.suspiciousEvents.set(username, []);
        }
        this.suspiciousEvents.get(username).push({ eventType, timestamp: Date.now(), metadata });

        // Example: Flag if too many events in short time
        const events = this.suspiciousEvents.get(username);
        const recentEvents = events.filter(e => Date.now() - e.timestamp < 60000); // Last minute
        if (recentEvents.length > 10) {
            console.warn(`High event rate for ${username}: ${recentEvents.length} in 1min`);
            this.flagUser(username, 'high_event_rate');
        }

        // Check for patterns, e.g., rapid answers
        if (eventType === 'answer_submitted' && metadata.responseTime < 500) {
            console.warn(`Suspicious fast answer from ${username}: ${metadata.responseTime}ms`);
            this.flagUser(username, 'fast_answer');
        }

        // If it's an answer event, record it for stats
        if (eventType === 'answer_submitted' && metadata.isCorrect !== undefined && metadata.responseTime !== undefined) {
            this.recordAnswer(username, metadata.isCorrect, metadata.responseTime, metadata.questionDifficulty || 'medium');
        }
    }

    recordAnswer(username, isCorrect, responseTime, questionDifficulty = 'medium') {
        if (!this.playerStats.has(username)) {
            this.playerStats.set(username, {
                answers: [],
                suspicionScore: 0,
                lastAnswerTime: 0
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

        // Calculate suspicion score
        this.updateSuspicionScore(username, stats);
        
        stats.lastAnswerTime = now;
    }

    updateSuspicionScore(username, stats) {
        const recent = stats.answers.slice(-20); // Last 20 answers
        if (recent.length < 10) return; // Need sufficient data

        const correctCount = recent.filter(a => a.isCorrect).length;
        const avgResponseTime = recent.reduce((sum, a) => sum + a.responseTime, 0) / recent.length;
        
        // Red flags:
        let suspicion = 0;
        
        // 1. Too high accuracy (>90% correct)
        if (correctCount / recent.length > 0.9) suspicion += 30;
        
        // 2. Consistently fast responses (<1000ms average)
        if (avgResponseTime < 1000) suspicion += 25;
        
        // 3. Very consistent response times (low variance)
        const variance = this.calculateVariance(recent.map(a => a.responseTime));
        if (variance < 100000) suspicion += 20; // Very consistent timing
        
        // 4. Perfect answers on difficult questions
        const hardQuestions = recent.filter(a => a.difficulty === 'hard' && a.isCorrect);
        if (hardQuestions.length / recent.filter(a => a.difficulty === 'hard').length > 0.8) {
            suspicion += 25;
        }

        stats.suspicionScore = suspicion;
        
        if (suspicion > 60) {
            console.warn(`HIGH SUSPICION: Player ${username} has suspicion score ${suspicion}`);
            console.warn(`Recent stats: ${correctCount}/${recent.length} correct, ${avgResponseTime.toFixed(0)}ms avg`);
        }
    }

    calculateVariance(numbers) {
        const mean = numbers.reduce((a, b) => a + b, 0) / numbers.length;
        return numbers.reduce((sq, n) => sq + Math.pow(n - mean, 2), 0) / numbers.length;
    }

    isSuspicious(username, threshold = 60) {
        const stats = this.playerStats.get(username);
        return stats ? stats.suspicionScore > threshold : false;
    }

    flagUser(identifier, reason) {
        console.warn(`BotDetector: Flagging ${identifier} for ${reason}`);
        this.blockedUsers.add(identifier);
        // Optionally integrate with Redis for blocking
        // await redisClient.set(`blocklist:${identifier}`, 1, 'EX', 86400);
    }

    isBlocked(identifier) {
        return this.blockedUsers.has(identifier);
    }

    getSuspicionScore(username) {
        if (!this.playerStats.has(username)) return 0;
        return this.playerStats.get(username).suspicionScore;
    }
}

module.exports = BotDetector;