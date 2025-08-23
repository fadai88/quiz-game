class BotDetector {
    constructor() {
        this.playerStats = new Map();
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
}

module.exports = BotDetector;
