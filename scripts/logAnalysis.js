// scripts/logAnalysis.js
// Log analysis queries and monitoring scripts
// Query structured logs for security insights

const fs = require('fs');
const readline = require('readline');
const path = require('path');

// ============================================================================
// LOG READER
// ============================================================================

class LogAnalyzer {
    constructor(logDir = 'logs') {
        this.logDir = logDir;
    }
    
    /**
     * Read and parse log file
     */
    async *readLogFile(filename) {
        const filepath = path.join(this.logDir, filename);
        
        if (!fs.existsSync(filepath)) {
            console.error(`Log file not found: ${filepath}`);
            return;
        }
        
        const fileStream = fs.createReadStream(filepath);
        const rl = readline.createInterface({
            input: fileStream,
            crlfDelay: Infinity
        });
        
        for await (const line of rl) {
            try {
                yield JSON.parse(line);
            } catch (e) {
                // Skip invalid JSON lines
            }
        }
    }
    
    /**
     * Get log files for date range
     */
    getLogFiles(type = 'app', startDate, endDate = new Date()) {
        const files = fs.readdirSync(this.logDir);
        const pattern = new RegExp(`^${type}-(\\d{4}-\\d{2}-\\d{2})\\.log$`);
        
        return files
            .filter(f => pattern.test(f))
            .filter(f => {
                const match = f.match(pattern);
                if (!match) return false;
                
                const fileDate = new Date(match[1]);
                return fileDate >= startDate && fileDate <= endDate;
            })
            .sort()
            .reverse(); // Most recent first
    }
    
    // ========================================================================
    // SECURITY QUERIES
    // ========================================================================
    
    /**
     * Find failed login attempts by IP
     */
    async findFailedLogins(hours = 24) {
        const since = Date.now() - (hours * 3600000);
        const failures = new Map();
        
        const files = this.getLogFiles('security', new Date(since));
        
        for (const file of files) {
            for await (const log of this.readLogFile(file)) {
                if (log.event === 'auth_failed' && 
                    new Date(log.timestamp).getTime() > since) {
                    
                    const key = log.ip || 'unknown';
                    if (!failures.has(key)) {
                        failures.set(key, []);
                    }
                    failures.get(key).push(log);
                }
            }
        }
        
        // Sort by count
        return Array.from(failures.entries())
            .map(([ip, logs]) => ({
                ip,
                count: logs.length,
                wallets: [...new Set(logs.map(l => l.walletAddress))],
                firstAttempt: logs[0].timestamp,
                lastAttempt: logs[logs.length - 1].timestamp
            }))
            .sort((a, b) => b.count - a.count);
    }
    
    /**
     * Find validation failures
     */
    async findValidationFailures(hours = 24) {
        const since = Date.now() - (hours * 3600000);
        const failures = new Map();
        
        const files = this.getLogFiles('security', new Date(since));
        
        for (const file of files) {
            for await (const log of this.readLogFile(file)) {
                if (log.event === 'validation_failure' && 
                    new Date(log.timestamp).getTime() > since) {
                    
                    const key = log.identifier || 'unknown';
                    if (!failures.has(key)) {
                        failures.set(key, []);
                    }
                    failures.get(key).push(log);
                }
            }
        }
        
        return Array.from(failures.entries())
            .map(([identifier, logs]) => ({
                identifier,
                count: logs.length,
                events: [...new Set(logs.map(l => l.eventName))],
                errors: [...new Set(logs.map(l => l.error))]
            }))
            .sort((a, b) => b.count - a.count);
    }
    
    /**
     * Find auto-blocked identifiers
     */
    async findBlockedIdentifiers(hours = 24) {
        const since = Date.now() - (hours * 3600000);
        const blocked = [];
        
        const files = this.getLogFiles('security', new Date(since));
        
        for (const file of files) {
            for await (const log of this.readLogFile(file)) {
                if (log.event === 'auto_blocked' && 
                    new Date(log.timestamp).getTime() > since) {
                    blocked.push({
                        identifier: log.identifier,
                        reason: log.reason,
                        violationCount: log.violationCount,
                        timestamp: log.timestamp
                    });
                }
            }
        }
        
        return blocked.sort((a, b) => 
            new Date(b.timestamp) - new Date(a.timestamp)
        );
    }
    
    /**
     * Find suspicious bot activity
     */
    async findBotActivity(hours = 24) {
        const since = Date.now() - (hours * 3600000);
        const suspicious = [];
        
        const files = this.getLogFiles('security', new Date(since));
        
        for (const file of files) {
            for await (const log of this.readLogFile(file)) {
                if ((log.event === 'bot_suspicion_detected' || 
                     log.event === 'recaptcha_low_score') && 
                    new Date(log.timestamp).getTime() > since) {
                    suspicious.push({
                        walletAddress: log.walletAddress,
                        event: log.event,
                        score: log.score || log.suspicionScore,
                        eventName: log.eventName,
                        timestamp: log.timestamp
                    });
                }
            }
        }
        
        return suspicious.sort((a, b) => 
            new Date(b.timestamp) - new Date(a.timestamp)
        );
    }
    
    /**
     * Find rate limit violations
     */
    async findRateLimitViolations(hours = 24) {
        const since = Date.now() - (hours * 3600000);
        const violations = new Map();
        
        const files = this.getLogFiles('security', new Date(since));
        
        for (const file of files) {
            for await (const log of this.readLogFile(file)) {
                if (log.event === 'rate_limit_exceeded' && 
                    new Date(log.timestamp).getTime() > since) {
                    
                    const key = `${log.identifier}:${log.eventName}`;
                    if (!violations.has(key)) {
                        violations.set(key, []);
                    }
                    violations.get(key).push(log);
                }
            }
        }
        
        return Array.from(violations.entries())
            .map(([key, logs]) => {
                const [identifier, eventName] = key.split(':');
                return {
                    identifier,
                    eventName,
                    count: logs.length,
                    firstViolation: logs[0].timestamp,
                    lastViolation: logs[logs.length - 1].timestamp
                };
            })
            .sort((a, b) => b.count - a.count);
    }
    
    // ========================================================================
    // AUDIT QUERIES
    // ========================================================================
    
    /**
     * Find transactions by wallet
     */
    async findTransactions(walletAddress, hours = 24) {
        const since = Date.now() - (hours * 3600000);
        const transactions = [];
        
        const files = this.getLogFiles('audit', new Date(since));
        
        for (const file of files) {
            for await (const log of this.readLogFile(file)) {
                if (log.event === 'transaction_verified' && 
                    log.walletAddress === walletAddress &&
                    new Date(log.timestamp).getTime() > since) {
                    transactions.push({
                        amount: log.amount,
                        signature: log.signature,
                        timestamp: log.timestamp
                    });
                }
            }
        }
        
        return transactions.sort((a, b) => 
            new Date(b.timestamp) - new Date(a.timestamp)
        );
    }
    
    /**
     * Find games by wallet
     */
    async findGames(walletAddress, hours = 24) {
        const since = Date.now() - (hours * 3600000);
        const games = [];
        
        const files = this.getLogFiles('audit', new Date(since));
        
        for (const file of files) {
            for await (const log of this.readLogFile(file)) {
                if (log.event === 'game_completed' && 
                    (log.winner === walletAddress || log.loser === walletAddress) &&
                    new Date(log.timestamp).getTime() > since) {
                    games.push({
                        roomId: log.roomId,
                        won: log.winner === walletAddress,
                        opponent: log.winner === walletAddress ? log.loser : log.winner,
                        betAmount: log.betAmount,
                        winnings: log.winner === walletAddress ? log.winnings : 0,
                        gameMode: log.gameMode,
                        timestamp: log.timestamp
                    });
                }
            }
        }
        
        return games.sort((a, b) => 
            new Date(b.timestamp) - new Date(a.timestamp)
        );
    }
    
    /**
     * Find payment activity
     */
    async findPayments(hours = 24) {
        const since = Date.now() - (hours * 3600000);
        const payments = new Map();
        
        const files = this.getLogFiles('audit', new Date(since));
        
        for (const file of files) {
            for await (const log of this.readLogFile(file)) {
                if (log.event === 'payment_processed' && 
                    new Date(log.timestamp).getTime() > since) {
                    
                    const status = log.status || 'unknown';
                    if (!payments.has(status)) {
                        payments.set(status, []);
                    }
                    payments.get(status).push(log);
                }
            }
        }
        
        const summary = {};
        for (const [status, logs] of payments.entries()) {
            summary[status] = {
                count: logs.length,
                totalAmount: logs.reduce((sum, l) => sum + (l.amount || 0), 0),
                wallets: [...new Set(logs.map(l => l.walletAddress))]
            };
        }
        
        return summary;
    }
    
    // ========================================================================
    // PERFORMANCE QUERIES
    // ========================================================================
    
    /**
     * Find slow operations
     */
    async findSlowOperations(threshold = 1000, hours = 24) {
        const since = Date.now() - (hours * 3600000);
        const slow = [];
        
        const files = this.getLogFiles('performance', new Date(since));
        
        for (const file of files) {
            for await (const log of this.readLogFile(file)) {
                if (log.duration >= threshold && 
                    new Date(log.timestamp).getTime() > since) {
                    slow.push({
                        event: log.event || log.message,
                        duration: log.duration,
                        ...log
                    });
                }
            }
        }
        
        return slow.sort((a, b) => b.duration - a.duration);
    }
    
    /**
     * Calculate average response times
     */
    async calculateAverageResponseTimes(hours = 24) {
        const since = Date.now() - (hours * 3600000);
        const times = new Map();
        
        const files = this.getLogFiles('performance', new Date(since));
        
        for (const file of files) {
            for await (const log of this.readLogFile(file)) {
                if (log.duration && new Date(log.timestamp).getTime() > since) {
                    const event = log.event || log.message;
                    if (!times.has(event)) {
                        times.set(event, []);
                    }
                    times.get(event).push(log.duration);
                }
            }
        }
        
        const averages = {};
        for (const [event, durations] of times.entries()) {
            const sorted = durations.sort((a, b) => a - b);
            averages[event] = {
                count: durations.length,
                min: sorted[0],
                max: sorted[sorted.length - 1],
                avg: durations.reduce((sum, d) => sum + d, 0) / durations.length,
                p50: sorted[Math.floor(sorted.length * 0.5)],
                p95: sorted[Math.floor(sorted.length * 0.95)],
                p99: sorted[Math.floor(sorted.length * 0.99)]
            };
        }
        
        return averages;
    }
    
    // ========================================================================
    // ERROR QUERIES
    // ========================================================================
    
    /**
     * Find errors by type
     */
    async findErrors(hours = 24) {
        const since = Date.now() - (hours * 3600000);
        const errors = new Map();
        
        const files = this.getLogFiles('error', new Date(since));
        
        for (const file of files) {
            for await (const log of this.readLogFile(file)) {
                if (log.level === 'error' && 
                    new Date(log.timestamp).getTime() > since) {
                    
                    const key = log.message || 'unknown';
                    if (!errors.has(key)) {
                        errors.set(key, []);
                    }
                    errors.get(key).push(log);
                }
            }
        }
        
        return Array.from(errors.entries())
            .map(([message, logs]) => ({
                message,
                count: logs.length,
                errorIds: logs.map(l => l.errorId).filter(Boolean),
                firstOccurrence: logs[0].timestamp,
                lastOccurrence: logs[logs.length - 1].timestamp
            }))
            .sort((a, b) => b.count - a.count);
    }
    
    /**
     * Find errors for specific user
     */
    async findUserErrors(walletAddress, hours = 24) {
        const since = Date.now() - (hours * 3600000);
        const errors = [];
        
        const files = this.getLogFiles('error', new Date(since));
        
        for (const file of files) {
            for await (const log of this.readLogFile(file)) {
                if (log.level === 'error' && 
                    log.walletAddress === walletAddress &&
                    new Date(log.timestamp).getTime() > since) {
                    errors.push({
                        errorId: log.errorId,
                        message: log.message,
                        context: log.context,
                        timestamp: log.timestamp
                    });
                }
            }
        }
        
        return errors.sort((a, b) => 
            new Date(b.timestamp) - new Date(a.timestamp)
        );
    }
}

// ============================================================================
// CLI INTERFACE
// ============================================================================

async function main() {
    const analyzer = new LogAnalyzer();
    const command = process.argv[2];
    const hours = parseInt(process.argv[3]) || 24;
    
    switch (command) {
        case 'failed-logins':
            console.log('Failed Login Attempts (last', hours, 'hours):');
            console.log(await analyzer.findFailedLogins(hours));
            break;
            
        case 'validation-failures':
            console.log('Validation Failures (last', hours, 'hours):');
            console.log(await analyzer.findValidationFailures(hours));
            break;
            
        case 'blocked':
            console.log('Blocked Identifiers (last', hours, 'hours):');
            console.log(await analyzer.findBlockedIdentifiers(hours));
            break;
            
        case 'bot-activity':
            console.log('Bot Activity (last', hours, 'hours):');
            console.log(await analyzer.findBotActivity(hours));
            break;
            
        case 'rate-limits':
            console.log('Rate Limit Violations (last', hours, 'hours):');
            console.log(await analyzer.findRateLimitViolations(hours));
            break;
            
        case 'slow':
            const threshold = parseInt(process.argv[4]) || 1000;
            console.log('Slow Operations >', threshold, 'ms (last', hours, 'hours):');
            console.log(await analyzer.findSlowOperations(threshold, hours));
            break;
            
        case 'response-times':
            console.log('Average Response Times (last', hours, 'hours):');
            console.log(await analyzer.calculateAverageResponseTimes(hours));
            break;
            
        case 'errors':
            console.log('Errors (last', hours, 'hours):');
            console.log(await analyzer.findErrors(hours));
            break;
            
        case 'payments':
            console.log('Payment Summary (last', hours, 'hours):');
            console.log(await analyzer.findPayments(hours));
            break;
            
        case 'user':
            const wallet = process.argv[4];
            if (!wallet) {
                console.error('Usage: node logAnalysis.js user <hours> <wallet>');
                process.exit(1);
            }
            console.log(`User Activity for ${wallet} (last ${hours} hours):`);
            console.log('Transactions:', await analyzer.findTransactions(wallet, hours));
            console.log('Games:', await analyzer.findGames(wallet, hours));
            console.log('Errors:', await analyzer.findUserErrors(wallet, hours));
            break;
            
        default:
            console.log('Usage: node logAnalysis.js <command> [hours]');
            console.log('Commands:');
            console.log('  failed-logins      - Find failed login attempts');
            console.log('  validation-failures- Find validation failures');
            console.log('  blocked           - Find blocked identifiers');
            console.log('  bot-activity      - Find suspicious bot activity');
            console.log('  rate-limits       - Find rate limit violations');
            console.log('  slow [threshold]  - Find slow operations');
            console.log('  response-times    - Calculate average response times');
            console.log('  errors            - Find errors');
            console.log('  payments          - Payment summary');
            console.log('  user <wallet>     - User activity report');
    }
}

// Run if called directly
if (require.main === module) {
    main().catch(console.error);
}

module.exports = LogAnalyzer;