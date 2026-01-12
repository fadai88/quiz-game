// services/TreasuryMonitor.js
const { getAssociatedTokenAddress } = require('@solana/spl-token');

/**
 * TreasuryMonitor - Monitors treasury wallet balance and sends alerts
 * Prevents payment failures due to insufficient funds
 */
class TreasuryMonitor {
    constructor(connection, treasuryWallet, usdcMint, options = {}) {
        this.connection = connection;
        this.treasuryWallet = treasuryWallet;
        this.usdcMint = usdcMint;
        
        // Configuration
        this.alertThreshold = options.alertThreshold || 10000000; // 10 USDC in atomic units
        this.criticalThreshold = options.criticalThreshold || 5000000; // 5 USDC
        this.alertCooldown = options.alertCooldown || 3600000; // 1 hour between alerts
        this.checkInterval = options.checkInterval || 300000; // 5 minutes
        
        // State
        this.lastAlertTime = 0;
        this.lastCriticalAlertTime = 0;
        this.monitorInterval = null;
        this.lastKnownBalance = null;
        
        // Callbacks
        this.onLowBalance = options.onLowBalance || null;
        this.onCriticalBalance = options.onCriticalBalance || null;
    }
    
    /**
     * Check current treasury balance
     * @returns {Promise<Object>} Balance info
     */
    async checkBalance() {
        try {
            // Get USDC token account
            const tokenAccount = await getAssociatedTokenAddress(
                this.usdcMint,
                this.treasuryWallet
            );
            
            // Get token balance
            const balance = await this.connection.getTokenAccountBalance(tokenAccount);
            const balanceAtomic = parseInt(balance.value.amount);
            const balanceUSDC = balanceAtomic / 1000000;
            
            // Also check SOL balance (needed for transaction fees)
            const solBalance = await this.connection.getBalance(this.treasuryWallet);
            const solBalanceSOL = solBalance / 1e9;
            
            // Log current balance
            console.log({
                level: 'info',
                event: 'treasuryBalance',
                usdcBalance: balanceUSDC,
                solBalance: solBalanceSOL,
                usdcThreshold: this.alertThreshold / 1000000,
                timestamp: new Date().toISOString()
            });
            
            // Store last known balance
            this.lastKnownBalance = {
                usdc: balanceAtomic,
                sol: solBalance,
                timestamp: Date.now()
            };
            
            // Check thresholds and send alerts
            const now = Date.now();
            
            // Critical alert (very low balance)
            if (balanceAtomic < this.criticalThreshold) {
                if (now - this.lastCriticalAlertTime > this.alertCooldown) {
                    console.error({
                        level: 'critical',
                        event: 'criticalTreasuryBalance',
                        usdcBalance: balanceUSDC,
                        threshold: this.criticalThreshold / 1000000,
                        message: '🚨 CRITICAL: Treasury almost empty! Immediate action required!'
                    });
                    
                    if (this.onCriticalBalance) {
                        await this.onCriticalBalance({
                            usdcBalance: balanceAtomic,
                            solBalance: solBalance,
                            threshold: this.criticalThreshold
                        });
                    }
                    
                    this.lastCriticalAlertTime = now;
                }
                return { status: 'critical', balanceAtomic, balanceUSDC, solBalanceSOL };
            }
            
            // Low balance alert
            if (balanceAtomic < this.alertThreshold) {
                if (now - this.lastAlertTime > this.alertCooldown) {
                    console.warn({
                        level: 'warning',
                        event: 'lowTreasuryBalance',
                        usdcBalance: balanceUSDC,
                        threshold: this.alertThreshold / 1000000,
                        message: '⚠️ WARNING: Treasury balance below threshold!'
                    });
                    
                    if (this.onLowBalance) {
                        await this.onLowBalance({
                            usdcBalance: balanceAtomic,
                            solBalance: solBalance,
                            threshold: this.alertThreshold
                        });
                    }
                    
                    this.lastAlertTime = now;
                }
                return { status: 'low', balanceAtomic, balanceUSDC, solBalanceSOL };
            }
            
            // Check SOL balance (need at least 0.01 SOL for fees)
            if (solBalanceSOL < 0.01) {
                console.warn({
                    level: 'warning',
                    event: 'lowSOLBalance',
                    solBalance: solBalanceSOL,
                    message: '⚠️ WARNING: Treasury low on SOL for transaction fees!'
                });
                
                return { status: 'low_sol', balanceAtomic, balanceUSDC, solBalanceSOL };
            }
            
            // Sufficient balance
            return { status: 'ok', balanceAtomic, balanceUSDC, solBalanceSOL };
            
        } catch (error) {
            console.error({
                level: 'error',
                event: 'treasuryBalanceCheckFailed',
                error: error.message,
                stack: error.stack
            });
            return { status: 'error', error: error.message };
        }
    }
    
    /**
     * Start monitoring treasury balance
     * @param {number} intervalMs - Check interval in milliseconds
     */
    startMonitoring(intervalMs) {
        if (this.monitorInterval) {
            console.log('Treasury monitoring already running, stopping existing monitor');
            this.stopMonitoring();
        }
        
        const interval = intervalMs || this.checkInterval;
        
        this.monitorInterval = setInterval(() => {
            this.checkBalance().catch(error => {
                console.error({
                    level: 'error',
                    event: 'treasuryMonitorError',
                    error: error.message
                });
            });
        }, interval);
        
        // Check immediately on start
        this.checkBalance().catch(error => {
            console.error({
                level: 'error',
                event: 'initialTreasuryCheckFailed',
                error: error.message
            });
        });
        
        console.log({
            level: 'info',
            event: 'treasuryMonitorStarted',
            checkInterval: interval / 1000,
            alertThreshold: this.alertThreshold / 1000000,
            criticalThreshold: this.criticalThreshold / 1000000
        });
    }
    
    /**
     * Stop monitoring
     */
    stopMonitoring() {
        if (this.monitorInterval) {
            clearInterval(this.monitorInterval);
            this.monitorInterval = null;
            console.log({
                level: 'info',
                event: 'treasuryMonitorStopped'
            });
        }
    }
    
    /**
     * Get last known balance without making a network call
     * @returns {Object|null} Last known balance or null
     */
    getLastKnownBalance() {
        return this.lastKnownBalance;
    }
    
    /**
     * Check if treasury has sufficient balance for a payment
     * Uses last known balance to avoid network calls
     * @param {number} amount - Amount in atomic units
     * @returns {boolean} True if sufficient balance
     */
    hasSufficientBalance(amount) {
        if (!this.lastKnownBalance) return true; // Assume yes if we haven't checked yet
        
        const age = Date.now() - this.lastKnownBalance.timestamp;
        if (age > 600000) { // 10 minutes old
            console.warn({
                level: 'warning',
                event: 'staleBalanceCheck',
                age: age / 1000,
                message: 'Balance data is stale, consider checking again'
            });
        }
        
        return this.lastKnownBalance.usdc >= amount;
    }
    
    /**
     * Format balance for display
     * @param {Object} balanceInfo - Balance info from checkBalance()
     * @returns {string} Formatted string
     */
    static formatBalance(balanceInfo) {
        if (!balanceInfo) return 'Unknown';
        
        const statusEmoji = {
            ok: '✅',
            low: '⚠️',
            critical: '🚨',
            low_sol: '⚠️',
            error: '❌'
        };
        
        const emoji = statusEmoji[balanceInfo.status] || '❓';
        return `${emoji} ${balanceInfo.balanceUSDC?.toFixed(2) || 'N/A'} USDC | ${balanceInfo.solBalanceSOL?.toFixed(4) || 'N/A'} SOL`;
    }
}

module.exports = TreasuryMonitor;