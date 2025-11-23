// services/PaymentProcessor.js
const { Connection, PublicKey, Transaction, sendAndConfirmTransaction, getLatestBlockhash } = require('@solana/web3.js');
const { createTransferCheckedInstruction, getAssociatedTokenAddress, createAssociatedTokenAccountInstruction, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID } = require('@solana/spl-token');
const PaymentQueue = require('../models/PaymentQueue');

class PaymentProcessor {
    constructor(config) {
        // ✅ CRITICAL FIX: Validate config before using it
        if (!config) {
            throw new Error('PaymentProcessor requires a valid config object');
        }
        
        // Validate all required config properties
        const requiredProps = {
            'connection': 'Solana Connection instance',
            'io': 'Socket.io instance for notifications',
            'TREASURY_KEYPAIR': 'Treasury keypair for signing transactions',
            'USDC_MINT': 'USDC mint public key',
            'TREASURY_WALLET': 'Treasury wallet public key',
            'rpcEndpoints': 'Array of RPC endpoints for failover'
        };
        
        for (const [prop, description] of Object.entries(requiredProps)) {
            if (!config[prop]) {
                throw new Error(`PaymentProcessor config missing required property: ${prop} (${description})`);
            }
        }
        
        // Additional validation for specific types
        if (!Array.isArray(config.rpcEndpoints) || config.rpcEndpoints.length === 0) {
            throw new Error('PaymentProcessor config.rpcEndpoints must be a non-empty array');
        }
        
        this.config = config;
        this.isProcessing = false;
        this.processInterval = null;
        
        console.log('✅ PaymentProcessor initialized with validated config');
    }

    // Start the payment processor
    startProcessing(intervalMs = 60000) { // Default: process every minute
        if (this.processInterval) {
            clearInterval(this.processInterval);
        }
        this.processInterval = setInterval(() => this.processPaymentQueue(), intervalMs);
        console.log(`Payment processor started with ${intervalMs}ms interval`);

        // Process immediately on startup
        this.processPaymentQueue();

        return this;
    }

    // Stop the payment processor
    stopProcessing() {
        if (this.processInterval) {
            clearInterval(this.processInterval);
            this.processInterval = null;
            console.log('Payment processor stopped');
        }
        return this;
    }

    // Queue a new payment
    async queuePayment(recipientWallet, amount, gameId, betAmount, metadata = {}) {
        try {
            // ✅ ADDED: Validate config is still available
            if (!this.config || !this.config.connection) {
                throw new Error('PaymentProcessor config invalid - connection not available');
            }
            
            // NEW: Pre-check treasury SOL balance (needs ~0.005 SOL for fees + ATA)
            const treasuryBalance = await this.config.connection.getBalance(this.config.TREASURY_WALLET);
            const minSol = 0.005 * 1e9; // 0.005 SOL in lamports
            if (treasuryBalance < minSol) {
                const error = new Error(`Treasury low on SOL: ${treasuryBalance / 1e9} SOL (needs at least ${minSol / 1e9})`);
                console.error({ level: 'error', event: 'queuePayment', gameId, error: error.message });
                throw error;
            }

            const payment = await PaymentQueue.queuePayment(
                recipientWallet,
                amount,
                gameId,
                betAmount,
                metadata
            );
            console.log({ level: 'info', event: 'queuePayment', paymentId: payment._id, amount, recipientWallet, gameId });
            
            // If we're not currently processing, kick off processing
            if (!this.isProcessing) {
                this.processPaymentQueue();
            }
            
            return payment;
        } catch (error) {
            console.error({ level: 'error', event: 'queuePayment', gameId, error: error.message });
            throw error;
        }
    }

    // Process the payment queue
    async processPaymentQueue() {
        if (this.isProcessing) {
            // Already processing, don't overlap
            return;
        }
        this.isProcessing = true;
        console.log({ level: 'info', event: 'processPaymentQueue', message: 'Starting batch' });

        try {
            // ✅ ADDED: Validate config before processing
            if (!this.config || !this.config.connection || !this.config.io) {
                throw new Error('PaymentProcessor config invalid - cannot process payments');
            }
            
            const pendingPayments = await PaymentQueue.getPendingPayments(5); // Process 5 at a time
            
            if (pendingPayments.length === 0) {
                console.log({ level: 'info', event: 'processPaymentQueue', message: 'No pending payments' });
                this.isProcessing = false;
                return;
            }
            
            console.log({ level: 'info', event: 'processPaymentQueue', count: pendingPayments.length });
            
            // Process each payment sequentially
            for (const payment of pendingPayments) {
                await this.processPayment(payment);
                
                // Small delay between transactions
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
            
        } catch (error) {
            console.error({ level: 'error', event: 'processPaymentQueue', error: error.message });
        } finally {
            this.isProcessing = false;
        }
    }

    // ✅ IMPROVED: Process a single payment with better validation and error handling
    async processPayment(payment) {
        console.log({ level: 'info', event: 'processPayment', paymentId: payment._id, amount: payment.amount, wallet: payment.recipientWallet });
        
        // ✅ NEW: Validate payment object has required methods
        if (!payment || typeof payment.markProcessing !== 'function') {
            console.error({
                level: 'critical',
                event: 'processPayment',
                paymentId: payment?._id,
                error: 'Payment object missing markProcessing method',
                message: 'This usually means the payment was fetched with .lean(). Check PaymentQueue.getPendingPayments().'
            });
            
            // Try to recover by refetching as Mongoose document
            try {
                if (payment && payment._id) {
                    const freshPayment = await PaymentQueue.findById(payment._id);
                    if (freshPayment && typeof freshPayment.markProcessing === 'function') {
                        console.log('✅ Successfully refetched payment as Mongoose document');
                        payment = freshPayment;
                    } else {
                        throw new Error('Could not recover Mongoose document with methods');
                    }
                } else {
                    throw new Error('Payment object has no _id for refetching');
                }
            } catch (refetchError) {
                console.error({
                    level: 'critical',
                    event: 'processPayment',
                    paymentId: payment?._id,
                    error: 'Failed to refetch payment document',
                    details: refetchError.message
                });
                return; // Skip this payment
            }
        }
        
        let dbUpdateError = null; // Track DB errors for rollback
        
        try {
            // ✅ ADDED: Validate config before processing
            if (!this.config || !this.config.connection) {
                throw new Error('PaymentProcessor config invalid - connection not available');
            }
            
            // Mark as processing (with try-catch for rollback)
            try {
                await payment.markProcessing();
            } catch (dbError) {
                dbUpdateError = dbError;
                throw new Error(`Failed to update DB status: ${dbError.message}`);
            }
            
            // Send the actual payment
            const signature = await this.sendPayment(
                payment.recipientWallet, 
                payment.amount
            );
            
            // Mark payment as completed (with try-catch)
            try {
                await payment.markCompleted(signature);
            } catch (dbError) {
                dbUpdateError = dbError;
                // Rollback: Re-mark as processing? Or emit alert—here, throw to log
                throw new Error(`DB completion update failed: ${dbError.message}. Tx succeeded but status not updated.`);
            }
            
            console.log({ level: 'info', event: 'processPayment', paymentId: payment._id, signature, status: 'completed' });
            
            // Emit success event if socket is available
            if (this.config.io) {
                this.config.io.to(`wallet:${payment.recipientWallet}`).emit('paymentCompleted', {
                    amount: payment.amount,
                    transactionSignature: signature,
                    gameId: payment.gameId
                });
            }
            
            return signature;
        } catch (error) {
            // Enhanced error handling with DB rollback
            console.error({ 
                level: 'error', 
                event: 'processPayment', 
                paymentId: payment._id, 
                error: error.message, 
                dbError: dbUpdateError?.message,
                stack: error.stack
            });
            
            if (dbUpdateError) {
                // Critical: DB failed first—don't mark failed, as it might be inconsistent
                console.error({ 
                    level: 'critical', 
                    event: 'processPayment', 
                    paymentId: payment._id, 
                    message: 'DB error during processing—manual intervention needed' 
                });
            } else {
                // Mark as failed with error message
                try {
                    // ✅ ADDED: Check if markFailed method exists before calling
                    if (typeof payment.markFailed === 'function') {
                        await payment.markFailed(error.message || 'Unknown error');
                    } else {
                        // Fallback: Direct DB update
                        await PaymentQueue.findByIdAndUpdate(payment._id, {
                            status: 'failed',
                            errorMessage: error.message || 'Unknown error',
                            $inc: { attempts: 1 }
                        });
                    }
                } catch (markError) {
                    console.error({ 
                        level: 'error', 
                        event: 'processPayment', 
                        paymentId: payment._id, 
                        markError: markError.message 
                    });
                }
            }
            
            // Emit failure event if socket is available
            if (this.config && this.config.io) {
                this.config.io.to(`wallet:${payment.recipientWallet}`).emit('paymentFailed', {
                    paymentId: payment._id.toString(),
                    error: error.message || 'Unknown error',
                    gameId: payment.gameId
                });
            }
            
            throw error;
        }
    }

    // Send a payment using Solana
    async sendPayment(recipientWalletAddress, amount) {
        const MAX_RETRIES = 3;
        let currentRetry = 0;
        let currentEndpointIndex = Math.floor(Math.random() * this.config.rpcEndpoints.length);
        let connection = this.config.connection;
        
        while (currentRetry < MAX_RETRIES) {
            try {
                console.log({ level: 'info', event: 'sendPayment', attempt: currentRetry + 1, amount, wallet: recipientWalletAddress, rpc: connection.rpcEndpoint });
                
                const recipientPublicKey = new PublicKey(recipientWalletAddress);
                
                // Get token accounts for treasury and recipient
                const treasuryTokenAccount = await this.findAssociatedTokenAddress(
                    this.config.TREASURY_WALLET,
                    this.config.USDC_MINT
                );
                
                const recipientTokenAccount = await this.findAssociatedTokenAddress(
                    recipientPublicKey,
                    this.config.USDC_MINT
                );
                
                // Create transaction
                const transaction = new Transaction();
                
                // Check if recipient ATA exists and create if not
                const recipientTokenAccountInfo = await connection.getAccountInfo(recipientTokenAccount);
                if (!recipientTokenAccountInfo) {
                    console.log({ level: 'info', event: 'sendPayment', message: `Creating ATA for ${recipientWalletAddress}` });
                    transaction.add(
                        createAssociatedTokenAccountInstruction(
                            this.config.TREASURY_WALLET,  // payer (treasury pays the fee)
                            recipientTokenAccount,
                            recipientPublicKey,
                            this.config.USDC_MINT
                        )
                    );
                }
                
                // Create transfer instruction
                const transferIx = createTransferCheckedInstruction(
                    treasuryTokenAccount,
                    this.config.USDC_MINT,
                    recipientTokenAccount,
                    this.config.TREASURY_WALLET,
                    Math.floor(amount * Math.pow(10, 6)), // Convert to USDC decimals
                    6
                );
                transaction.add(transferIx);
                
                transaction.feePayer = this.config.TREASURY_WALLET;
                
                // Use getLatestBlockhash instead of getRecentBlockhash
                console.log({ level: 'info', event: 'sendPayment', message: 'Getting latest blockhash...' });
                const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
                transaction.recentBlockhash = blockhash;
                transaction.lastValidBlockHeight = lastValidBlockHeight;
                
                // Sign and send transaction
                console.log({ level: 'info', event: 'sendPayment', message: 'Signing and sending...' });
                const signature = await sendAndConfirmTransaction(
                    connection,
                    transaction,
                    [this.config.TREASURY_KEYPAIR],
                    {
                        skipPreflight: false,
                        preflightCommitment: 'confirmed',
                        commitment: 'confirmed',
                        maxRetries: 5
                    }
                );
                
                console.log({ level: 'info', event: 'sendPayment', signature, status: 'success' });
                return signature;
            } catch (error) {
                console.error({ level: 'error', event: 'sendPayment', attempt: currentRetry + 1, error: error.message, rpc: connection.rpcEndpoint });
                currentRetry++;
                
                if (currentRetry >= MAX_RETRIES) {
                    console.error({ level: 'error', event: 'sendPayment', message: 'Max retries reached' });
                    throw error;
                }
                
                // Try a different RPC endpoint
                currentEndpointIndex = (currentEndpointIndex + 1) % this.config.rpcEndpoints.length;
                const newEndpoint = this.config.rpcEndpoints[currentEndpointIndex];
                console.log({ level: 'info', event: 'sendPayment', message: `Switching RPC to ${newEndpoint}` });
                
                connection = new Connection(newEndpoint, {
                    commitment: 'confirmed',
                    confirmTransactionInitialTimeout: 60000
                });
                
                // Exponential backoff
                const waitTime = Math.pow(2, currentRetry) * 1000;
                console.log({ level: 'info', event: 'sendPayment', message: `Waiting ${waitTime}ms before retry` });
                await new Promise(resolve => setTimeout(resolve, waitTime));
            }
        }

        throw new Error('Failed to send payment after multiple attempts');
    }

    // Helper to find associated token address
    async findAssociatedTokenAddress(walletAddress, tokenMintAddress) {
        return await getAssociatedTokenAddress(
            tokenMintAddress,
            walletAddress,
            false,
            TOKEN_PROGRAM_ID,
            ASSOCIATED_TOKEN_PROGRAM_ID
        );
    }

    // Get payment status by ID
    async getPaymentStatus(paymentId) {
        return PaymentQueue.findById(paymentId);
    }

    // Get all payments for a wallet
    async getWalletPayments(walletAddress) {
        return PaymentQueue.find({ recipientWallet: walletAddress })
            .sort({ createdAt: -1 });
    }

    // Handle failed payments (admin function)
    async retryFailedPayments() {
        const failedPayments = await PaymentQueue.find({
            status: 'failed',
            attempts: { $lt: 5 }
        }).sort({ createdAt: 1 });
        
        console.log({ level: 'info', event: 'retryFailedPayments', count: failedPayments.length });

        if (failedPayments.length === 0) {
            return { success: true, message: 'No failed payments to retry' };
        }

        let successCount = 0;
        let failCount = 0;

        for (const payment of failedPayments) {
            try {
                await this.processPayment(payment);
                successCount++;
            } catch (error) {
                failCount++;
                console.error({ level: 'error', event: 'retryFailedPayments', paymentId: payment._id, error: error.message });
            }
            
            // Add delay between retries
            await new Promise(resolve => setTimeout(resolve, 3000));
        }

        return {
            success: true,
            message: `Retried ${failedPayments.length} payments: ${successCount} succeeded, ${failCount} failed`,
            details: { successCount, failCount, total: failedPayments.length }
        };
    }

    // ✅ NEW: Test configuration method for debugging
    async testConfiguration() {
        console.log('🧪 Testing PaymentProcessor configuration...');
        
        const tests = [
            { name: 'Config exists', check: () => !!this.config },
            { name: 'Connection exists', check: () => !!this.config?.connection },
            { name: 'IO exists', check: () => !!this.config?.io },
            { name: 'Treasury keypair exists', check: () => !!this.config?.TREASURY_KEYPAIR },
            { name: 'USDC mint exists', check: () => !!this.config?.USDC_MINT },
            { name: 'Treasury wallet exists', check: () => !!this.config?.TREASURY_WALLET },
            { name: 'RPC endpoints array exists', check: () => Array.isArray(this.config?.rpcEndpoints) && this.config.rpcEndpoints.length > 0 },
            { name: 'Can query payments', check: async () => {
                const count = await PaymentQueue.countDocuments();
                return count >= 0;
            }}
        ];
        
        for (const test of tests) {
            try {
                const result = test.check instanceof Function ? await test.check() : test.check;
                console.log(`${result ? '✅' : '❌'} ${test.name}: ${result}`);
            } catch (error) {
                console.log(`❌ ${test.name}: ${error.message}`);
            }
        }
        
        console.log('🧪 Configuration test complete');
    }
}

module.exports = PaymentProcessor;