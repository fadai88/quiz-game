// services/PaymentProcessor.js
const { Connection, PublicKey, Transaction, sendAndConfirmTransaction, getLatestBlockhash } = require('@solana/web3.js'); // FIXED: Import getLatestBlockhash
const { createTransferCheckedInstruction, getAssociatedTokenAddress, createAssociatedTokenAccountInstruction, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID } = require('@solana/spl-token');
const PaymentQueue = require('../models/PaymentQueue');

class PaymentProcessor {
    constructor(config) {
        this.config = config;
        this.isProcessing = false;
        this.processInterval = null;
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
            console.log({ level: 'info', event: 'queuePayment', paymentId: payment._id, amount, recipientWallet, gameId }); // NEW: Structured log
            
            // If we're not currently processing, kick off processing
            if (!this.isProcessing) {
                this.processPaymentQueue();
            }
            
            return payment;
        } catch (error) {
            console.error({ level: 'error', event: 'queuePayment', gameId, error: error.message }); // NEW: Structured log
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
        console.log({ level: 'info', event: 'processPaymentQueue', message: 'Starting batch' }); // NEW: Structured log

        try {
            const pendingPayments = await PaymentQueue.getPendingPayments(5); // Process 5 at a time
            
            if (pendingPayments.length === 0) {
                console.log({ level: 'info', event: 'processPaymentQueue', message: 'No pending payments' }); // NEW: Structured log
                this.isProcessing = false;
                return;
            }
            
            console.log({ level: 'info', event: 'processPaymentQueue', count: pendingPayments.length }); // NEW: Structured log
            
            // Process each payment sequentially
            for (const payment of pendingPayments) {
                await this.processPayment(payment);
                
                // Small delay between transactions
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
            
        } catch (error) {
            console.error({ level: 'error', event: 'processPaymentQueue', error: error.message }); // NEW: Structured log
        } finally {
            this.isProcessing = false;
        }
    }

    // Process a single payment
    async processPayment(payment) {
        console.log({ level: 'info', event: 'processPayment', paymentId: payment._id, amount: payment.amount, wallet: payment.recipientWallet }); // NEW: Structured log
        let dbUpdateError = null; // NEW: Track DB errors for rollback
        try {
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
            
            console.log({ level: 'info', event: 'processPayment', paymentId: payment._id, signature, status: 'completed' }); // NEW: Structured log
            
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
            // NEW: Enhanced error handling with DB rollback
            console.error({ level: 'error', event: 'processPayment', paymentId: payment._id, error: error.message, dbError: dbUpdateError?.message }); // NEW: Structured log
            
            if (dbUpdateError) {
                // Critical: DB failed first—don't mark failed, as it might be inconsistent
                console.error({ level: 'critical', event: 'processPayment', paymentId: payment._id, message: 'DB error during processing—manual intervention needed' });
            } else {
                // Mark as failed with error message
                try {
                    await payment.markFailed(error.message || 'Unknown error');
                } catch (markError) {
                    console.error({ level: 'error', event: 'processPayment', paymentId: payment._id, markError: markError.message });
                }
            }
            
            // Emit failure event if socket is available
            if (this.config.io) {
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
        let currentEndpointIndex = Math.floor(Math.random() * this.config.rpcEndpoints.length); // NEW: Randomize initial endpoint
        let connection = this.config.connection;
        while (currentRetry < MAX_RETRIES) {
            try {
                console.log({ level: 'info', event: 'sendPayment', attempt: currentRetry + 1, amount, wallet: recipientWalletAddress, rpc: connection.rpcEndpoint }); // NEW: Structured log
                
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
                    console.log({ level: 'info', event: 'sendPayment', message: `Creating ATA for ${recipientWalletAddress}` }); // NEW: Structured log
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
                
                // FIXED: Use getLatestBlockhash instead of getRecentBlockhash
                console.log({ level: 'info', event: 'sendPayment', message: 'Getting latest blockhash...' }); // NEW: Structured log
                const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
                transaction.recentBlockhash = blockhash;
                transaction.lastValidBlockHeight = lastValidBlockHeight;
                
                // Sign and send transaction
                console.log({ level: 'info', event: 'sendPayment', message: 'Signing and sending...' }); // NEW: Structured log
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
                
                console.log({ level: 'info', event: 'sendPayment', signature, status: 'success' }); // NEW: Structured log
                return signature;
            } catch (error) {
                console.error({ level: 'error', event: 'sendPayment', attempt: currentRetry + 1, error: error.message, rpc: connection.rpcEndpoint }); // NEW: Structured log
                currentRetry++;
                
                if (currentRetry >= MAX_RETRIES) {
                    console.error({ level: 'error', event: 'sendPayment', message: 'Max retries reached' }); // NEW: Structured log
                    throw error;
                }
                
                // Try a different RPC endpoint
                currentEndpointIndex = (currentEndpointIndex + 1) % this.config.rpcEndpoints.length;
                const newEndpoint = this.config.rpcEndpoints[currentEndpointIndex];
                console.log({ level: 'info', event: 'sendPayment', message: `Switching RPC to ${newEndpoint}` }); // NEW: Structured log
                
                connection = new Connection(newEndpoint, {
                    commitment: 'confirmed',
                    confirmTransactionInitialTimeout: 60000
                });
                
                // Exponential backoff
                const waitTime = Math.pow(2, currentRetry) * 1000;
                console.log({ level: 'info', event: 'sendPayment', message: `Waiting ${waitTime}ms before retry` }); // NEW: Structured log
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
        
        console.log({ level: 'info', event: 'retryFailedPayments', count: failedPayments.length }); // NEW: Structured log

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
                console.error({ level: 'error', event: 'retryFailedPayments', paymentId: payment._id, error: error.message }); // NEW: Structured log
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
}

module.exports = PaymentProcessor;