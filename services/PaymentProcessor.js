// services/PaymentProcessor.js
const { Connection, PublicKey, Transaction, sendAndConfirmTransaction } = require('@solana/web3.js');
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
            const payment = await PaymentQueue.queuePayment(
                recipientWallet,
                amount,
                gameId,
                betAmount,
                metadata
            );
            console.log(`Payment queued: ${amount} USDC to ${recipientWallet} (Game: ${gameId})`);
            
            // If we're not currently processing, kick off processing
            if (!this.isProcessing) {
                this.processPaymentQueue();
            }
            
            return payment;
        } catch (error) {
            console.error('Error queueing payment:', error);
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
        console.log('Starting payment queue processing');

        try {
            const pendingPayments = await PaymentQueue.getPendingPayments(5); // Process 5 at a time
            
            if (pendingPayments.length === 0) {
                console.log('No pending payments to process');
                this.isProcessing = false;
                return;
            }
            
            console.log(`Processing ${pendingPayments.length} pending payments`);
            
            // Process each payment sequentially
            for (const payment of pendingPayments) {
                await this.processPayment(payment);
                
                // Small delay between transactions
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
            
        } catch (error) {
            console.error('Error processing payment queue:', error);
        } finally {
            this.isProcessing = false;
        }
    }

    // Process a single payment
    async processPayment(payment) {
        console.log(`Processing payment ${payment._id} for ${payment.amount} USDC to ${payment.recipientWallet}`);
        try {
            // Mark as processing
            await payment.markProcessing();
            
            // Send the actual payment
            const signature = await this.sendPayment(
                payment.recipientWallet, 
                payment.amount
            );
            
            // Mark payment as completed
            await payment.markCompleted(signature);
            
            console.log(`Payment completed: ${signature}`);
            
            // Emit success event if socket is available
            if (this.config.io) {
                this.config.io.to(payment.recipientWallet).emit('paymentCompleted', {
                    amount: payment.amount,
                    transactionSignature: signature,
                    gameId: payment.gameId
                });
            }
            
            return signature;
        } catch (error) {
            console.error(`Payment ${payment._id} failed:`, error);
            
            // Mark as failed with error message
            await payment.markFailed(error.message || 'Unknown error');
            
            // Emit failure event if socket is available
            if (this.config.io) {
                this.config.io.to(payment.recipientWallet).emit('paymentFailed', {
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
        let currentEndpointIndex = 0;
        let connection = this.config.connection;
        while (currentRetry < MAX_RETRIES) {
            try {
                console.log(`Attempt ${currentRetry + 1} to send ${amount} USDC to ${recipientWalletAddress}`);
                
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
                    console.log(`Creating ATA for recipient ${recipientWalletAddress}`);
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
                
                // Try to get recent blockhash with retry mechanism
                let blockhashObj;
                let blockhashRetries = 3;
                
                while (blockhashRetries > 0) {
                    try {
                        console.log('Getting recent blockhash...');
                        blockhashObj = await connection.getRecentBlockhash('confirmed');
                        break;
                    } catch (blockhashError) {
                        console.warn(`Blockhash fetch attempt ${4 - blockhashRetries} failed:`, blockhashError.message);
                        blockhashRetries--;
                        
                        if (blockhashRetries === 0) {
                            // Try a different RPC endpoint
                            currentEndpointIndex = (currentEndpointIndex + 1) % this.config.rpcEndpoints.length;
                            const newEndpoint = this.config.rpcEndpoints[currentEndpointIndex];
                            console.log(`Switching to alternative RPC endpoint: ${newEndpoint}`);
                            
                            connection = new Connection(newEndpoint, {
                                commitment: 'confirmed',
                                confirmTransactionInitialTimeout: 60000
                            });
                            
                            // Reset blockhash retries with new connection
                            blockhashRetries = 2;
                            await new Promise(resolve => setTimeout(resolve, 1000));
                            continue;
                        }
                        
                        await new Promise(resolve => setTimeout(resolve, 1000));
                    }
                }
                
                transaction.recentBlockhash = blockhashObj.blockhash;
                
                // Sign and send transaction
                console.log('Signing and sending transaction...');
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
                
                console.log('Transaction successful:', signature);
                return signature;
            } catch (error) {
                console.error(`Payment attempt ${currentRetry + 1} failed:`, error);
                currentRetry++;
                
                if (currentRetry >= MAX_RETRIES) {
                    console.error('Max retries reached, payment failed');
                    throw error;
                }
                
                // Try a different RPC endpoint
                currentEndpointIndex = (currentEndpointIndex + 1) % this.config.rpcEndpoints.length;
                const newEndpoint = this.config.rpcEndpoints[currentEndpointIndex];
                console.log(`Switching to alternative RPC endpoint: ${newEndpoint}`);
                
                connection = new Connection(newEndpoint, {
                    commitment: 'confirmed',
                    confirmTransactionInitialTimeout: 60000
                });
                
                // Exponential backoff
                const waitTime = Math.pow(2, currentRetry) * 1000;
                console.log(`Waiting ${waitTime}ms before retry...`);
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
        
        console.log(`Found ${failedPayments.length} failed payments to retry`);

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
                console.error(`Failed to retry payment ${payment._id}:`, error);
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