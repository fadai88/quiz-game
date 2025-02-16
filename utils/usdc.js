const { Connection, PublicKey, Transaction } = require('@solana/web3.js');
const { 
    createAssociatedTokenAccountInstruction, 
    getAssociatedTokenAddress, 
    TOKEN_PROGRAM_ID, 
    ASSOCIATED_TOKEN_PROGRAM_ID, 
    getAccount,
    createTransferCheckedInstruction
} = require('@solana/spl-token');
const config = require('../config/solana');

class USDCManager {
    constructor(connection) {
        this.connection = connection;
        this.usdcMint = config.USDC_MINT; // Already a PublicKey instance
    }

    async getOrCreateAssociatedTokenAccount(walletPublicKey) {
        try {
            const tokenAccount = await getAssociatedTokenAddress(
                this.usdcMint,
                walletPublicKey,
                false,
                TOKEN_PROGRAM_ID,
                ASSOCIATED_TOKEN_PROGRAM_ID
            );

            try {
                // Try to get the token account
                const account = await getAccount(this.connection, tokenAccount);
                return { tokenAccount, transaction: null };
            } catch (error) {
                // If account doesn't exist, return the creation transaction
                if (error.name === 'TokenAccountNotFoundError') {
                    console.log('Creating new associated token account...');
                    const transaction = new Transaction().add(
                        createAssociatedTokenAccountInstruction(
                            walletPublicKey, // payer
                            tokenAccount, // associatedToken
                            walletPublicKey, // owner
                            this.usdcMint, // mint
                            TOKEN_PROGRAM_ID,
                            ASSOCIATED_TOKEN_PROGRAM_ID
                        )
                    );

                    const { blockhash } = await this.connection.getRecentBlockhash();
                    transaction.recentBlockhash = blockhash;
                    transaction.feePayer = walletPublicKey;

                    return { tokenAccount, transaction };
                }
                throw error;
            }
        } catch (error) {
            console.error('Error in getOrCreateAssociatedTokenAccount:', error);
            throw error;
        }
    }

    async createTokenAccountIfNeeded(walletAddress) {
        const walletPublicKey = new PublicKey(walletAddress);
        const { tokenAccount, transaction } = await this.getOrCreateAssociatedTokenAccount(walletPublicKey);
        
        if (transaction) {
            // Return the unsigned transaction - it needs to be signed by the wallet
            return { transaction, tokenAccount };
        }
        
        return { tokenAccount };
    }

    async getUSDCBalance(walletAddress) {
        try {
            const walletPublicKey = new PublicKey(walletAddress);
            
            try {
                const tokenAccount = await getAssociatedTokenAddress(
                    this.usdcMint,
                    walletPublicKey,
                    false,
                    TOKEN_PROGRAM_ID,
                    ASSOCIATED_TOKEN_PROGRAM_ID
                );
    
                try {
                    const account = await getAccount(this.connection, tokenAccount);
                    return { 
                        balance: Number(account.amount) / Math.pow(10, 6),
                        needsTokenAccount: false 
                    };
                } catch (e) {
                    if (e.name === 'TokenAccountNotFoundError') {
                        console.log('Creating new associated token account...');
                        
                        // Create the transaction
                        const transaction = new Transaction().add(
                            createAssociatedTokenAccountInstruction(
                                walletPublicKey,          // payer
                                tokenAccount,             // associatedToken
                                walletPublicKey,          // owner
                                this.usdcMint,           // mint
                                TOKEN_PROGRAM_ID,
                                ASSOCIATED_TOKEN_PROGRAM_ID
                            )
                        );
    
                        const { blockhash } = await this.connection.getRecentBlockhash();
                        transaction.recentBlockhash = blockhash;
                        transaction.feePayer = walletPublicKey;
    
                        return {
                            balance: 0,
                            needsTokenAccount: true,
                            createAccountTransaction: transaction
                        };
                    }
                    throw e;
                }
            } catch (error) {
                console.error('Error getting token account:', error);
                throw error;
            }
        } catch (error) {
            console.error('Error getting USDC balance:', error);
            throw error;
        }
    }

    async createTransferTransaction(walletAddress, betAmount) {
        try {
            // Validate bet amount
            if (betAmount < config.MIN_BET_AMOUNT || betAmount > config.MAX_BET_AMOUNT) {
                throw new Error(`Bet amount must be between ${config.MIN_BET_AMOUNT} and ${config.MAX_BET_AMOUNT} USDC`);
            }

            const fromWallet = new PublicKey(walletAddress);
            
            // Get token accounts
            const { tokenAccount: fromTokenAccount, transaction: createFromAcctTx } = 
                await this.getOrCreateAssociatedTokenAccount(fromWallet);
            const { tokenAccount: toTokenAccount, transaction: createToAcctTx } = 
                await this.getOrCreateAssociatedTokenAccount(config.TREASURY_WALLET);

            // Create transfer instruction
            const transferIx = createTransferCheckedInstruction(
                fromTokenAccount, // source
                this.usdcMint,    // mint (USDC)
                toTokenAccount,   // destination
                fromWallet,       // owner
                betAmount * 1000000, // amount (converting to USDC decimals)
                6                 // decimals
            );

            // Create transaction and add all necessary instructions
            const transaction = new Transaction();
            if (createFromAcctTx) transaction.add(createFromAcctTx);
            if (createToAcctTx) transaction.add(createToAcctTx);
            transaction.add(transferIx);

            // Get recent blockhash
            const { blockhash } = await this.connection.getRecentBlockhash();
            transaction.recentBlockhash = blockhash;
            transaction.feePayer = fromWallet;

            return transaction;
        } catch (error) {
            console.error('Error creating transfer transaction:', error);
            throw error;
        }
    }

    async createPayoutTransaction(winnerWallet, amount) {
        try {
            const winnerPubkey = new PublicKey(winnerWallet);
            
            // Calculate payout amount after house fee
            const houseFee = (amount * config.HOUSE_FEE_PERCENT) / 100;
            const payoutAmount = amount - houseFee;

            // Get token accounts
            const { tokenAccount: fromTokenAccount } = 
                await this.getOrCreateAssociatedTokenAccount(config.TREASURY_WALLET);
            const { tokenAccount: toTokenAccount, transaction: createToAcctTx } = 
                await this.getOrCreateAssociatedTokenAccount(winnerPubkey);

            // Create transfer instruction
            const transferIx = createTransferCheckedInstruction(
                fromTokenAccount,
                this.usdcMint,
                toTokenAccount,
                config.TREASURY_WALLET,
                payoutAmount * 1000000, // Convert to USDC decimals
                6
            );

            // Create transaction and add all necessary instructions
            const transaction = new Transaction();
            if (createToAcctTx) transaction.add(createToAcctTx);
            transaction.add(transferIx);

            // Get recent blockhash
            const { blockhash } = await this.connection.getRecentBlockhash();
            transaction.recentBlockhash = blockhash;
            transaction.feePayer = config.TREASURY_WALLET;

            return transaction;
        } catch (error) {
            console.error('Error creating payout transaction:', error);
            throw error;
        }
    }
}

module.exports = USDCManager;