const { Connection, Keypair, PublicKey } = require('@solana/web3.js');
const { createAssociatedTokenAccount, getAssociatedTokenAddress } = require('@solana/spl-token');
const config = require('../config/solana');
require('dotenv').config();

async function airdropDevnetUSDC(destinationWallet, amount) {
    try {
        const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
        
        // Parse destination wallet
        const destinationPubkey = new PublicKey(destinationWallet);
        
        // Get associated token account for devnet USDC
        const tokenAccount = await getAssociatedTokenAddress(
            config.USDC_MINT,
            destinationPubkey
        );

        // Create token account if it doesn't exist
        try {
            // You need some SOL in the wallet to create a token account
            const treasuryKeypair = Keypair.fromSecretKey(
                Uint8Array.from(JSON.parse(process.env.TREASURY_SECRET_KEY))
            );
            
            await createAssociatedTokenAccount(
                connection,
                treasuryKeypair,
                config.USDC_MINT,
                destinationPubkey
            );
            console.log('Created new token account for devnet USDC');
        } catch (e) {
            console.log('Token account already exists or creation failed');
            console.error(e);
        }

        // For devnet USDC, you'll need to use the faucet API to airdrop tokens
        // This is a mock URL - you'll need to replace it with the actual faucet endpoint
        console.log(`To get devnet USDC, use the SPL faucet at: https://spl-token-faucet.com`);
        console.log(`Send to token account address: ${tokenAccount.toString()}`);
        
        return tokenAccount.toString();
    } catch (error) {
        console.error('Error:', error);
        throw error;
    }
}

// Usage
const walletAddress = process.argv[2];
const amount = process.argv[3];

if (!walletAddress || !amount) {
    console.log('Usage: node airdrop-devnet-usdc.js <wallet-address> <amount>');
    process.exit(1);
}

airdropDevnetUSDC(walletAddress, parseFloat(amount));