const { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey } = require('@solana/web3.js');
require('dotenv').config();

async function initTreasury() {
    try {
        // Connect to devnet
        const connection = new Connection('https://api.devnet.solana.com', 'confirmed');

        // Create keypair from secret key
        const secretKeyString = process.env.TREASURY_SECRET_KEY;
        const secretKey = Uint8Array.from(JSON.parse(secretKeyString));
        const keypair = Keypair.fromSecretKey(secretKey);

        console.log('Treasury public key:', keypair.publicKey.toString());

        // Request airdrop
        console.log('Requesting airdrop...');
        const signature = await connection.requestAirdrop(
            keypair.publicKey,
            2 * LAMPORTS_PER_SOL // 2 SOL
        );

        // Wait for confirmation
        await connection.confirmTransaction(signature);

        // Check balance
        const balance = await connection.getBalance(keypair.publicKey);
        console.log(`Treasury balance: ${balance / LAMPORTS_PER_SOL} SOL`);

    } catch (error) {
        console.error('Error:', error);
    }
}

initTreasury(); 