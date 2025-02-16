const { Keypair } = require('@solana/web3.js');

class TreasuryManager {
    static keypair = null;

    static initialize() {
        // In production, use secure key management
        // For development, you can use a JSON file or environment variables
        const secretKey = process.env.TREASURY_SECRET_KEY;
        if (!secretKey) {
            throw new Error('Treasury secret key not configured');
        }

        this.keypair = Keypair.fromSecretKey(
            Buffer.from(JSON.parse(secretKey))
        );
    }

    static async signTransaction(transaction) {
        if (!this.keypair) {
            throw new Error('Treasury not initialized');
        }

        transaction.sign(this.keypair);
        return transaction;
    }
}

module.exports = TreasuryManager; 