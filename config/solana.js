const { Connection, PublicKey } = require('@solana/web3.js');

const config = {
    // Official Solana devnet USDC mint
    USDC_MINT: new PublicKey('Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr'),
    
    // Connection to Solana devnet
    connection: new Connection('https://api.devnet.solana.com', 'confirmed'),
    
    // Your treasury wallet address
    TREASURY_WALLET: new PublicKey('GN6uUVKuijj15ULm3X954mQTKEzur9jxXdRRuLeMqmgH'),
    
    // House fee percentage (e.g., 2.5%)
    HOUSE_FEE_PERCENT: 2.5,
    
    // Minimum bet amount in USDC (e.g., 1 USDC)
    MIN_BET_AMOUNT: 1,
    
    // Maximum bet amount in USDC (e.g., 100 USDC)
    MAX_BET_AMOUNT: 100
};

module.exports = config;