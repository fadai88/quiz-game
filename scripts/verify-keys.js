const { PublicKey } = require('@solana/web3.js');

function verifyKey(keyString) {
    try {
        new PublicKey(keyString);
        console.log(`✅ Valid key: ${keyString}`);
        return true;
    } catch (error) {
        console.error(`❌ Invalid key: ${keyString}`);
        console.error(error.message);
        return false;
    }
}

// Verify all our keys
const keys = {
    'USDC Mint': 'DbSXGoHrvL21RKSGJCR8VCxRPPmCtmi9Wm3hXtagyZps',
    'Treasury Wallet': 'GN6uUVKuijj15ULm3X954mQTKEzur9jxXdRRuLeMqmgH'
};

console.log('Verifying Solana public keys...');
Object.entries(keys).forEach(([name, key]) => {
    console.log(`\nChecking ${name}:`);
    verifyKey(key);
}); 