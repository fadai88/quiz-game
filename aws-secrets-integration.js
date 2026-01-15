// Simplified version for production deployment
async function getCachedTreasurySecretKey() {
    const secretKey = process.env.TREASURY_SECRET_KEY;
    
    if (!secretKey) {
        console.error('❌ TREASURY_SECRET_KEY not set');
        throw new Error('TREASURY_SECRET_KEY environment variable required');
    }
    
    console.log('✅ Treasury secret key loaded from environment');
    return secretKey;
}

module.exports = {
    getCachedTreasurySecretKey
};
