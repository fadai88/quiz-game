const { Keypair } = require('@solana/web3.js');

const keypair = Keypair.generate();
console.log('Public Key:', keypair.publicKey.toString());
console.log('Secret Key:', JSON.stringify(Array.from(keypair.secretKey))); 