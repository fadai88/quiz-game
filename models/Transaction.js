const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
    signature: {
        type: String,
        required: true,
        unique: true
    },
    type: {
        type: String,
        enum: ['bet', 'payout'],
        required: true
    },
    amount: {
        type: Number,
        required: true
    },
    fromWallet: {
        type: String,
        required: true
    },
    toWallet: {
        type: String,
        required: true
    },
    gameId: {
        type: String,
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'confirmed', 'failed'],
        default: 'pending'
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Transaction', transactionSchema); 