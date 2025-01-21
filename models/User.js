const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    walletAddress: { 
        type: String, 
        required: true, 
        unique: true,
        sparse: true
    },
    virtualBalance: { 
        type: Number, 
        default: 10 
    },
    gamesPlayed: { 
        type: Number, 
        default: 0 
    },
    correctAnswers: { 
        type: Number, 
        default: 0 
    },
    totalPoints: { 
        type: Number, 
        default: 0 
    }
});

// Remove all other indexes except walletAddress
userSchema.index({ walletAddress: 1 }, { unique: true });

const User = mongoose.model('User', userSchema);

module.exports = User;