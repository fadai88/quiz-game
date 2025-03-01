// Update models/User.js to also fix the email field issue:

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        // Default to a substring of wallet address
        default: function() {
            return this.walletAddress ? this.walletAddress.substring(0, 8) : `user_${Date.now().toString(36)}`;
        }
    },
    walletAddress: {
        type: String,
        required: true,
        unique: true // This should be the unique identifier
    },
    email: {
        type: String,
        required: false, // Make email optional
        unique: false,   // Remove the unique constraint
        sparse: true     // Only enforce uniqueness for non-null values
    },
    password: {
        type: String,
        required: false
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    verificationToken: String,
    registrationIP: String,
    lastLoginIP: String,
    registrationDate: Date,
    lastLoginDate: Date,
    userAgent: String,
    virtualBalance: {
        type: Number,
        default: 0
    },
    correctAnswers: {
        type: Number,
        default: 0
    },
    gamesPlayed: {
        type: Number,
        default: 0
    },
    totalPoints: {
        type: Number,
        default: 0
    }
}, {
    timestamps: true
});

// Password hashing middleware
UserSchema.pre('save', async function(next) {
    if (this.password && this.isModified('password')) {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
    }
    next();
});

UserSchema.methods.matchPassword = async function(enteredPassword) {
    if (!this.password) return false;
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', UserSchema);
module.exports = User;