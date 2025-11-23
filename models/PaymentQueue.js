// models/PaymentQueue.js
const mongoose = require('mongoose');

const PaymentQueueSchema = new mongoose.Schema({
  recipientWallet: {
    type: String,
    required: true,
    match: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/, // Basic base58 for Solana addresses
    index: true
  },
  amount: {
    type: Number,
    required: true,
    min: [0.01, 'Amount must be greater than 0'] // Min 0.01 USDC
  },
  gameId: {
    type: String,
    required: true,
    unique: true // NEW: Prevent duplicate queues per game
  },
  betAmount: {
    type: Number,
    required: true,
    min: [0, 'Bet amount cannot be negative']
  },
  status: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'failed'],
    default: 'pending',
    index: true
  },
  attempts: {
    type: Number,
    default: 0,
    min: 0
  },
  lastAttemptAt: {
    type: Date
  },
  transactionSignature: {
    type: String,
    sparse: true
  },
  errorMessage: {
    type: String
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  completedAt: {
    type: Date
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  }
});

// Index for finding payments that need processing
PaymentQueueSchema.index({ status: 1, attempts: 1, lastAttemptAt: 1 });

// NEW: Pre-save hook to ensure status is set and validate
PaymentQueueSchema.pre('save', function(next) {
  if (this.isNew && !this.status) {
    this.status = 'pending';
  }
  next();
});

// Static method to add a payment to the queue
PaymentQueueSchema.statics.queuePayment = async function(recipientWallet, amount, gameId, betAmount, metadata = {}) {
  // NEW: Check for existing by gameId to prevent duplicates
  const existing = await this.findOne({ gameId });
  if (existing) {
    if (existing.status === 'completed') {
      throw new Error(`Payment for game ${gameId} already completed`);
    }
    if (existing.status === 'pending' || existing.status === 'processing') {
      return existing; // Return existing if already queued
    }
  }
  return this.create({
    recipientWallet,
    amount,
    gameId,
    betAmount,
    metadata
  });
};

// ✅ FIXED: Static method to get pending payments ready for processing
PaymentQueueSchema.statics.getPendingPayments = async function(limit = 10) {
  // Get payments that are pending or failed but haven't exceeded max attempts
  // and weren't attempted in the last 5 minutes
  const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
  
  // ✅ CRITICAL FIX: Removed .lean() to preserve Mongoose instance methods
  // This ensures markProcessing(), markCompleted(), and markFailed() methods are available
  return this.find({
    $or: [
      { status: 'pending' },
      { 
        status: 'failed', 
        attempts: { $lt: 5 },
        lastAttemptAt: { $lt: fiveMinutesAgo }
      }
    ]
  })
  .sort({ createdAt: 1 })
  .limit(limit);
  // ❌ REMOVED .lean() - we need instance methods!
  // If you need performance, consider using .select() to limit fields instead
};

// NEW: Static method to cleanup old pending payments (call in cron)
PaymentQueueSchema.statics.cleanupOldPendings = async function(hours = 24) {
  const cutoff = new Date(Date.now() - hours * 60 * 60 * 1000);
  const result = await this.deleteMany({
    status: 'pending',
    createdAt: { $lt: cutoff }
  });
  console.log(`Cleaned up ${result.deletedCount} old pending payments`);
  return result;
};

// Mark a payment as processing
PaymentQueueSchema.methods.markProcessing = async function() {
  try {
    this.status = 'processing';
    this.attempts += 1;
    this.lastAttemptAt = new Date();
    return await this.save();
  } catch (error) {
    // NEW: Rollback on DB error
    console.error('Failed to mark payment as processing:', error);
    throw new Error(`DB update failed: ${error.message}`);
  }
};

// Mark a payment as completed
PaymentQueueSchema.methods.markCompleted = async function(transactionSignature) {
  try {
    this.status = 'completed';
    this.transactionSignature = transactionSignature;
    this.completedAt = new Date();
    return await this.save();
  } catch (error) {
    console.error('Failed to mark payment as completed:', error);
    throw new Error(`DB update failed: ${error.message}`);
  }
};

// Mark a payment as failed
PaymentQueueSchema.methods.markFailed = async function(errorMessage) {
  try {
    this.status = 'failed';
    this.errorMessage = errorMessage;
    return await this.save();
  } catch (error) {
    console.error('Failed to mark payment as failed:', error);
    throw new Error(`DB update failed: ${error.message}`);
  }
};

const PaymentQueue = mongoose.model('PaymentQueue', PaymentQueueSchema);

module.exports = PaymentQueue;