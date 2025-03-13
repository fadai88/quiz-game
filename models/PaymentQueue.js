// models/PaymentQueue.js
const mongoose = require('mongoose');

const PaymentQueueSchema = new mongoose.Schema({
  recipientWallet: {
    type: String,
    required: true,
    index: true
  },
  amount: {
    type: Number,
    required: true
  },
  gameId: {
    type: String,
    required: true
  },
  betAmount: {
    type: Number,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'failed'],
    default: 'pending',
    index: true
  },
  attempts: {
    type: Number,
    default: 0
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

// Static method to add a payment to the queue
PaymentQueueSchema.statics.queuePayment = async function(recipientWallet, amount, gameId, betAmount, metadata = {}) {
  return this.create({
    recipientWallet,
    amount,
    gameId,
    betAmount,
    metadata
  });
};

// Static method to get pending payments ready for processing
PaymentQueueSchema.statics.getPendingPayments = async function(limit = 10) {
  // Get payments that are pending or failed but haven't exceeded max attempts
  // and weren't attempted in the last 5 minutes
  const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
  
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
};

// Mark a payment as processing
PaymentQueueSchema.methods.markProcessing = async function() {
  this.status = 'processing';
  this.attempts += 1;
  this.lastAttemptAt = new Date();
  return this.save();
};

// Mark a payment as completed
PaymentQueueSchema.methods.markCompleted = async function(transactionSignature) {
  this.status = 'completed';
  this.transactionSignature = transactionSignature;
  this.completedAt = new Date();
  return this.save();
};

// Mark a payment as failed
PaymentQueueSchema.methods.markFailed = async function(errorMessage) {
  this.status = 'failed';
  this.errorMessage = errorMessage;
  return this.save();
};

const PaymentQueue = mongoose.model('PaymentQueue', PaymentQueueSchema);

module.exports = PaymentQueue;