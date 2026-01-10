/**
 * USDC Atomic Unit Utilities
 * 
 * CRITICAL: This module eliminates floating-point arithmetic in financial calculations
 * by working exclusively with atomic units (integers).
 * 
 * USDC uses 6 decimals: 1 USDC = 1,000,000 atomic units
 */

const USDC_DECIMALS = 6;
const USDC_MULTIPLIER = 1_000_000; // 10^6

/**
 * Valid bet amounts in USDC (display values)
 */
const VALID_BET_AMOUNTS_USDC = [3, 10, 15, 20, 30];

/**
 * Valid bet amounts in atomic units (what backend should accept)
 */
const VALID_BET_AMOUNTS_ATOMIC = VALID_BET_AMOUNTS_USDC.map(x => x * USDC_MULTIPLIER);
// Result: [3000000, 10000000, 15000000, 20000000, 30000000]

/**
 * Convert USDC display amount to atomic units (ONLY USE FOR INITIALIZATION)
 * DO NOT use this in transaction logic - accept atomic units directly
 * 
 * @param {number} usdcAmount - Amount in USDC (e.g., 3.5)
 * @returns {bigint} Amount in atomic units
 */
function toAtomicUnits(usdcAmount) {
    // Only use this for validation/initialization, not transactions!
    if (!Number.isFinite(usdcAmount)) {
        throw new Error('Invalid USDC amount: must be a finite number');
    }
    
    // Round to avoid floating point errors
    const atomic = Math.round(usdcAmount * USDC_MULTIPLIER);
    return BigInt(atomic);
}

/**
 * Convert atomic units to USDC display amount
 * 
 * @param {bigint|number|string} atomicAmount - Amount in atomic units
 * @returns {number} Amount in USDC (for display only)
 */
function fromAtomicUnits(atomicAmount) {
    const atomic = BigInt(atomicAmount);
    return Number(atomic) / USDC_MULTIPLIER;
}

/**
 * Validate that an atomic amount matches one of the allowed bet amounts
 * 
 * @param {number|string} atomicAmount - Amount to validate (in atomic units)
 * @returns {boolean} True if valid
 */
function isValidBetAmount(atomicAmount) {
    const amount = typeof atomicAmount === 'string' ? parseInt(atomicAmount, 10) : atomicAmount;
    return VALID_BET_AMOUNTS_ATOMIC.includes(amount);
}

/**
 * Calculate winnings in atomic units (NO FLOATING POINT!)
 * 
 * @param {number} betAtomicAmount - Bet amount in atomic units
 * @param {number} multiplier - Win multiplier (e.g., 1.8 for human vs human)
 * @returns {bigint} Winnings in atomic units
 */
function calculateWinnings(betAtomicAmount, multiplier) {
    // Convert multiplier to integer math: 1.8 -> 18/10
    // This avoids floating point entirely
    
    let numerator, denominator;
    
    if (multiplier === 1.8) {
        numerator = 18;
        denominator = 10;
    } else if (multiplier === 1.5) {
        numerator = 15;
        denominator = 10;
    } else {
        // Generic handling for other multipliers
        // Convert to fraction (e.g., 1.8 -> 18/10)
        const factor = 10;
        numerator = Math.round(multiplier * factor);
        denominator = factor;
    }
    
    // Integer arithmetic only: (bet * numerator) / denominator
    const bet = BigInt(betAtomicAmount);
    const result = (bet * BigInt(numerator)) / BigInt(denominator);
    
    return result;
}

/**
 * Format atomic units as USDC for logging/display
 * 
 * @param {bigint|number|string} atomicAmount
 * @returns {string} Formatted amount (e.g., "3.000000 USDC")
 */
function formatUSDC(atomicAmount) {
    const usdc = fromAtomicUnits(atomicAmount);
    return `${usdc.toFixed(6)} USDC`;
}

module.exports = {
    USDC_DECIMALS,
    USDC_MULTIPLIER,
    VALID_BET_AMOUNTS_USDC,
    VALID_BET_AMOUNTS_ATOMIC,
    toAtomicUnits,
    fromAtomicUnits,
    isValidBetAmount,
    calculateWinnings,
    formatUSDC
};