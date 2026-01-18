// AWS Secrets Manager integration module
const {
  SecretsManagerClient,
  GetSecretValueCommand,
} = require("@aws-sdk/client-secrets-manager");

const secret_name = "wallet_secret_key";

// Create client with your region
const client = new SecretsManagerClient({
  region: "eu-north-1",
  // AWS credentials will be automatically loaded from:
  // 1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
  // 2. AWS credentials file (~/.aws/credentials)
  // 3. IAM role (if running on EC2/ECS/Lambda)
});

/**
 * Retrieves the treasury wallet secret key from AWS Secrets Manager
 * @returns {Promise<string>} The secret key as a JSON string
 */
async function getTreasurySecretKey() {
  try {
    const response = await client.send(
      new GetSecretValueCommand({
        SecretId: secret_name,
        VersionStage: "AWSCURRENT",
      })
    );
    
    const secret = response.SecretString;
    console.log("✅ Successfully retrieved treasury key from AWS Secrets Manager");
    return secret;
  } catch (error) {
    console.error("❌ Error retrieving secret from AWS Secrets Manager:", error);
    
    // Provide helpful error messages
    if (error.name === 'ResourceNotFoundException') {
      throw new Error(`Secret '${secret_name}' not found in AWS Secrets Manager`);
    } else if (error.name === 'InvalidRequestException') {
      throw new Error('Invalid request to AWS Secrets Manager - check your secret name and region');
    } else if (error.name === 'InvalidParameterException') {
      throw new Error('Invalid parameter in AWS Secrets Manager request');
    } else if (error.name === 'DecryptionFailure') {
      throw new Error('Failed to decrypt secret - check KMS permissions');
    } else if (error.name === 'InternalServiceError') {
      throw new Error('AWS Secrets Manager internal error - try again later');
    }
    
    throw error;
  }
}

/**
 * Cache the secret to avoid repeated API calls
 * Refresh every 24 hours for security
 */
let cachedSecret = null;
let cacheTimestamp = null;
const CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours

async function getCachedTreasurySecretKey() {
  const now = Date.now();
  
  if (cachedSecret && cacheTimestamp && (now - cacheTimestamp) < CACHE_DURATION) {
    console.log("📦 Using cached treasury key");
    return cachedSecret;
  }
  
  console.log("🔄 Fetching fresh treasury key from AWS...");
  cachedSecret = await getTreasurySecretKey();
  cacheTimestamp = now;
  
  return cachedSecret;
}

module.exports = {
  getTreasurySecretKey,
  getCachedTreasurySecretKey
};
