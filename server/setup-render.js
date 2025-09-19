#!/usr/bin/env node

/**
 * QuickCredo Server - Render Deployment Setup Script
 * 
 * This script helps you set up the environment variables for Render deployment
 * Run this script to generate a .env file with all required variables
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const question = (query) => new Promise((resolve) => rl.question(query, resolve));

async function setupEnvironment() {
  console.log('🚀 QuickCredo Server - Render Deployment Setup');
  console.log('===============================================\n');

  console.log('This script will help you create a .env file for your server.\n');

  // Basic server configuration
  const nodeEnv = await question('NODE_ENV (production/development) [production]: ') || 'production';
  const port = await question('PORT [3000]: ') || '3000';
  const logLevel = await question('LOG_LEVEL (debug/info/warn/error) [info]: ') || 'info';

  // Firebase configuration
  console.log('\n📱 Firebase Configuration:');
  const gcpProjectId = await question('GCP_PROJECT_ID [daimapay]: ') || 'daimapay';
  const gcpKeyFile = await question('GCP_KEY_FILE [./service-account-key.json]: ') || './service-account-key.json';

  // Africa's Talking configuration
  console.log('\n🌍 Africa\'s Talking Configuration:');
  const atApiKey = await question('AT_API_KEY (get from https://account.africastalking.com): ');
  const atUsername = await question('AT_USERNAME: ');

  // M-Pesa configuration
  console.log('\n💰 M-Pesa Daraja API Configuration:');
  const consumerKey = await question('CONSUMER_KEY (get from https://developer.safaricom.co.ke): ');
  const consumerSecret = await question('CONSUMER_SECRET: ');
  const businessShortCode = await question('BUSINESS_SHORT_CODE: ');
  const passkey = await question('PASSKEY: ');

  // Callback URLs
  console.log('\n🔗 Callback URLs:');
  const renderUrl = await question('Your Render app URL (e.g., https://your-app.onrender.com): ');
  const callbackUrl = `${renderUrl}/stk-callback`;
  const analyticsUrl = `${renderUrl}/analytics`;

  // Email configuration
  console.log('\n📧 Email Configuration:');
  const emailUser = await question('EMAIL_USER (Gmail address): ');
  const emailPass = await question('EMAIL_PASS (Gmail App Password): ');

  // M-Pesa Airtime API
  console.log('\n📱 M-Pesa Airtime API Configuration:');
  const mpesaAirtimeKey = await question('MPESA_AIRTIME_KEY: ');
  const mpesaAirtimeSecret = await question('MPESA_AIRTIME_SECRET: ');
  const dealerSenderMsisdn = await question('DEALER_SENDER_MSISDN [254700000000]: ') || '254700000000';

  // M-Pesa Reversal API
  console.log('\n🔄 M-Pesa Reversal API Configuration:');
  const mpesaShortcode = await question('MPESA_SHORTCODE: ');
  const mpesaInitiatorName = await question('MPESA_INITIATOR_NAME: ');
  const mpesaSecurityPassword = await question('MPESA_SECURITY_PASSWORD: ');

  // M-Pesa Withdrawal API
  console.log('\n💸 M-Pesa Withdrawal API Configuration:');
  const withdrawalConsumerKey = await question('WITHDRAWAL_CONSUMER_KEY: ');
  const withdrawalConsumerSecret = await question('WITHDRAWAL_CONSUMER_SECRET: ');
  const withdrawalShortcode = await question('WITHDRAWAL_SHORTCODE: ');
  const withdrawalInitiatorName = await question('WITHDRAWAL_INITIATOR_NAME: ');
  const withdrawalInitiatorPassword = await question('WITHDRAWAL_INITIATOR_PASSWORD: ');

  // Security
  console.log('\n🔒 Security Configuration:');
  const jwtSecret = await question('JWT_SECRET (generate a strong random string): ');
  const sessionSecret = await question('SESSION_SECRET (generate a strong random string): ');

  // Generate .env content
  const envContent = `# ===========================================
# QUICKCREDO ECOSYSTEM - SERVER ENVIRONMENT
# Generated on ${new Date().toISOString()}
# ===========================================

# ===========================================
# BASIC SERVER CONFIGURATION
# ===========================================
NODE_ENV=${nodeEnv}
PORT=${port}
LOG_LEVEL=${logLevel}

# ===========================================
# FIREBASE/GCP CONFIGURATION
# ===========================================
GCP_PROJECT_ID=${gcpProjectId}
GCP_KEY_FILE=${gcpKeyFile}

# Firebase Web App Configuration (already configured)
FIREBASE_API_KEY=AIzaSyAGrGftWHmKryFtYd5JKPnYRO1tQJOA3b8
FIREBASE_AUTH_DOMAIN=daimapay.firebaseapp.com
FIREBASE_PROJECT_ID=daimapay
FIREBASE_STORAGE_BUCKET=daimapay.firebasestorage.app
FIREBASE_MESSAGING_SENDER_ID=860639848562
FIREBASE_APP_ID=1:860639848562:web:e65be4b6c91906c5d13aeb

# ===========================================
# AFRICA'S TALKING API CONFIGURATION
# ===========================================
AT_API_KEY=${atApiKey}
AT_USERNAME=${atUsername}

# ===========================================
# M-PESA DARAJA API CONFIGURATION
# ===========================================
CONSUMER_KEY=${consumerKey}
CONSUMER_SECRET=${consumerSecret}
BUSINESS_SHORT_CODE=${businessShortCode}
PASSKEY=${passkey}

# M-Pesa Daraja API URLs
DARAJA_CONSUMER_KEY=${consumerKey}
DARAJA_CONSUMER_SECRET=${consumerSecret}
DARAJA_OAUTH_URL=https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials

# ===========================================
# M-PESA CALLBACK URLS
# ===========================================
CALLBACK_URL=${callbackUrl}
ANALYTICS_SERVER_URL=${analyticsUrl}

# ===========================================
# EMAIL CONFIGURATION
# ===========================================
EMAIL_USER=${emailUser}
EMAIL_PASS=${emailPass}

# ===========================================
# M-PESA AIRTIME API CONFIGURATION
# ===========================================
MPESA_AIRTIME_KEY=${mpesaAirtimeKey}
MPESA_AIRTIME_SECRET=${mpesaAirtimeSecret}
MPESA_GRANT_URL=https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials
MPESA_AIRTIME_URL=https://api.safaricom.co.ke/mpesa/airtime/v1/send
DEALER_SENDER_MSISDN=${dealerSenderMsisdn}

# ===========================================
# M-PESA REVERSAL API CONFIGURATION
# ===========================================
MPESA_REVERSAL_URL=https://api.safaricom.co.ke/mpesa/reversal/v1/request
MPESA_SHORTCODE=${mpesaShortcode}
MPESA_INITIATOR_NAME=${mpesaInitiatorName}
MPESA_SECURITY_PASSWORD=${mpesaSecurityPassword}
MPESA_REVERSAL_QUEUE_TIMEOUT_URL=${renderUrl}/reversal-timeout
MPESA_REVERSAL_RESULT_URL=${renderUrl}/reversal-result

# ===========================================
# M-PESA WITHDRAWAL API CONFIGURATION
# ===========================================
WITHDRAWAL_CONSUMER_KEY=${withdrawalConsumerKey}
WITHDRAWAL_CONSUMER_SECRET=${withdrawalConsumerSecret}
WITHDRAWAL_MPESA_CERT_PATH=./certificates/withdrawal-cert.p12
WITHDRAWAL_INITIATOR_PASSWORD=${withdrawalInitiatorPassword}
WITHDRAWAL_SHORTCODE=${withdrawalShortcode}
WITHDRAWAL_INITIATOR_NAME=${withdrawalInitiatorName}
WITHDRAWAL_BASE_URL=${renderUrl}

# ===========================================
# SECURITY CONFIGURATION
# ===========================================
JWT_SECRET=${jwtSecret}
SESSION_SECRET=${sessionSecret}

# ===========================================
# RENDER SPECIFIC CONFIGURATION
# ===========================================
RENDER=true
RENDER_EXTERNAL_URL=${renderUrl}

# ===========================================
# OPTIONAL CONFIGURATION
# ===========================================
RATE_LIMIT_WINDOW_MS=300000
RATE_LIMIT_MAX_REQUESTS=100
LOG_MAX_SIZE=20m
LOG_MAX_FILES=14d
ERROR_LOG_MAX_FILES=30d
ALLOWED_ORIGINS=https://www.daimapay.com,https://daimapay.com,https://daimapay-51406.web.app,https://daimapay.web.app,https://daimapay-wallet.web.app,https://new-wallet.web.app
ENABLE_BULK_AIRTIME=true
ENABLE_DRIVER_COMMISSIONS=true
ENABLE_MPESA_INTEGRATION=true
ENABLE_AFRICASTALKING_INTEGRATION=true
ENABLE_EMAIL_NOTIFICATIONS=true
DRIVER_COMMISSION_RATE=2.5
RETAILER_COMMISSION_RATE=1.5
MIN_AIRTIME_AMOUNT=5
MAX_AIRTIME_AMOUNT=10000
SAFARICOM_FLOAT_THRESHOLD=1000
AFRICASTALKING_FLOAT_THRESHOLD=1000
HEALTH_CHECK_ENABLED=true
METRICS_ENABLED=true
DEBUG_MODE=false
VERBOSE_LOGGING=false
MAINTENANCE_MODE=false
MAINTENANCE_MESSAGE=System is under maintenance. Please try again later.
MAX_CONCURRENT_REQUESTS=100
REQUEST_TIMEOUT=30000
KEEP_ALIVE_TIMEOUT=5000
MAX_FILE_SIZE=10485760
ALLOWED_FILE_TYPES=csv,xlsx,txt
API_VERSION=v1
API_PREFIX=/api
WEBHOOK_SECRET=your-webhook-secret-here
WEBHOOK_TIMEOUT=30000
REDIS_URL=redis://localhost:6379
CACHE_TTL=3600
SSL_ENABLED=true
SSL_CERT_PATH=./certificates/cert.pem
SSL_KEY_PATH=./certificates/key.pem
BACKUP_ENABLED=true
BACKUP_SCHEDULE=0 2 * * *
BACKUP_RETENTION_DAYS=30
FCM_SERVER_KEY=your_fcm_server_key_here
FCM_SENDER_ID=your_fcm_sender_id_here
FIRESTORE_EMULATOR_HOST=localhost:8080
FIRESTORE_EMULATOR_AUTH_EMULATOR_HOST=localhost:9099
`;

  // Write .env file
  const envPath = path.join(__dirname, '.env');
  fs.writeFileSync(envPath, envContent);

  console.log('\n✅ Environment file created successfully!');
  console.log(`📁 Location: ${envPath}`);
  console.log('\n📋 Next steps:');
  console.log('1. Review the .env file and update any missing values');
  console.log('2. Create a service-account-key.json file from Firebase Console');
  console.log('3. Deploy to Render using the deployment guide');
  console.log('4. Update callback URLs after deployment');
  console.log('\n🚀 Happy deploying!');

  rl.close();
}

// Run the setup
setupEnvironment().catch(console.error);
