require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs')
const { Firestore, FieldValue } = require('@google-cloud/firestore'); // Import FieldValue
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const nodemailer = require('nodemailer');
require('winston-daily-rotate-file');

// --- Global Error Handlers (VERY IMPORTANT FOR PRODUCTION) ---
process.on('uncaughtException', (err) => {
    console.error('UNCAUGHT EXCEPTION! Shutting down...', err.name, err.message, err.stack);
    logger.error('UNCAUGHT EXCEPTION! Shutting down...', { error: err.message, stack: err.stack, name: err.name });
    // Give a short grace period for logs to flush before exiting
    setTimeout(() => process.exit(1), 1000);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('UNHANDLED REJECTION! Shutting down...', reason);
    logger.error('UNHANDLED REJECTION! Shutting down...', { reason: reason, promise: promise });
    // Give a short grace period for logs to flush before exiting
    setTimeout(() => process.exit(1), 1000);
});

// --- Winston Logger Setup ---
const transports = [
    new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
        ),
        level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
    }),
];

if (process.env.NODE_ENV === 'production') {
    transports.push(
        new winston.transports.DailyRotateFile({
            filename: 'logs/application-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            zippedArchive: true,
            maxSize: '20m',
            maxFiles: '14d',
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            ),
        }),
        new winston.transports.DailyRotateFile({
            filename: 'logs/error-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            zippedArchive: true,
            maxSize: '20m',
            maxFiles: '30d',
            level: 'error',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            ),
        })
    );
}

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        winston.format.splat(),
        winston.format.json()
    ),
    defaultMeta: { service: 'daimapay-c2b-server' },
    transports: transports,
});

// Function to hash sensitive data like MSISDN
function hashString(str) {
    if (!str) return null;
    return crypto.createHash('sha256').update(str).digest('hex');
}

// --- Express App Setup ---
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Trust proxy for rate limiting to work correctly with load balancers
app.set('trust proxy', 1);

// --- Firestore Initialization ---
let firestore;

console.log('🔍 Firebase Debug Info:');
console.log('RENDER env:', process.env.RENDER);
console.log('GCP_PROJECT_ID:', process.env.GCP_PROJECT_ID);
console.log('GCP_KEY_FILE exists:', !!process.env.GCP_KEY_FILE);

// Use service account key file for both local and Render deployment
console.log('🔧 Using service account key file...');
console.log('🔍 DEBUG: FIRESTORE_EMULATOR_HOST:', process.env.FIRESTORE_EMULATOR_HOST);
console.log('🔍 DEBUG: NODE_ENV:', process.env.NODE_ENV);
console.log('🔍 DEBUG: RENDER:', process.env.RENDER);
console.log('🔍 DEBUG: All environment variables with FIRESTORE:', Object.keys(process.env).filter(key => key.includes('FIRESTORE')));
console.log('🔍 DEBUG: All environment variables with EMULATOR:', Object.keys(process.env).filter(key => key.includes('EMULATOR')));

try {
    // Read the service account key file
    const serviceAccountKey = require('./serviceAcountKey.json');
    console.log('✅ Service account key loaded successfully');
        console.log('Project ID from key:', serviceAccountKey.project_id);
        
    // DEBUG: Show Firestore configuration
    const firestoreConfig = {
            projectId: process.env.GCP_PROJECT_ID,
            credentials: serviceAccountKey,
    };
    
    // FORCE: Completely override any emulator settings
    console.log('🔍 DEBUG: FIRESTORE_EMULATOR_HOST before override:', process.env.FIRESTORE_EMULATOR_HOST);
    
    // Completely remove emulator environment variables
    delete process.env.FIRESTORE_EMULATOR_HOST;
    delete process.env.FIRESTORE_EMULATOR_AUTH_EMULATOR_HOST;
    
    console.log('🔍 DEBUG: FIRESTORE_EMULATOR_HOST after override:', process.env.FIRESTORE_EMULATOR_HOST);
    
    // Force production configuration
    firestoreConfig.host = undefined;
    firestoreConfig.ssl = true;
    // Don't set port - let it use default
    
    console.log('⚠️ FORCED: Production Firestore mode - all emulator settings removed');
    
    console.log('🔍 DEBUG: Firestore config:', JSON.stringify(firestoreConfig, null, 2));
    
    firestore = new Firestore(firestoreConfig);
        console.log('✅ Firestore initialized with credentials');
    console.log('🔍 DEBUG: Firestore instance created - no localhost/emulator config');
    } catch (error) {
    console.error('❌ Failed to load service account key:', error.message);
        throw error;
}

const transactionsCollection = firestore.collection('transactions');
const salesCollection = firestore.collection('sales');
const errorsCollection = firestore.collection('errors');
const safaricomFloatDocRef = firestore.collection('Saf_float').doc('current');
const africasTalkingFloatDocRef = firestore.collection('AT_Float').doc('current');
const reconciledTransactionsCollection = firestore.collection('reconciled_transactions');
const failedReconciliationsCollection = firestore.collection('failed_reconciliations');
const reversalTimeoutsCollection = firestore.collection('reversal_timeouts'); // NEW: Initialize this collection
const bonusHistoryCollection = firestore.collection('bonus_history'); // NEW: Initialize this collection
const stkTransactionsCollection = firestore.collection('stk_Transactions');
const safaricomDealerConfigRef = firestore.collection('mpesa_settings').doc('main_config');
const bulkAirtimeJobsCollection = firestore.collection('bulk_airtime_jobs');
const bulkTransactionsCollection = firestore.collection('bulk_transactions');
const bulkSalesCollection = firestore.collection('bulk_sales');
const singleSalesCollection = firestore.collection('single_sales');

// --- Africa's Talking Initialization ---
const AfricasTalking = require('africastalking');
const africastalking = AfricasTalking({
    apiKey: process.env.AT_API_KEY,
    username: process.env.AT_USERNAME
});

// M-Pesa API Credentials from .env
const CONSUMER_KEY = process.env.CONSUMER_KEY;
const CONSUMER_SECRET = process.env.CONSUMER_SECRET;
const SHORTCODE = process.env.BUSINESS_SHORT_CODE; // Your Paybill/Till number
const PASSKEY = process.env.PASSKEY;
const STK_CALLBACK_URL = process.env.CALLBACK_URL; // Your public URL for /stk-callback
const ANALYTICS_SERVER_URL = process.env.ANALYTICS_SERVER_URL; // Your analytics server URL
const BASE_URL = process.env.CALLBACK_URL?.replace('/stk-callback', '') || 'https://daimaofflineserver.onrender.com'; // Fallback for BASE_URL

// --- Middleware ---
app.use(helmet());
app.use(bodyParser.json({ limit: '1mb' }));

// Special middleware for STK callback to handle different body formats
app.use('/stk-callback', (req, res, next) => {
    // If body is already parsed as object, continue
    if (typeof req.body === 'object' && req.body !== null) {
        return next();
    }
    
    // If body is a string, try to parse it
    if (typeof req.body === 'string') {
        try {
            req.body = JSON.parse(req.body);
            logger.info('📞 Successfully parsed stringified STK callback body');
        } catch (error) {
            logger.error('❌ Failed to parse STK callback string body:', error.message);
            logger.error('❌ Raw body string:', req.body);
        }
    }
    
    next();
});
// Allow specific origins (recommended for production)
const allowedOrigins = [
    'http://localhost:3000',
    'https://daimapay.com',
    'https://daimapay-51406.web.app',
    'https://daimapay.web.app',
    'https://daimapay-wallet.web.app',
    'https://new-wallet.web.app'
];
app.use(cors({
    origin: function (origin, callback) {
        // allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE', 
    credentials: true, 
    optionsSuccessStatus: 204 
}));

const c2bLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 60,
    message: 'Too many requests from this IP for C2B callbacks, please try again later.',
    handler: (req, res, next, options) => {
        logger.warn(`Rate limit exceeded for IP: ${req.ip} on ${req.path}`);
        res.status(options.statusCode).json({
            "ResultCode": 1,
            "ResultDesc": options.message
        });
    }
});
app.use('/c2b-confirmation', c2bLimiter);
app.use('/c2b-validation', c2bLimiter);


let cachedDarajaAccessToken = null;
let tokenExpiryTime = 0; // Timestamp when the current token expires

async function getDarajaAccessToken() {
    // Check if token is still valid
    if (cachedDarajaAccessToken && Date.now() < tokenExpiryTime) {
        logger.debug('🔑 Using cached Daraja access token.');
        return cachedDarajaAccessToken;
    }

    logger.info('🔑 Generating new Daraja access token...');
    try {
        const consumerKey = process.env.DARAJA_CONSUMER_KEY;
        const consumerSecret = process.env.DARAJA_CONSUMER_SECRET;
        const oauthUrl = process.env.DARAJA_OAUTH_URL;

        if (!consumerKey || !consumerSecret || !oauthUrl) {
            throw new Error("Missing Daraja API credentials or OAuth URL in environment variables.");
        }

        // Base64 encode consumer key and secret
        const authString = Buffer.from(`${consumerKey}:${consumerSecret}`).toString('base64');

        const response = await axios.get(oauthUrl, {
            headers: {
                Authorization: `Basic ${authString}`,
            },
        });

        const { access_token, expires_in } = response.data;

        if (access_token && expires_in) {
            cachedDarajaAccessToken = access_token;
            // Set expiry time a bit before the actual expiry to avoid using an expired token
            // Daraja tokens are usually valid for 3600 seconds (1 hour)
            tokenExpiryTime = Date.now() + (expires_in * 1000) - (60 * 1000); // 1 minute buffer
            logger.info(`✅ New Daraja access token generated. Expires in ${expires_in} seconds.`);
            return cachedDarajaAccessToken;
        } else {
            logger.error('❌ Daraja OAuth response did not contain access_token or expires_in:', response.data);
            throw new Error('Invalid Daraja OAuth response.');
        }
    } catch (error) {
        const errorDetails = error.response ? JSON.stringify(error.response.data) : error.message;
        logger.error(`❌ Failed to get Daraja access token: ${errorDetails}`);
        throw new Error(`Failed to obtain Daraja access token: ${errorDetails}`);
    }
}

//--BEGINING OF EMAIL FUNCTION --
// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER, 
    pass: process.env.EMAIL_PASS, 
  }
});

app.post('/api/send-login-email', async (req, res) => {
  const { userEmail, userRole, timestamp } = req.body;

  if (!userEmail || !userRole || !timestamp) {
    return res.status(400).json({ error: 'All fields required' });
  }
    const mailOptions = {
    from: `"Login Alert" <no-reply@daimapay.com>`,
    to: 'team.daimapay@gmail.com',
    subject: `New Login Detected`,
    text: `User ${userEmail} logged in as ${userRole} at ${timestamp}`,
    html: `<p><strong>Email:</strong> ${userEmail}</p><p><strong>Role:</strong> ${userRole}</p><p><strong>Time:</strong> ${timestamp}</p>`
  };

  try {
    await transporter.sendMail(mailOptions);
    res.status(200).json({ success: true, message: 'Email sent successfully' });
  } catch (err) {
    console.error('Email Error:', err);
    res.status(500).json({ error: 'Failed to send email' });
  }
});

app.post('/api/notify-float-balance', async (req, res) => {
  const { to, floatBalance, threshold, telco } = req.body;

  // Input validation
  if (!to || !floatBalance || !telco) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  // Configure nodemailer transporter
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER, // Your Gmail address
      pass: process.env.EMAIL_PASS, // App password or real password (use app password for Gmail)
    },
  });

  // Email content
  const mailOptions = {
    from: `"DaimaPay Alerts" <${process.env.EMAIL_USER}>`,
    to,
    subject: `Float Balance Alert: ${telco}`,
    html: `
      <h2>Float Balance Notification</h2>
      <p><strong>Telco:</strong> ${telco}</p>
      <p><strong>Current Float Balance:</strong> Ksh ${Number(floatBalance).toLocaleString()}</p>
      ${threshold ? `<p><strong>Threshold:</strong> Ksh ${Number(threshold).toLocaleString()}</p>` : ''}
      <p>Please take necessary action if the balance is below the threshold.</p>
      <hr>
      <small>This is an automated message from DaimaPay.</small>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: 'Email sent successfully.' });
  } catch (err) {
    console.error('Email send error:', err);
    res.status(500).json({ error: 'Failed to send email notification.' });
  }
});
//-- END OF EMAIL --

//-- BEGINING OF ANALYTICS
const formatDate = (date) => date.toISOString().split('T')[0];
const getFloatCollectionId = (telco) => {
  if (telco === 'Safaricom') return 'Saf_float';
  if (['Airtel', 'Telkom', 'Africastalking'].includes(telco)) return 'AT_Float';
  return null;
};

const getIndividualFloatBalance = async (floatType) => {
  try {
    const doc = await firestore.collection(floatType).doc('current').get();
    return doc.exists ? doc.data().balance || 0 : 0;
  } catch (err) {
    console.error(`Error fetching ${floatType} float:`, err);
    return 0;
  }
};

// --- Time helpers ---
const getStartOfDayEAT = (date) => {
  const d = new Date(date);
  d.setUTCHours(0, 0, 0, 0);
  d.setUTCHours(d.getUTCHours() - 3);
  return Firestore.Timestamp.fromDate(d);
};
const getEndOfDayEAT = (date) => {
  const d = new Date(date);
  d.setUTCHours(23, 59, 59, 999);
  d.setUTCHours(d.getUTCHours() - 3);
  return Firestore.Timestamp.fromDate(d);
};
const getStartOfMonthEAT = (date) => {
  const d = new Date(date.getFullYear(), date.getMonth(), 1);
  d.setUTCHours(0, 0, 0, 0);
  d.setUTCHours(d.getUTCHours() - 3);
  return Firestore.Timestamp.fromDate(d);
};

// --- Classic sum fallback ---
async function sumSales(collectionRef) {
  const snap = await collectionRef.get();
  return snap.docs.reduce((sum, doc) => sum + (doc.data().amount || 0), 0);
}

// --- Main Sales Data Function ---
const getSalesOverviewData = async () => {
  const telcos = ['Safaricom', 'Airtel', 'Telkom'];
  const sales = {};
  const topPurchasers = {};
    
  const today = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(today.getDate() - 1);

  const startToday = getStartOfDayEAT(today);
  const endToday = getEndOfDayEAT(today);
  const startYesterday = getStartOfDayEAT(yesterday);
  const endYesterday = getEndOfDayEAT(yesterday);
  const startMonth = getStartOfMonthEAT(today);

  for (const telco of telcos) {
    // Today
    const todayRef = firestore.collection('sales')
      .where('status', 'in', ['COMPLETED', 'SUCCESS'])
      .where('carrier', '==', telco)
      .where('createdAt', '>=', startToday)
      .where('createdAt', '<=', endToday);
    const todayTotal = await sumSales(todayRef);
      
    // Yesterday
    const yestRef = firestore.collection('sales')
      .where('status', 'in', ['COMPLETED', 'SUCCESS'])
      .where('carrier', '==', telco)
      .where('createdAt', '>=', startYesterday)
      .where('createdAt', '<=', endYesterday);
    const yestTotal = await sumSales(yestRef);

    // This month
    const monthRef = firestore.collection('sales')
      .where('status', 'in', ['COMPLETED', 'SUCCESS'])
      .where('carrier', '==', telco)
      .where('createdAt', '>=', startMonth);
    const monthTotal = await sumSales(monthRef);

    const trend = yestTotal === 0
      ? (todayTotal > 0 ? 'up' : 'neutral')
      : (todayTotal >= yestTotal ? 'up' : 'down');

    sales[telco] = { today: todayTotal, month: monthTotal, trend };
      // Top purchasers
    const allRef = firestore.collection('sales')
      .where('carrier', '==', telco)
      .where('status', 'in', ['COMPLETED', 'SUCCESS']);
    const allSnap = await allRef.get();
    const buyers = {};
    allSnap.forEach(doc => {
      const { topupNumber, amount } = doc.data();
      if (topupNumber) buyers[topupNumber] = (buyers[topupNumber] || 0) + (amount || 0);
    });
    const top = Object.entries(buyers)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([name, Amount]) => ({ name, Amount }));
    topPurchasers[telco] = top;
  }

  return { sales, topPurchasers };
};

// --- Endpoints ---
app.get('/api/analytics/sales-overview', async (req, res) => {
  try {
    const { sales } = await getSalesOverviewData();
    res.json(sales);
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ error: 'Failed to load sales overview.' });
  }
});
app.post('/api/process-airtime-purchase', async (req, res) => {
  const { amount, status, telco, transactionId } = req.body;

  if (!amount || !status || !telco || !transactionId) {
    return res.status(400).json({ error: 'Missing fields.' });
  }

  if (!['COMPLETED', 'SUCCESS'].includes(status.toUpperCase())) {
    return res.json({ ok: true, note: 'No float deduction needed.' });
  }

  const floatCollectionId = getFloatCollectionId(telco);
  if (!floatCollectionId) {
    return res.status(400).json({ error: 'Unknown telco.' });
  }

  const floatRef = firestore.collection(floatCollectionId).doc('current');
    try {
    await firestore.runTransaction(async (tx) => {
      const doc = await tx.get(floatRef);
      if (!doc.exists) throw new Error('Float doc missing.');
      const current = doc.data().balance || 0;
      const newBal = current - amount;
      if (newBal < 0) throw new Error('Insufficient float.');
      tx.update(floatRef, { balance: newBal });
    });
    res.json({ ok: true, note: 'Float deducted.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/analytics/dashboard', async (req, res) => {
  try {
    const { sales, topPurchasers } = await getSalesOverviewData();
    const saf = await getIndividualFloatBalance('Saf_float');
    const at = await getIndividualFloatBalance('AT_Float');

    const floatLogsSnap = await firestore.collection('floatLogs')
      .orderBy('timestamp', 'desc')
      .limit(50)
      .get();

    const floatLogs = floatLogsSnap.docs.map(doc => ({
      date: formatDate(doc.data().timestamp?.toDate?.() || new Date()),
      type: doc.data().type,
      Amount: doc.data().Amount,
      description: doc.data().description,
    }));

    res.json({
      sales,
      safFloatBalance: saf,
      atFloatBalance: at,
      floatBalance: saf + at,
      floatLogs,
      topPurchasers
    });
} catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load dashboard.' });
  }
});
   
//--END OF ANALYTICS --

// Function to get Daraja access token
async function getAccessToken() {
    const auth = Buffer.from(`${CONSUMER_KEY}:${CONSUMER_SECRET}`).toString('base64');
    try {
        const response = await axios.get('https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials', {
            headers: {
                'Authorization': `Basic ${auth}`
            }
        });
        return response.data.access_token;
    } catch (error) {
        logger.error('Error getting access token:', error.message);
        throw new Error('Failed to get M-Pesa access token.');
    }
}

let cachedAirtimeToken = null;
let tokenExpiryTimestamp = 0;

// NEW: Cache variables for Dealer Service PIN
let cachedDealerServicePin = null;
let dealerPinExpiryTimestamp = 0;
const DEALER_PIN_CACHE_TTL = 10 * 60 * 1000; // Cache for 10 minutes (600,000 milliseconds)

//service pin
async function generateServicePin(rawPin) {
    logger.debug('[generateServicePin] rawPin length:', rawPin ? rawPin.length : 'null');
    try {
        const encodedPin = Buffer.from(rawPin).toString('base64'); // Correct for Node.js
        logger.debug('[generateServicePin] encodedPin length:', encodedPin.length);
        return encodedPin;
    } catch (error) {
        logger.error('[generateServicePin] error:', error);
        throw new Error(`Service PIN generation failed: ${error.message}`);
    }
}

// Function to generate password for STK Push
function generatePassword(shortcode, passkey, timestamp) {
    const str = shortcode + passkey + timestamp;
    return Buffer.from(str).toString('base64');
}

// NEW: Function to get dealer service PIN from Firestore with caching
async function getDealerServicePin() {
    const now = Date.now();
    if (cachedDealerServicePin && now < dealerPinExpiryTimestamp) {
        logger.info('🔑 Using cached dealer service PIN from memory.');
        return cachedDealerServicePin;
    }

    logger.info('🔄 Fetching dealer service PIN from Firestore (mpesa_settings/main_config/servicePin)...');
    try {
        const doc = await safaricomDealerConfigRef.get(); // This now points to mpesa_settings/main_config

        if (!doc.exists) {
            const errorMsg = 'Dealer service PIN configuration document (mpesa_settings/main_config) not found in Firestore. Please create it with a "servicePin" field.';
            logger.error(`❌ ${errorMsg}`);
            throw new Error(errorMsg);
        }

        const pin = doc.data().servicePin; // THIS IS THE KEY CHANGE for the field name

        if (!pin) {
            const errorMsg = 'Dealer service PIN field ("servicePin") not found in Firestore document (mpesa_settings/main_config). Please add it.';
            logger.error(`❌ ${errorMsg}`);
            throw new Error(errorMsg);
        }

        // Cache the retrieved PIN and set expiry
        cachedDealerServicePin = pin;
        dealerPinExpiryTimestamp = now + DEALER_PIN_CACHE_TTL;
        logger.info('✅ Successfully fetched and cached dealer service PIN from Firestore.');
        return pin;

    } catch (error) {
        logger.error('❌ Failed to retrieve dealer service PIN from Firestore:', {
            message: error.message,
            stack: error.stack
        });
        throw new Error(`Failed to retrieve dealer service PIN: ${error.message}`);
    }
}


// Carrier detection helper
function detectCarrier(phoneNumber) {
    const normalized = phoneNumber.replace(/^(\+254|254)/, '0').trim();
    if (normalized.length !== 10 || !normalized.startsWith('0')) {
        logger.debug(`Invalid phone number format for carrier detection: ${phoneNumber}`);
        return 'Unknown';
    }
    const prefix3 = normalized.substring(1, 4);

    const safaricom = new Set([
        '110', '111', '112', '113', '114', '115', '116', '117', '118', '119',
        '700', '701', '702', '703', '704', '705', '706', '707', '708', '709',
        '710', '711', '712', '713', '714', '715', '716', '717', '718', '719',
        '720', '721', '722', '723', '724', '725', '726', '727', '728', '729',
        '740', '741', '742', '743', '744', '745', '746', '748', '749',
        '757', '758', '759',
        '768', '769',
        '790', '791', '792', '793', '794', '795', '796', '797', '798', '799'
    ]);
    const airtel = new Set([
        '100', '101', '102', '103', '104', '105', '106', '107', '108', '109',
        '730', '731', '732', '733', '734', '735', '736', '737', '738', '739',
        '750', '751', '752', '753', '754', '755', '756',
        '780', '781', '782', '783', '784', '785', '786', '787', '788', '789'
    ]);
    const telkom = new Set([
        '770', '771', '772', '773', '774', '775', '776', '777', '778', '779'
    ]);
    const equitel = new Set([
        '764', '765', '766', '767',
    ]);
    const faiba = new Set([
        '747',
    ]);

    if (safaricom.has(prefix3)) return 'Safaricom';
    if (airtel.has(prefix3)) return 'Airtel';
    if (telkom.has(prefix3)) return 'Telkom';
    if (equitel.has(prefix3)) return 'Equitel';
    if (faiba.has(prefix3)) return 'Faiba';
    return 'Unknown';
}

// ✅ Safaricom dealer token
async function getCachedAirtimeToken() {
    const now = Date.now();
    if (cachedAirtimeToken && now < tokenExpiryTimestamp) {
        logger.info('🔑 Using cached dealer token');
        return cachedAirtimeToken;
    }
    try {
        const auth = Buffer.from(`${process.env.MPESA_AIRTIME_KEY}:${process.env.MPESA_AIRTIME_SECRET}`).toString('base64');
        const response = await axios.post(
            process.env.MPESA_GRANT_URL,
            {},
            {
                headers: {
                    Authorization: `Basic ${auth}`,
                    'Content-Type': 'application/json',
                },
            }
        );
        const token = response.data.access_token;
        cachedAirtimeToken = token;
        tokenExpiryTimestamp = now + 3599 * 1000;
        logger.info('✅ Fetched new dealer token.');
        return token;
    } catch (error) {
        logger.error('❌ Failed to get Safaricom airtime token:', {
            message: error.message,
            response_data: error.response ? error.response.data : 'N/A',
            stack: error.stack
        });
        throw new Error('Failed to obtain Safaricom airtime token.');
    }
}

function normalizeReceiverPhoneNumber(num) {
    let normalized = String(num).replace(/^(\+254|254)/, '0').trim();
    if (normalized.startsWith('0') && normalized.length === 10) {
        return normalized.slice(1); // Converts '0712345678' to '712345678'
    }
    if (normalized.length === 9 && !normalized.startsWith('0')) {
        return normalized;
    }
    logger.warn(`Phone number could not be normalized to 7XXXXXXXX format for Safaricom: ${num}. Returning as is.`);
    return num; // Return as is, let the API potentially fail for incorrect format
}

// ✅ Send Safaricom dealer airtime
async function sendSafaricomAirtime(receiverNumber, amount) {
    try {
        const token = await getCachedAirtimeToken();
        const normalizedReceiver = normalizeReceiverPhoneNumber(receiverNumber);
        const adjustedAmount = Math.round(amount * 100); // Amount in cents

        if (!process.env.DEALER_SENDER_MSISDN || !process.env.MPESA_AIRTIME_URL) {
            const missingEnvError = 'Missing Safaricom Dealer API environment variables (DEALER_SENDER_MSISDN, MPESA_AIRTIME_URL). DEALER_SERVICE_PIN is now fetched from Firestore.';
            logger.error(missingEnvError);
            return { status: 'FAILED', message: missingEnvError };
        }

        const rawDealerPin = await getDealerServicePin(); 
        const servicePin = await generateServicePin(rawDealerPin); 

        const body = {
            senderMsisdn: process.env.DEALER_SENDER_MSISDN,
            amount: adjustedAmount,
            servicePin: servicePin,
            receiverMsisdn: normalizedReceiver,
        };

        const response = await axios.post(
            process.env.MPESA_AIRTIME_URL,
            body,
            {
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'application/json',
                },
            }
        );

        let safaricomInternalTransId = null;
        let newSafaricomFloatBalance = null;

        // --- CORRECTED: Check Safaricom API response status for actual success ---
        const isSuccess = response.data && response.data.responseStatus === '200';

        if (response.data && response.data.responseDesc) {
            const desc = response.data.responseDesc;
            const idMatch = desc.match(/^(R\d{6}\.\d{4}\.\d{6})/); // Regex for the transaction ID
            if (idMatch && idMatch[1]) {
                safaricomInternalTransId = idMatch[1];
            }
            const balanceMatch = desc.match(/New balance is Ksh\. (\d+(?:\.\d{2})?)/); // Regex for the balance
            if (balanceMatch && balanceMatch[1]) {
                newSafaricomFloatBalance = parseFloat(balanceMatch[1]);
            }
        }

        // Always log the full response from Safaricom for debugging purposes
        logger.info('✅ Safaricom dealer airtime API response:', { receiver: normalizedReceiver, amount: amount, response_data: response.data });

        if (isSuccess) {
            return {
                status: 'SUCCESS',
                message: 'Safaricom airtime sent',
                data: response.data,
                safaricomInternalTransId: safaricomInternalTransId,
                newSafaricomFloatBalance: newSafaricomFloatBalance,
            };
        } else {
            // If the status code indicates failure, return FAILED
            const errorMessage = `Safaricom Dealer API reported failure (Status: ${response.data.responseStatus || 'N/A'}): ${response.data.responseDesc || 'Unknown reason'}`;
            logger.warn(`⚠️ Safaricom dealer airtime send reported non-success:`, {
                receiver: receiverNumber,
                amount: amount,
                response_data: response.data,
                errorMessage: errorMessage
            });
            return {
                status: 'FAILED',
                message: errorMessage,
                error: response.data, // Provide the full response for debugging
            };
        }
    } catch (error) {
        logger.error('❌ Safaricom dealer airtime send failed (exception caught):', {
            receiver: receiverNumber,
            amount: amount,
            message: error.message,
            response_data: error.response ? error.response.data : 'N/A',
            stack: error.stack
        });
        return {
            status: 'FAILED',
            message: 'Safaricom airtime send failed due to network/API error',
            error: error.response ? error.response.data : error.message,
        };
    }
}

// Function to send Africa's Talking Airtime
async function sendAfricasTalkingAirtime(phoneNumber, amount, carrier) {
    let normalizedPhone = phoneNumber;

    // AT expects E.164 format (+254XXXXXXXXX)
    if (phoneNumber.startsWith('0')) {
        normalizedPhone = '+254' + phoneNumber.slice(1);
    } else if (phoneNumber.startsWith('254') && !phoneNumber.startsWith('+')) {
        normalizedPhone = '+' + phoneNumber;
    } else if (phoneNumber.startsWith('+254')) {
        // Already in correct format
        normalizedPhone = phoneNumber;
    } else {
        // Handle numbers without prefix (like 788403012) - assume it's a Kenyan number and add 0
        if (phoneNumber.length === 9 && phoneNumber.startsWith('7')) {
            normalizedPhone = '+254' + phoneNumber;
            logger.info(`📱 Auto-normalized phone number: ${phoneNumber} → ${normalizedPhone}`);
        } else {
            logger.error('[sendAfricasTalkingAirtime] Invalid phone format:', { phoneNumber: phoneNumber });
            return {
                status: 'FAILED',
                message: 'Invalid phone number format for Africa\'s Talking',
                details: {
                    error: 'Phone must start with +254, 254, 0, or be a 9-digit number starting with 7'
                }
            };
        }
    }

    if (!process.env.AT_API_KEY || !process.env.AT_USERNAME) {
        logger.error('Missing Africa\'s Talking API environment variables.');
        return { status: 'FAILED', message: 'Missing Africa\'s Talking credentials.' };
    }

    try {
        const result = await africastalking.AIRTIME.send({
            recipients: [{
                phoneNumber: normalizedPhone,
                amount: amount,
                currencyCode: 'KES'
            }]
        });

        // Defensive check
        const response = result?.responses?.[0];
        const status = response?.status;
        const errorMessage = response?.errorMessage;

        if (status === 'Sent' && errorMessage === 'None') {
            logger.info(`✅ Africa's Talking airtime successfully sent to ${carrier}:`, {
                recipient: normalizedPhone,
                amount: amount,
                at_response: result
            });
            return {
                status: 'SUCCESS',
                message: 'Africa\'s Talking airtime sent',
                data: result,
            };
        } else {
            logger.error(`❌ Africa's Talking airtime send indicates non-success for ${carrier}:`, {
                recipient: normalizedPhone,
                amount: amount,
                at_response: result
            });
            return {
                status: 'FAILED',
                message: 'Africa\'s Talking airtime send failed or not successful.',
                error: result,
            };
        }

    } catch (error) {
        logger.error(`❌ Africa's Talking airtime send failed for ${carrier} (exception caught):`, {
            recipient: normalizedPhone,
            amount: amount,
            message: error.message,
            stack: error.stack
        });
        return {
            status: 'FAILED',
            message: 'Africa\'s Talking airtime send failed (exception)',
            error: error.message,
        };
    }
}

function generateSecurityCredential(password) {
    const certificatePath = '/etc/secrets/ProductionCertificate.cer';

    try {
        console.log('🔹 Reading the public key certificate...');
        const publicKey = fs.readFileSync(certificatePath, 'utf8');

        console.log('✅ Certificate loaded successfully.');
        console.log('🔹 Encrypting the password...');
        const encryptedBuffer = crypto.publicEncrypt(
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_PADDING,
            },
            Buffer.from(password, 'utf8')
        );

        return encryptedBuffer.toString('base64');
    } catch (error) {
        console.error('❌ Error generating security credential:', error.message);
        return null;
    }
}

// Helper function to notify the offline server (add this somewhere in your server.js)
async function notifyOfflineServerForFulfillment(transactionDetails) {
    try {
        const offlineServerUrl = process.env.OFFLINE_SERVER_FULFILLMENT_URL;
        if (!offlineServerUrl) {
            logger.error('OFFLINE_SERVER_FULFILLMENT_URL is not set in environment variables. Cannot notify offline server.');
            return { success: false, message: 'Offline server URL not configured.' };
        }

        // Send a POST request to your offline server
        const response = await axios.post(offlineServerUrl, transactionDetails);

        logger.info(`✅ Notified offline server for fulfillment of ${transactionDetails.checkoutRequestID}. Offline server response:`, response.data);
        return { success: true, responseData: response.data };

    } catch (error) {
        logger.error(`❌ Failed to notify offline server for fulfillment of ${transactionDetails.checkoutRequestID}:`, {
            message: error.message,
            statusCode: error.response ? error.response.status : 'N/A',
            responseData: error.response ? error.response.data : 'N/A',
            stack: error.stack
        });

         // Log this critical error to Firestore's errorsCollection
        await errorsCollection.add({
            type: 'OFFLINE_SERVER_NOTIFICATION_FAILED',
            checkoutRequestID: transactionDetails.checkoutRequestID,
            error: error.message,
            offlineServerResponse: error.response ? error.response.data : null,
            payloadSent: transactionDetails,
            createdAt: FieldValue.serverTimestamp(),
        });

        return { success: false, message: 'Failed to notify offline server.' };
    }
}

// --- NEW: Daraja Reversal Function ---
async function initiateDarajaReversal(transactionId, amount, receiverMsisdn) { 
    logger.info(`🔄 Attempting Daraja reversal for TransID: ${transactionId}, Amount: ${amount}`);
    try {
        const accessToken = await getDarajaAccessToken(); // Function to get Daraja access token

        if (!accessToken) {
            throw new Error("Failed to get Daraja access token for reversal.");
        }

        const url = process.env.MPESA_REVERSAL_URL; 
        const shortCode = process.env.MPESA_SHORTCODE; 
        const initiator = process.env.MPESA_INITIATOR_NAME; 
        const password=process.env.MPESA_SECURITY_PASSWORD;
        const securityCredential = generateSecurityCredential(password);  
        

        if (!url || !shortCode || !initiator || !securityCredential) {
            throw new Error("Missing Daraja reversal environment variables.");
        }

        const payload = {
            Initiator: initiator,
            SecurityCredential: securityCredential, // Use your actual security credential
            CommandID: "TransactionReversal",
            TransactionID: transactionId, // The M-Pesa TransID to be reversed
            Amount: amount, // The amount to reverse
            ReceiverParty: shortCode, // Your Short Code
            RecieverIdentifierType: "11",
            QueueTimeOutURL: process.env.MPESA_REVERSAL_QUEUE_TIMEOUT_URL, // URL for timeout callbacks
            ResultURL: process.env.MPESA_REVERSAL_RESULT_URL, // URL for result callbacks
            Remarks: `Airtime dispatch failed for ${transactionId}`,
            Occasion: "Failed Airtime Topup"
        };

        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`
        };

        const response = await axios.post(url, payload, { headers });

        logger.info(`✅ Daraja Reversal API response for TransID ${transactionId}:`, response.data);

        // Daraja reversal API typically returns a `ResponseCode` and `ResponseDescription`
        // A ResponseCode of '0' usually indicates that the request was accepted for processing.
        // The actual success/failure of the reversal happens asynchronously via the ResultURL.
        // For now, we'll consider '0' as "reversal initiated successfully".
        if (response.data && response.data.ResponseCode === '0') {
            return {
                success: true,
                message: "Reversal request accepted by Daraja.",
                data: response.data,
                // You might store the ConversationID for tracking if provided
                conversationId: response.data.ConversationID || null,
            };
        } else {
            const errorMessage = response.data ?
                `Daraja reversal request failed: ${response.data.ResponseDescription || 'Unknown error'}` :
                'Daraja reversal request failed with no response data.';
            logger.error(`❌ Daraja reversal request not accepted for TransID ${transactionId}: ${errorMessage}`);
            return {
                success: false,
                message: errorMessage,
                data: response.data,
            };
        }

    } catch (error) {
        const errorData = error.response ? error.response.data : error.message;
        logger.error(`❌ Exception during Daraja reversal for TransID ${transactionId}:`, {
            error: errorData,
            stack: error.stack
        });
        return {
            success: false,
            message: `Exception in reversal process: ${errorData.errorMessage || error.message}`,
            error: errorData
        };
    }
}

async function updateCarrierFloatBalance(carrierLogicalName, amount) {
    return firestore.runTransaction(async t => {
        let floatDocRef;
        if (carrierLogicalName === 'safaricomFloat') {
            floatDocRef = safaricomFloatDocRef;
        } else if (carrierLogicalName === 'africasTalkingFloat') {
            floatDocRef = africasTalkingFloatDocRef;
        } else {
            const errorMessage = `Invalid float logical name provided: ${carrierLogicalName}`;
            logger.error(`❌ ${errorMessage}`);
            throw new Error(errorMessage);
        }

        const floatDocSnapshot = await t.get(floatDocRef);

        let currentFloat = 0;
        if (floatDocSnapshot.exists) {
            currentFloat = parseFloat(floatDocSnapshot.data().balance); // Assuming 'balance' field as per your frontend
            if (isNaN(currentFloat)) {
                const errorMessage = `Float balance in document '${carrierLogicalName}' is invalid!`;
                logger.error(`❌ ${errorMessage}`);
                throw new Error(errorMessage);
            }
        } else {
            // If the document doesn't exist, create it with initial balance 0
            logger.warn(`Float document '${carrierLogicalName}' not found. Initializing with balance 0.`);
            t.set(floatDocRef, { balance: 0, lastUpdated: FieldValue.serverTimestamp() }); // Use FieldValue.serverTimestamp()
            currentFloat = 0; // Set currentFloat to 0 for this transaction's calculation
        }

        const newFloat = currentFloat + amount; // amount can be negative for debit
        if (amount < 0 && newFloat < 0) {
            const errorMessage = `Attempt to debit ${carrierLogicalName} float below zero. Current: ${currentFloat}, Attempted debit: ${-amount}`;
            logger.warn(`⚠️ ${errorMessage}`);
            throw new Error('Insufficient carrier-specific float balance for this transaction.');
        }

        t.update(floatDocRef, { balance: newFloat, lastUpdated: FieldValue.serverTimestamp() }); // Use FieldValue.serverTimestamp()
        logger.info(`✅ Updated ${carrierLogicalName} float balance. Old: ${currentFloat}, New: ${newFloat}, Change: ${amount}`);
        return { success: true, newBalance: newFloat };
    });
}

// ---STK Functions ---

// --- RATE LIMITING ---
const stkPushLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 20, // Limit each IP to 20 requests per window
    message: 'Too many STK Push requests from this IP, please try again after a minute.',
    statusCode: 429,
    headers: true,
});

const stkCallbackRateLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 100, // M-Pesa can send multiple retries
    message: 'Too many STK Callback requests, please try again later.',
    statusCode: 429,
    headers: true,
});

// 1. STK Push Initiation Endpoint
app.post('/stk-push', stkPushLimiter, async (req, res) => {
    const { amount, phoneNumber, recipient, customerName, serviceType, reference } = req.body; // Added customerName, serviceType, reference for completeness

    logger.info('🚀 STK Push endpoint called - /stk-push', { 
        amount, 
        phoneNumber, 
        recipient, 
        customerName, 
        serviceType, 
        reference,
        body: req.body 
    });

    if (!amount || !phoneNumber || !recipient) {
        logger.warn('Missing required parameters for STK Push:', { amount, phoneNumber, recipient });
        return res.status(400).json({ success: false, message: 'Missing required parameters: amount, phoneNumber, recipient.' });
    }

    const timestamp = generateTimestamp();
    const password = generatePassword(SHORTCODE, PASSKEY, timestamp);

    logger.info(`Initiating STK Push for recipient: ${recipient}, amount: ${amount}, customer: ${phoneNumber}`);

    // --- Input Validation (moved here for early exit) ---
    const MIN_AMOUNT = 5;
    const MAX_AMOUNT = 5000;
    const amountFloat = parseFloat(amount);

     if (isNaN(amountFloat) || amountFloat < MIN_AMOUNT || amountFloat > MAX_AMOUNT) {
        logger.warn(`🛑 Invalid amount ${amount} for STK Push. Amount must be between ${MIN_AMOUNT} and ${MAX_AMOUNT}.`);
        return res.status(400).json({ success: false, message: `Invalid amount. Must be between ${MIN_AMOUNT} and ${MAX_AMOUNT}.` });
    }

    const cleanedRecipient = recipient.replace(/\D/g, ''); // Ensure only digits
    const cleanedCustomerPhone = phoneNumber.replace(/\D/g, ''); // Ensure only digits

    if (!cleanedRecipient || !cleanedCustomerPhone || cleanedRecipient.length < 9 || cleanedCustomerPhone.length < 9) {
        logger.warn(`🛑 Invalid recipient (${recipient}) or customer phone (${phoneNumber}) for STK Push.`);
        return res.status(400).json({ success: false, message: "Invalid recipient or customer phone number format." });
    }

    const detectedCarrier = detectCarrier(cleanedRecipient); // Detect carrier at initiation
    if (detectedCarrier === 'Unknown') {
        logger.warn(`🛑 Unknown carrier for recipient ${cleanedRecipient}.`);
        return res.status(400).json({ success: false, message: "Recipient's carrier is not supported." });
    }

    // Declare CheckoutRequestID here, it will be set after Daraja response
    let CheckoutRequestID = null;

    try {
        const accessToken = await getAccessToken();

        // Check if this is a driver request (has reference field with driver info)
        let accountReference = cleanedRecipient;
        if (reference && reference.startsWith('DRIVER_AIRTIME_')) {
            // Extract driverId from reference
            const parts = reference.split('_');
            if (parts.length >= 3) {
                const driverId = parts[2];
                // Find driver and get username
                const driverDoc = await firestore.collection('drivers').doc(driverId).get();
                if (driverDoc.exists) {
                    accountReference = driverDoc.data().username;
                    logger.info(`🔄 Using driver username as AccountReference: ${accountReference} (from reference: ${reference})`);
                }
            }
        }
        
        // Truncate AccountReference to M-Pesa limits (max 20 characters)
        const truncatedAccountRef = accountReference.length > 20 ? accountReference.substring(0, 20) : accountReference;
        
        const stkPushPayload = {
            BusinessShortCode: SHORTCODE,
            Password: password,
            Timestamp: timestamp,
            TransactionType: 'CustomerPayBillOnline', // Or 'CustomerBuyGoodsOnline' if applicable
            Amount: amountFloat, // Use the parsed float amount
            PartyA: cleanedCustomerPhone, // Customer's phone number
            PartyB: SHORTCODE, // Your Paybill/Till number
            PhoneNumber: cleanedCustomerPhone, // Customer's phone number
            CallBackURL: STK_CALLBACK_URL,
            AccountReference: truncatedAccountRef, // Use driver username or truncated recipient number
            TransactionDesc: `Airtime for ${cleanedRecipient}`
        };
        
        logger.info('📤 STK Push payload being sent to M-Pesa:', stkPushPayload);

        const stkPushResponse = await axios.post(
            'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
            stkPushPayload,
            {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                     'Content-Type': 'application/json' // Explicitly set Content-Type
                }
            }
        );

        logger.info('STK Push Request Sent to Daraja:', stkPushResponse.data);

        const {
            ResponseCode,
            ResponseDescription,
            CustomerMessage,
            CheckoutRequestID: darajaCheckoutRequestID, // Rename to avoid conflict with outer scope
            MerchantRequestID
        } = stkPushResponse.data;

        // Assign Daraja's CheckoutRequestID to the outer scope variable
        CheckoutRequestID = darajaCheckoutRequestID;

        // ONLY create the stk_transaction document if M-Pesa successfully accepted the push request
        if (ResponseCode === '0') {
            await stkTransactionsCollection.doc(CheckoutRequestID).set({
                checkoutRequestID: CheckoutRequestID,
                merchantRequestID: MerchantRequestID, // Populate directly here
                phoneNumber: cleanedCustomerPhone, // The number that received the STK Push
                amount: amountFloat, // Use amountFloat for consistency
                recipient: cleanedRecipient, // Crucial: Store the intended recipient here
                carrier: detectedCarrier, // Assuming you detect carrier during initial request
                initialRequestAt: FieldValue.serverTimestamp(),
                stkPushStatus: 'PUSH_INITIATED', // Initial status
                stkPushPayload: stkPushPayload, // Store the payload sent to Daraja
                darajaResponse: stkPushResponse.data, // Store full Daraja response here
                customerName: customerName || null,
                serviceType: serviceType || 'airtime',
                reference: reference || null,
                lastUpdated: FieldValue.serverTimestamp(), // Add lastUpdated here too
            });
            logger.info(`✅ STK Transaction document ${CheckoutRequestID} created with STK Push initiation response.`);

            return res.status(200).json({ success: true, message: CustomerMessage, checkoutRequestID: CheckoutRequestID });

        } else {
            // M-Pesa did not accept the push request (e.g., invalid number, insufficient balance in your shortcode)
            logger.error('❌ STK Push Request Failed by Daraja:', stkPushResponse.data);
            // Log this failure in errors collection
            await errorsCollection.add({
                type: 'STK_PUSH_INITIATION_FAILED_BY_DARJA',
                error: ResponseDescription,
                requestPayload: stkPushPayload,
                mpesaResponse: stkPushResponse.data,
                createdAt: FieldValue.serverTimestamp(),
                checkoutRequestID: CheckoutRequestID, // Log this ID even if no record was created for it
            });

            // No stk_transaction document created if Daraja rejected the request
            return res.status(500).json({ success: false, message: ResponseDescription || 'STK Push request failed.' });
        }

    } catch (error) {
        logger.error('❌ Critical error during STK Push initiation:', {
            message: error.message,
            stack: error.stack,
            requestBody: req.body,
            responseError: error.response ? error.response.data : 'No response data'
        });

        const errorMessage = error.response ? (error.response.data.errorMessage || error.response.data.MpesaError || error.response.data) : error.message;

        await errorsCollection.add({
            type: 'STK_PUSH_CRITICAL_INITIATION_ERROR',
            error: errorMessage,
            requestBody: req.body,
            stack: error.stack,
            createdAt: FieldValue.serverTimestamp(),
            checkoutRequestID: CheckoutRequestID || 'N/A', // Log the ID if available
        });

        res.status(500).json({ success: false, message: 'Failed to initiate STK Push.', error: errorMessage });
    }
}); 

// Modified STK Callback Endpoint
app.post('/stk-callback', async (req, res) => {
    const callback = req.body;
    
    logger.info('📞 Received STK Callback:', JSON.stringify(callback, null, 2)); // Log full callback for debugging

    // Safaricom sends an empty object on initial push confirmation before payment
    if (!callback || !callback.Body || !callback.Body.stkCallback) {
        logger.warn('Received an empty or malformed STK callback. Ignoring.');
        // Always respond with ResultCode 0 to M-Pesa to acknowledge receipt and prevent retries.
        return res.json({ ResultCode: 0, ResultDesc: 'Callback processed (ignored empty/malformed).' });
    }

    const { MerchantRequestID, CheckoutRequestID, ResultCode, ResultDesc, CallbackMetadata } = callback.Body.stkCallback;

    // Extracting relevant data from the callback
    const amount = CallbackMetadata?.Item.find(item => item.Name === 'Amount')?.Value;
    const mpesaReceiptNumber = CallbackMetadata?.Item.find(item => item.Name === 'MpesaReceiptNumber')?.Value;
    const transactionDate = CallbackMetadata?.Item.find(item => item.Name === 'TransactionDate')?.Value;
    const customerPhoneNumber = CallbackMetadata?.Item.find(item => item.Name === 'PhoneNumber')?.Value; // PartyA's phone

    // --- Retrieve the STK transaction record ---
    // This is the *only* collection the STK server should read/update now.
    const stkTransactionDocRef = stkTransactionsCollection.doc(CheckoutRequestID);
    const stkTransactionDoc = await stkTransactionDocRef.get();

    if (!stkTransactionDoc.exists) {
        logger.error(`❌ No matching STK transaction record for CheckoutRequestID (${CheckoutRequestID}) found in 'stk_transactions' collection.`);
        
        // Log additional debugging information
        logger.error(`🔍 Debugging STK callback issue:`, {
            checkoutRequestID: CheckoutRequestID,
            merchantRequestID: MerchantRequestID,
            callbackData: callback,
            timestamp: new Date().toISOString()
        });
        
        // Check if there are any recent STK transactions with similar IDs
        const recentTransactions = await stkTransactionsCollection
            .where('checkoutRequestID', '>=', CheckoutRequestID.substring(0, 10))
            .where('checkoutRequestID', '<=', CheckoutRequestID.substring(0, 10) + '\uf8ff')
            .limit(5)
            .get();
            
        if (!recentTransactions.empty) {
            logger.warn(`⚠️ Found ${recentTransactions.size} recent STK transactions with similar IDs:`, 
                recentTransactions.docs.map(doc => doc.data().checkoutRequestID));
        } else {
            logger.warn(`⚠️ No recent STK transactions found with similar IDs`);
        }
        
        // Respond with success to M-Pesa to prevent retries of this unknown callback,
        // but log for manual investigation.
        return res.json({ ResultCode: 0, ResultDesc: 'No matching STK transaction record found.' });
    }
        
    const stkTransactionData = stkTransactionDoc.data();
    // Get original recipient and carrier from the initial STK Push record
    const originalRecipient = stkTransactionData.recipient;
    const originalCarrier = stkTransactionData.carrier;
    const originalAmountRequested = stkTransactionData.amount; // The amount initially requested for the push

    // Prepare common update data for stk_transactions
    const commonStkUpdateData = {
        mpesaResultCode: ResultCode,
        mpesaResultDesc: ResultDesc,
        lastUpdated: FieldValue.serverTimestamp(),
    };
    
    // Only add CallbackMetadata if it exists (it might be undefined for failed/cancelled payments)
    if (CallbackMetadata) {
        commonStkUpdateData.mpesaCallbackMetadata = CallbackMetadata;
    }
    
    // Only add customerPhoneNumber if it exists
    if (customerPhoneNumber) {
        commonStkUpdateData.customerPhoneNumber = customerPhoneNumber;
    }

    // Check M-Pesa ResultCode for success
    if (ResultCode === 0) {
        logger.info(`✅ M-Pesa payment successful for ${CheckoutRequestID}. Updating 'stk_transactions' and notifying offline server.`);

        const successfulStkUpdateData = {
            ...commonStkUpdateData,
            mpesaPaymentStatus: 'SUCCESSFUL',
             mpesaReceiptNumber: mpesaReceiptNumber,
            mpesaTransactionDate: transactionDate,
            amountConfirmed: amount, // Amount from M-Pesa callback
            stkPushStatus: 'MPESA_PAYMENT_SUCCESS', // Final STK transaction status on STK server
        };

        try {
            await stkTransactionDocRef.update(successfulStkUpdateData);
            logger.info(`✅ STK transaction document ${CheckoutRequestID} updated with MPESA_PAYMENT_SUCCESS status.`);


            // Always respond to M-Pesa with ResultCode 0 to acknowledge receipt of the callback.
            return res.json({ ResultCode: 0, ResultDesc: 'Callback received and processing for external fulfillment initiated.' });

        } catch (updateError) {
            logger.error(`❌ Error updating 'stk_transactions' or notifying offline server for ${CheckoutRequestID}:`, { message: updateError.message, stack: updateError.stack });
            await errorsCollection.add({
                type: 'STK_CALLBACK_UPDATE_OR_NOTIFICATION_ERROR',
                checkoutRequestID: CheckoutRequestID,
                error: updateError.message,
                stack: updateError.stack,
                callbackData: callback,
                createdAt: FieldValue.serverTimestamp(),
            });
            // Still respond success to M-Pesa to prevent retries (you'll handle the error internally)
            return res.json({ ResultCode: 0, ResultDesc: 'Callback processed with internal error during update/notification.' });
        }

    } else {
        // M-Pesa payment failed or was cancelled by user
        logger.warn(`⚠️ M-Pesa payment failed or cancelled for ${CheckoutRequestID}. ResultCode: ${ResultCode}, ResultDesc: ${ResultDesc}`);
        const failedStkUpdateData = {
            ...commonStkUpdateData,
            mpesaPaymentStatus: 'FAILED_OR_CANCELLED',
            stkPushStatus: 'MPESA_PAYMENT_FAILED', // Final STK transaction status on STK server
        };

        try {
            // Update only the stk_transactions document for failed/cancelled payments
            await stkTransactionDocRef.update(failedStkUpdateData);
            logger.info(`✅ STK transaction document updated for failed/cancelled payment for ${CheckoutRequestID}.`);
        } catch (error) {
            logger.error(`❌ Error updating 'stk_transactions' for failed/cancelled STK payment ${CheckoutRequestID}:`, { message: error.message, stack: error.stack });
            await errorsCollection.add({
                type: 'STK_CALLBACK_FAILED_PAYMENT_UPDATE_ERROR',
                checkoutRequestID: CheckoutRequestID,
                error: error.message,
                stack: error.stack,
                callbackData: callback,
                createdAt: FieldValue.serverTimestamp(),
            });
        }
        // Always respond with ResultCode 0 to M-Pesa even for failed payments, to acknowledge receipt of the callback.
        return res.json({ ResultCode: 0, ResultDesc: 'Payment failed/cancelled. Callback processed.' });
    }
});

// --- C2B (Offline Paybill) Callbacks ---
/**
 * Processes the airtime fulfillment for a given transaction.
 * This function is designed to be called by both C2B confirmation and STK Push callback.
 *
 * @param {object} params - The parameters for fulfillment.
 * @param {string} params.transactionId - The unique M-Pesa transaction ID (TransID or CheckoutRequestID).
 * @param {number} params.originalAmountPaid - The original amount paid by the customer.
 * @param {string} params.payerMsisdn - The phone number of the customer who paid.
 * @param {string} params.payerName - The name of the customer (optional, can be null for STK Push).
 * @param {string} params.topupNumber - The recipient phone number for airtime.
 * @param {string} params.sourceCallbackData - The raw callback data from M-Pesa (C2B or STK Push).
 * @param {string} params.requestType - 'C2B' or 'STK_PUSH' to differentiate logging/storage.
 * @param {string|null} [params.relatedSaleId=null] - Optional: saleId if already created (e.g., from STK Push initial request).
 * @returns {Promise<object>} - An object indicating success/failure and final status.
 */
async function processAirtimeFulfillment({
    transactionId,
    originalAmountPaid,
    payerMsisdn,
    payerName,
    topupNumber,
    sourceCallbackData,
    requestType,
    relatedSaleId = null,
    driverUsername = null,
    driverId = null
}) {
    const now = FieldValue.serverTimestamp(); // Use server timestamp for consistency
    logger.info(`Starting airtime fulfillment for ${requestType} transaction: ${transactionId}`);

    let airtimeDispatchStatus = 'FAILED';
    let airtimeDispatchResult = null;
    let saleErrorMessage = null;
    let airtimeProviderUsed = null;
    let finalSaleId = relatedSaleId; // Use existing saleId if provided

    try {
        // --- Input Validation (amount range - moved from C2B, now applies to both) ---
        // Note: For STK Push, amount validation happens before dispatch.
        // For C2B, it's here because the initial recording happens before this logic.
        const MIN_AMOUNT = 5;
        const MAX_AMOUNT = 5000;
        const amountInt = Math.round(parseFloat(originalAmountPaid));

        if (amountInt < MIN_AMOUNT || amountInt > MAX_AMOUNT) {
            const errorMessage = `Transaction amount ${amountInt} is outside allowed range (${MIN_AMOUNT} - ${MAX_AMOUNT}).`;
            logger.warn(`🛑 ${errorMessage} Initiating reversal for ${transactionId}.`);
            await errorsCollection.add({
                type: 'AIRTIME_FULFILLMENT_ERROR',
                subType: 'INVALID_AMOUNT_RANGE',
                error: errorMessage,
                transactionId: transactionId,
                originalAmount: originalAmountPaid,
                payerMsisdn: payerMsisdn,
                topupNumber: topupNumber,
                requestType: requestType,
                createdAt: now,
            });

            // Update transaction status before attempting reversal
            await transactionsCollection.doc(transactionId).update({
                status: 'RECEIVED_FULFILLMENT_FAILED',
                fulfillmentStatus: 'FAILED_INVALID_AMOUNT',
                errorMessage: errorMessage,
                lastUpdated: now,
            });

            const reversalResult = await initiateDarajaReversal(transactionId, originalAmountPaid, payerMsisdn);
            if (reversalResult.success) {
                logger.info(`✅ Reversal initiated for invalid amount ${amountInt} on transaction ${transactionId}`);
                await reconciledTransactionsCollection.doc(transactionId).set({
                    transactionId: transactionId,
                    amount: originalAmountPaid,
                    mpesaNumber: payerMsisdn,
                    reversalInitiatedAt: now,
                    reversalRequestDetails: reversalResult.data,
                    originalCallbackData: sourceCallbackData,
                    status: 'REVERSAL_INITIATED',
                    createdAt: now,
                }, { merge: true });
                await transactionsCollection.doc(transactionId).update({
                    status: 'REVERSAL_PENDING_CONFIRMATION',
                    lastUpdated: now,
                    reversalDetails: reversalResult.data,
                    errorMessage: reversalResult.message,
                    reversalAttempted: true,
                });
                return { success: true, status: 'REVERSAL_INITIATED_INVALID_AMOUNT' }; // Return success as reversal was initiated
            } else {
                logger.error(`❌ Reversal failed for invalid amount ${amountInt} for ${transactionId}: ${reversalResult.message}`);
                await failedReconciliationsCollection.doc(transactionId).set({
                    transactionId: transactionId,
                    amount: originalAmountPaid,
                    mpesaNumber: payerMsisdn,
                    reversalAttemptedAt: now,
                    reversalFailureDetails: reversalResult.error,
                    originalCallbackData: sourceCallbackData,
                    reason: `Reversal initiation failed for invalid amount: ${reversalResult.message}`,
                    createdAt: now,
                }, { merge: true });
                await transactionsCollection.doc(transactionId).update({
                    status: 'REVERSAL_INITIATION_FAILED',
                    lastUpdated: now,
                    reversalDetails: reversalResult.error,
                    errorMessage: `Reversal initiation failed for invalid amount: ${reversalResult.message}`,
                    reversalAttempted: true,
                });
                return { success: false, status: 'REVERSAL_FAILED_INVALID_AMOUNT', error: reversalResult.message };
            }
        }


        // --- Determine target carrier ---
        const targetCarrier = detectCarrier(topupNumber);
        if (targetCarrier === 'Unknown') {
            const errorMessage = `Unsupported carrier prefix for airtime top-up: ${topupNumber}`;
            logger.error(`❌ ${errorMessage}`, { TransID: transactionId, topupNumber: topupNumber });
            await errorsCollection.add({
                type: 'AIRTIME_FULFILLMENT_ERROR',
                subType: 'UNKNOWN_CARRIER',
                error: errorMessage,
                transactionId: transactionId,
                requestType: requestType,
                createdAt: now,
            });
            await transactionsCollection.doc(transactionId).update({
                status: 'RECEIVED_FULFILLMENT_FAILED',
                fulfillmentStatus: 'FAILED_UNKNOWN_CARRIER',
                errorMessage: errorMessage,
                lastUpdated: now,
            });
            return { success: false, status: 'FAILED_UNKNOWN_CARRIER', error: errorMessage };
        }

        // --- FETCH BONUS SETTINGS AND CALCULATE FINAL AMOUNT TO DISPATCH ---
        const bonusDocRef = firestore.collection('airtime_bonuses').doc('current_settings');
        const bonusDocSnap = await bonusDocRef.get();

        let safaricomBonus = 0;
        let atBonus = 0;

        if (bonusDocSnap.exists) {
            safaricomBonus = bonusDocSnap.data()?.safaricomPercentage ?? 0;
            atBonus = bonusDocSnap.data()?.africastalkingPercentage ?? 0;
        } else {
            logger.warn('Bonus settings document does not exist. Skipping bonus application.');
        }

        let finalAmountToDispatch = originalAmountPaid;
        let bonusApplied = 0;

        // Custom rounding: 0.1–0.4 => 0, 0.5–0.9 => 1
        const customRound = (value) => {
            const decimalPart = value % 1;
            const integerPart = Math.floor(value);
            return decimalPart >= 0.5 ? integerPart + 1 : integerPart;
        };

        // Apply bonus with optional rounding
        const applyBonus = (amount, percentage, label, round = false) => {
            const rawBonus = amount * (percentage / 100);
            const bonus = round ? customRound(rawBonus) : rawBonus;
            const total = amount + bonus;
            logger.info(
                `Applying ${percentage}% ${label} bonus. Original: ${amount}, Bonus: ${bonus} (${round ? 'rounded' : 'raw'}), Final: ${total}`
            );
            return { total, bonus, rawBonus };
        };

        // Normalize carrier name to lowercase
        const carrierNormalized = targetCarrier.toLowerCase();

        if (carrierNormalized === 'safaricom' && safaricomBonus > 0) {
            const result = applyBonus(originalAmountPaid, safaricomBonus, 'Safaricom', false); // No rounding
            finalAmountToDispatch = result.total;
            bonusApplied = result.rawBonus;
        } else if (['airtel', 'telkom', 'equitel', 'faiba'].includes(carrierNormalized) && atBonus > 0) {
            const result = applyBonus(originalAmountPaid, atBonus, 'AfricasTalking', true); // Use custom rounding
            finalAmountToDispatch = result.total;
            bonusApplied = result.bonus;
        }

        logger.info(`Final amount to dispatch for ${transactionId}: ${finalAmountToDispatch}`);

        // --- Initialize or Update sale document ---
        const saleData = {
            relatedTransactionId: transactionId,
            topupNumber: topupNumber,
            originalAmountPaid: originalAmountPaid,
            amount: finalAmountToDispatch, // This is the amount actually dispatched (original + bonus)
            bonusApplied: bonusApplied, // Store the bonus amount
            carrier: targetCarrier, // Use the detected carrier
            status: 'PENDING_DISPATCH',
            dispatchAttemptedAt: now,
            lastUpdated: now,
            requestType: requestType, // C2B or STK_PUSH
            // createdAt will be set if this is a new document, or remain if it's an update
        };

        if (finalSaleId) {
            // If relatedSaleId exists (from STK Push initial request), update it
            const saleDoc = await salesCollection.doc(finalSaleId).get();
            if (saleDoc.exists) {
                await salesCollection.doc(finalSaleId).update(saleData);
                logger.info(`✅ Updated existing sale document ${finalSaleId} for TransID ${transactionId} with fulfillment details.`);
            } else {
                // If ID was provided but document doesn't exist (e.g., deleted), create new one
                const newSaleRef = salesCollection.doc();
                finalSaleId = newSaleRef.id;
                await newSaleRef.set({ saleId: finalSaleId, createdAt: now, ...saleData });
                logger.warn(`⚠️ Sale document ${relatedSaleId} not found. Created new sale document ${finalSaleId} for TransID ${transactionId}.`);
            }
        } else {
            // Create a new sale document (typical for C2B)
            const newSaleRef = salesCollection.doc();
            finalSaleId = newSaleRef.id;
            await newSaleRef.set({ saleId: finalSaleId, createdAt: now, ...saleData });
            logger.info(`✅ Initialized new sale document ${finalSaleId} in 'sales' collection for TransID ${transactionId}.`);
        }

        // --- Conditional Airtime Dispatch Logic based on Carrier ---
        if (targetCarrier === 'Safaricom') {
            try {
                await updateCarrierFloatBalance('safaricomFloat', -finalAmountToDispatch);
                airtimeProviderUsed = 'SafaricomDealer';
                airtimeDispatchResult = await sendSafaricomAirtime(topupNumber, finalAmountToDispatch);

                if (airtimeDispatchResult && airtimeDispatchResult.status === 'SUCCESS') {
                    airtimeDispatchStatus = 'COMPLETED';
                    logger.info(`✅ Safaricom airtime successfully sent via Dealer Portal for sale ${finalSaleId}.`);
                } else {
                    saleErrorMessage = airtimeDispatchResult?.error || 'Safaricom Dealer Portal failed with unknown error.';
                    logger.warn(`⚠️ Safaricom Dealer Portal failed for TransID ${transactionId}. Attempting fallback to Africastalking. Error: ${saleErrorMessage}`);

                    // Refund Safaricom float, as primary attempt failed
                    await updateCarrierFloatBalance('safaricomFloat', finalAmountToDispatch);
                    logger.info(`✅ Refunded Safaricom float for TransID ${transactionId}: +${finalAmountToDispatch}`);

                    // Attempt fallback via Africa's Talking (debit AT float)
                    await updateCarrierFloatBalance('africasTalkingFloat', -finalAmountToDispatch);
                    airtimeProviderUsed = 'AfricasTalkingFallback';
                    airtimeDispatchResult = await sendAfricasTalkingAirtime(topupNumber, finalAmountToDispatch, targetCarrier);

                    if (airtimeDispatchResult && airtimeDispatchResult.status === 'SUCCESS') {
                        airtimeDispatchStatus = 'COMPLETED';
                        logger.info(`✅ Safaricom fallback airtime successfully sent via AfricasTalking for sale ${finalSaleId}.`);
                        // NEW: Adjust Africa's Talking float for 4% commission
                        const commissionAmount = parseFloat((originalAmountPaid * 0.04).toFixed(2));
                        await updateCarrierFloatBalance('africasTalkingFloat', commissionAmount);
                        logger.info(`✅ Credited Africa's Talking float with ${commissionAmount} (4% commission) for TransID ${transactionId}.`);
                    } else {
                        saleErrorMessage = airtimeDispatchResult ? airtimeDispatchResult.error : 'AfricasTalking fallback failed with no specific error.';
                        logger.error(`❌ Safaricom fallback via AfricasTalking failed for sale ${finalSaleId}: ${saleErrorMessage}`);
                    }
                }
            } catch (dispatchError) {
                saleErrorMessage = `Safaricom primary dispatch process failed (or float debit failed): ${dispatchError.message}`;
                logger.error(`❌ Safaricom primary dispatch process failed for TransID ${transactionId}: ${dispatchError.message}`);
            }

        } else if (['Airtel', 'Telkom', 'Equitel', 'Faiba'].includes(targetCarrier)) {
            // Directly dispatch via Africa's Talking
            try {
                await updateCarrierFloatBalance('africasTalkingFloat', -finalAmountToDispatch);
                airtimeProviderUsed = 'AfricasTalkingDirect';
                airtimeDispatchResult = await sendAfricasTalkingAirtime(topupNumber, finalAmountToDispatch, targetCarrier);

                if (airtimeDispatchResult && airtimeDispatchResult.status === 'SUCCESS') {
                    airtimeDispatchStatus = 'COMPLETED';
                    logger.info(`✅ AfricasTalking airtime successfully sent directly for sale ${finalSaleId}.`);
                    // NEW: Adjust Africa's Talking float for 4% commission
                    const commissionAmount = parseFloat((originalAmountPaid * 0.04).toFixed(2));
                    await updateCarrierFloatBalance('africasTalkingFloat', commissionAmount);
                    logger.info(`✅ Credited Africa's Talking float with ${commissionAmount} (4% commission) for TransID ${transactionId}.`);
                } else {
                    saleErrorMessage = airtimeDispatchResult ? airtimeDispatchResult.Safaricom : 'AfricasTalking direct dispatch failed with no specific error.';
                    logger.error(`❌ AfricasTalking direct dispatch failed for sale ${finalSaleId}: ${saleErrorMessage}`);
                }
            } catch (dispatchError) {
                saleErrorMessage = `AfricasTalking direct dispatch process failed (or float debit failed): ${dispatchError.message}`;
                logger.error(`❌ AfricasTalking direct dispatch process failed for TransID ${transactionId}: ${dispatchError.message}`);
            }
        } else {
            // This case should ideally be caught by the initial detectCarrier check, but good for robustness
            saleErrorMessage = `No valid dispatch path for carrier: ${targetCarrier}`;
            logger.error(`❌ ${saleErrorMessage} for TransID ${transactionId}`);
            await errorsCollection.add({
                type: 'AIRTIME_FULFILLMENT_ERROR',
                subType: 'NO_DISPATCH_PATH',
                error: saleErrorMessage,
                transactionId: transactionId,
                requestType: requestType,
                createdAt: now,
            });
        }

        const updateSaleFields = {
            lastUpdated: now,
            dispatchResult: airtimeDispatchResult?.data || airtimeDispatchResult?.error || airtimeDispatchResult,
            airtimeProviderUsed: airtimeProviderUsed,
        };

        // If airtime dispatch was COMPLETELY successful
        if (airtimeDispatchStatus === 'COMPLETED') {
            updateSaleFields.status = airtimeDispatchStatus;

            // Only update Safaricom float balance from API response if Safaricom Dealer was used and successful
            if (targetCarrier === 'Safaricom' && airtimeDispatchResult && airtimeDispatchResult.newSafaricomFloatBalance !== undefined && airtimeProviderUsed === 'SafaricomDealer') {
                try {
                    await safaricomFloatDocRef.update({
                        balance: airtimeDispatchResult.newSafaricomFloatBalance,
                        lastUpdated: now
                    });
                    logger.info(`✅ Safaricom float balance directly updated from API response for TransID ${transactionId}. New balance: ${airtimeDispatchResult.newSafaricomFloatBalance}`);
                } catch (floatUpdateErr) {
                    logger.error(`❌ Failed to directly update Safaricom float from API response for TransID ${transactionId}:`, {
                        error: floatUpdateErr.message, reportedBalance: airtimeDispatchResult.newSafaricomFloatBalance
                    });
                    const reportedBalanceForError = airtimeDispatchResult.newSafaricomFloatBalance !== undefined ? airtimeDispatchResult.newSafaricomFloatBalance : 'N/A';
                    await errorsCollection.add({
                        type: 'FLOAT_RECONCILIATION_WARNING',
                        subType: 'SAFARICOM_REPORTED_BALANCE_UPDATE_FAILED',
                        error: `Failed to update Safaricom float with reported balance: ${floatUpdateErr.message}`,
                        transactionId: transactionId,
                        saleId: finalSaleId,
                        reportedBalance: reportedBalanceForError,
                        createdAt: now,
                    });
                }
            }
            await salesCollection.doc(finalSaleId).update(updateSaleFields);
            logger.info(`✅ Updated sale document ${finalSaleId} with dispatch result (COMPLETED).`);

            // --- Award driver commission if driver username was used ---
            if (driverUsername && driverId) {
                try {
                    logger.info(`💰 Processing driver commission for username: ${driverUsername}, driverId: ${driverId}, amount: ${originalAmountPaid}`);
                    
                    // Get commission percentage from wallet_bonuses/drivers_comm
                    const commissionDoc = await firestore.collection('wallet_bonuses').doc('drivers_comm').get();
                    const commissionPercentage = commissionDoc.exists ? commissionDoc.data().percentage || 0 : 0;
                    const commissionAmount = originalAmountPaid * (commissionPercentage / 100);
                    
                    logger.info(`📊 Driver commission calculation - percentage: ${commissionPercentage}%, amount: ${originalAmountPaid}, commission: ${commissionAmount}`);
                    
                    if (commissionAmount > 0) {
                        // Update driver's commission earned
                        await firestore.collection('drivers').doc(driverId).update({
                            commissionEarned: FieldValue.increment(commissionAmount),
                            lastCommissionUpdate: now
                        });
                        
                        logger.info(`✅ Awarded commission ${commissionAmount} to driver ${driverUsername} (${driverId})`);
                        
                        // Log commission award in bonus_history
                        await bonusHistoryCollection.add({
                            type: 'DRIVER_COMMISSION_AWARDED',
                            driverId: driverId,
                            driverUsername: driverUsername,
                            transactionId: transactionId,
                            saleId: finalSaleId,
                            originalAmount: originalAmountPaid,
                            commissionPercentage: commissionPercentage,
                            commissionAmount: commissionAmount,
                            createdAt: now
                        });
                    } else {
                        logger.warn(`⚠️ No commission awarded - percentage is 0 or document not found for driver ${driverUsername}`);
                    }
                } catch (commissionError) {
                    logger.error(`❌ Error awarding driver commission for ${driverUsername}:`, {
                        error: commissionError.message,
                        driverId: driverId,
                        amount: originalAmountPaid
                    });
                    
                    // Log commission error but don't fail the transaction
                    await errorsCollection.add({
                        type: 'DRIVER_COMMISSION_ERROR',
                        error: commissionError.message,
                        driverId: driverId,
                        driverUsername: driverUsername,
                        transactionId: transactionId,
                        saleId: finalSaleId,
                        amount: originalAmountPaid,
                        createdAt: now
                    });
                }
            }

            // Also update the main transaction status to fulfilled
            await transactionsCollection.doc(transactionId).update({
                status: 'COMPLETED_AND_FULFILLED',
                fulfillmentStatus: airtimeDispatchStatus,
                fulfillmentDetails: airtimeDispatchResult,
                lastUpdated: now,
                airtimeProviderUsed: airtimeProviderUsed,
                driverCommissionAwarded: driverUsername ? true : false,
                driverUsername: driverUsername || null,
                driverId: driverId || null
            });
            logger.info(`✅ Transaction ${transactionId} marked as COMPLETED_AND_FULFILLED.`);
            return { success: true, status: 'COMPLETED_AND_FULFILLED' };

        } else {
            // Airtime dispatch ultimately failed (either primary or fallback)
            saleErrorMessage = saleErrorMessage || 'Airtime dispatch failed with no specific error message.';
            logger.error(`❌ Airtime dispatch ultimately failed for sale ${finalSaleId} (TransID ${transactionId}):`, {
                error_message: saleErrorMessage,
                carrier: targetCarrier,
                topupNumber: topupNumber,
                originalAmountPaid: originalAmountPaid,
                finalAmountDispatched: finalAmountToDispatch,
                airtimeResponse: airtimeDispatchResult,
                sourceCallbackData: sourceCallbackData,
            });
            await errorsCollection.add({
                type: 'AIRTIME_FULFILLMENT_ERROR',
                subType: 'AIRTIME_DISPATCH_FAILED',
                error: saleErrorMessage,
                transactionId: transactionId,
                saleId: finalSaleId,
                sourceCallbackData: sourceCallbackData,
                airtimeApiResponse: airtimeDispatchResult,
                providerAttempted: airtimeProviderUsed,
                requestType: requestType,
                createdAt: now,
            });

            updateSaleFields.status = 'FAILED_DISPATCH_API';
            updateSaleFields.errorMessage = saleErrorMessage;
            await salesCollection.doc(finalSaleId).update(updateSaleFields);
            logger.info(`✅ Updated sale document ${finalSaleId} with dispatch result (FAILED).`);

            // --- Initiate Reversal if airtime dispatch failed ---
            logger.warn(`🛑 Airtime dispatch ultimately failed for TransID ${transactionId}. Initiating Daraja reversal.`);

            // Update main transaction status to reflect immediate failure
            await transactionsCollection.doc(transactionId).update({
                status: 'RECEIVED_FULFILLMENT_FAILED',
                fulfillmentStatus: 'FAILED_DISPATCH_API',
                fulfillmentDetails: airtimeDispatchResult,
                errorMessage: saleErrorMessage,
                lastUpdated: now,
                airtimeProviderUsed: airtimeProviderUsed,
                reversalAttempted: true,
            });

            const reversalResult = await initiateDarajaReversal(transactionId, originalAmountPaid, payerMsisdn);

            if (reversalResult.success) {
                logger.info(`✅ Daraja reversal initiated successfully for TransID ${transactionId}.`);
                await reconciledTransactionsCollection.doc(transactionId).set({
                    transactionId: transactionId,
                    amount: originalAmountPaid,
                    mpesaNumber: payerMsisdn,
                    reversalInitiatedAt: now,
                    reversalRequestDetails: reversalResult.data,
                    originalCallbackData: sourceCallbackData,
                    status: 'REVERSAL_INITIATED',
                    createdAt: now,
                }, { merge: true });
                await transactionsCollection.doc(transactionId).update({
                    status: 'REVERSAL_PENDING_CONFIRMATION',
                    lastUpdated: now,
                    reversalDetails: reversalResult.data,
                    errorMessage: reversalResult.message,
                });
                return { success: true, status: 'REVERSAL_INITIATED' };
            } else {
                logger.error(`❌ Daraja reversal failed to initiate for TransID ${transactionId}: ${reversalResult.message}`);
                await failedReconciliationsCollection.doc(transactionId).set({
                    transactionId: transactionId,
                    amount: originalAmountPaid,
                    mpesaNumber: payerMsisdn,
                    reversalAttemptedAt: now,
                    reversalFailureDetails: reversalResult.error,
                    originalCallbackData: sourceCallbackData,
                    reason: reversalResult.message,
                    createdAt: now,
                }, { merge: true });
                await transactionsCollection.doc(transactionId).update({
                    status: 'REVERSAL_INITIATION_FAILED',
                    lastUpdated: now,
                    reversalDetails: reversalResult.error,
                    errorMessage: `Reversal initiation failed: ${reversalResult.message}`
                });
                return { success: false, status: 'REVERSAL_INITIATION_FAILED', error: reversalResult.message };
            }
        }
    } catch (error) {
        logger.error(`❌ CRITICAL ERROR during Airtime Fulfillment for TransID ${transactionId}:`, {
            message: error.message,
            stack: error.stack,
            sourceCallbackData: sourceCallbackData,
            requestType: requestType,
        });

        // Ensure main transaction record reflects critical error
        if (transactionId) {
            try {
                await transactionsCollection.doc(transactionId).update({
                    status: 'CRITICAL_FULFILLMENT_ERROR',
                    errorMessage: `Critical server error during airtime fulfillment: ${error.message}`,
                    lastUpdated: now,
                });
            } catch (updateError) {
                logger.error(`❌ Failed to update transaction ${transactionId} after critical fulfillment error:`, updateError.message);
            }
        }

        // Add to errors collection as a fallback
        await errorsCollection.add({
            type: 'CRITICAL_FULFILLMENT_ERROR',
            error: error.message,
            stack: error.stack,
            transactionId: transactionId,
            requestType: requestType,
            sourceCallbackData: sourceCallbackData,
            createdAt: now,
        });

        return { success: false, status: 'CRITICAL_ERROR', error: error.message };
    }
}

// C2B Validation Endpoint
app.post('/c2b-validation', async (req, res) => {
    const callbackData = req.body;
    const now = new Date();
    const transactionIdentifier = callbackData.TransID || `C2B_VALIDATION_${Date.now()}`;
    const { TransAmount, BillRefNumber } = callbackData;
    const amount = parseFloat(TransAmount);

    try {
        // ✅ Validate phone format, account number, or driver username
        const phoneRegex = /^(\+254|254|0)(1\d|7\d)\d{7}$/;
        const isPhone = phoneRegex.test(BillRefNumber);
        let isAccountNumber = false;
        let isDriverUsername = false;
        
        if (!isPhone) {
            // Check if BillRefNumber matches a registered account number across all user collections
            const [retailersSnap, driversSnap, organisationsSnap] = await Promise.all([
                firestore.collection('retailers').where('accountNumber', '==', BillRefNumber).limit(1).get(),
                firestore.collection('drivers').where('accountNumber', '==', BillRefNumber).limit(1).get(),
                firestore.collection('organisations').where('accountNumber', '==', BillRefNumber).limit(1).get()
            ]);
            isAccountNumber = !retailersSnap.empty || !driversSnap.empty || !organisationsSnap.empty;
            
            // If not an account number, check if it's a driver username
            if (!isAccountNumber) {
                const driversUsernameSnap = await firestore.collection('drivers').where('username', '==', BillRefNumber).limit(1).get();
                isDriverUsername = !driversUsernameSnap.empty;
            }
        }
        
        if (!isPhone && !isAccountNumber && !isDriverUsername) {
            throw {
                code: 'C2B00012',
                desc: `Invalid BillRefNumber format: ${BillRefNumber}. Must be a phone number, account number, or driver username.`,
                subType: 'INVALID_BILL_REF'
            };
        }

        // ✅ Detect carrier (only if phone)
        let carrier = 'Unknown';
        if (isPhone) {
            carrier = detectCarrier(BillRefNumber);
            if (carrier === 'Unknown') {
                throw {
                    code: 'C2B00011',
                    desc: `Could not detect carrier from BillRefNumber: ${BillRefNumber}`,
                    subType: 'CARRIER_UNKNOWN'
                };
            }
        }

        // ✅ Fetch settings from Firestore in parallel
        const [carrierDoc, systemDoc] = await Promise.all([
            isPhone ? firestore.collection('carrier_settings').doc(carrier.toLowerCase()).get() : Promise.resolve({ exists: true, data: () => ({ active: true }) }),
            firestore.collection('system_settings').doc('global').get(),
        ]);

        // ✅ Check system status
        const systemStatus = systemDoc.exists ? systemDoc.data().status : 'offline';
        if (systemStatus !== 'online') {
            throw {
                code: 'C2B00016',
                desc: `System is currently offline.`,
                subType: 'SYSTEM_OFFLINE'
            };
        }

        // ✅ Check if carrier is active (only if phone)
        const carrierActive = isPhone ? (carrierDoc.exists ? carrierDoc.data().active : false) : true;
        if (isPhone && !carrierActive) {
            throw {
                code: 'C2B00011',
                desc: `${carrier} is currently inactive`,
                subType: 'CARRIER_INACTIVE'
            };
        }

        // ✅ Passed all checks
        console.info('✅ C2B Validation successful:', {
            TransID: transactionIdentifier,
            Amount: TransAmount,
            Carrier: carrier,
            Phone: BillRefNumber,
        });

        return res.json({
            ResultCode: '0',
            ResultDesc: 'Accepted',
        });

    } catch (err) {
        console.warn(`❌ Validation failed [${transactionIdentifier}]: ${err.desc}`, { error: err });

        await firestore.collection('errors').add({
            type: 'C2B_VALIDATION_REJECT',
            subType: err.subType || 'UNKNOWN_ERROR',
            error: err.desc || JSON.stringify(err),
            callbackData,
            createdAt: FieldValue.serverTimestamp(),
        });

        return res.json({
            ResultCode: err.code || 'C2B00016',
            ResultDesc: 'Rejected',
        });
    }
});


// C2B Confirmation Endpoint (Mandatory)
app.post('/c2b-confirmation', async (req, res) => {
    const callbackData = req.body;
    const transactionId = callbackData.TransID;
    const now = FieldValue.serverTimestamp(); // Use server timestamp

    logger.info('📞 Received C2B Confirmation Callback:', { TransID: transactionId, callback: callbackData });

    const {
        TransTime,
        TransAmount,
        BillRefNumber,
        MSISDN,
        FirstName,
        MiddleName,
        LastName,
    } = callbackData;

    const amount = parseFloat(TransAmount); // This is the original amount paid by customer
    const mpesaNumber = MSISDN;
    const customerName = `${FirstName || ''} ${MiddleName || ''} ${LastName || ''}`.trim();

    try {
        // --- 1. Record the incoming M-Pesa transaction (money received) ---
        const existingTxDoc = await transactionsCollection.doc(transactionId).get();
        if (existingTxDoc.exists) {
            logger.warn(`⚠️ Duplicate C2B confirmation for TransID: ${transactionId}. Skipping processing.`);
            return res.json({ "ResultCode": 0, "ResultDesc": "Duplicate C2B confirmation received and ignored." });
        }

        // Check if BillRefNumber is a phone number, account number, or driver username
        const phoneRegex = /^(\+254|254|0)(1\d|7\d)\d{7}$/;
        const isPhone = phoneRegex.test(BillRefNumber);
        let topupNumber = BillRefNumber;
        let walletUpdateResult = null;
        let bonusApplied = 0;
        let bonusPercentage = 0;
        let driverUsername = null;
        let driverId = null;
        
        logger.info(`🔍 C2B Confirmation - BillRefNumber: ${BillRefNumber}, isPhone: ${isPhone}, amount: ${amount}`);
        
        if (!isPhone) {
            // Check if it's an account number first
            const [retailersSnap, driversSnap, organisationsSnap] = await Promise.all([
                firestore.collection('retailers').where('accountNumber', '==', BillRefNumber).limit(1).get(),
                firestore.collection('drivers').where('accountNumber', '==', BillRefNumber).limit(1).get(),
                firestore.collection('organisations').where('accountNumber', '==', BillRefNumber).limit(1).get()
            ]);
            
            let userDoc = null;
            let userRef = null;
            let userData = null;
            let userCollection = null;
            
            if (!retailersSnap.empty) {
                userDoc = retailersSnap.docs[0];
                userRef = userDoc.ref;
                userData = userDoc.data();
                userCollection = 'retailers';
            } else if (!driversSnap.empty) {
                userDoc = driversSnap.docs[0];
                userRef = userDoc.ref;
                userData = userDoc.data();
                userCollection = 'drivers';
            } else if (!organisationsSnap.empty) {
                userDoc = organisationsSnap.docs[0];
                userRef = userDoc.ref;
                userData = userDoc.data();
                userCollection = 'organisations';
            }
            
            // If not found as account number, check if it's a driver username
            if (!userDoc) {
                const driversUsernameSnap = await firestore.collection('drivers').where('username', '==', BillRefNumber).limit(1).get();
                if (!driversUsernameSnap.empty) {
                    userDoc = driversUsernameSnap.docs[0];
                    userRef = userDoc.ref;
                    userData = userDoc.data();
                    userCollection = 'drivers';
                    driverUsername = BillRefNumber;
                    driverId = userDoc.id;
                    logger.info(`✅ Found driver by username: ${driverUsername}, driverId: ${driverId}`);
                }
            }
            
            if (userDoc) {
                // Check if this is a driver username (airtime sale) or account number (wallet top-up)
                if (driverUsername && driverId) {
                    // SCENARIO 2: Driver Username - Send airtime and award commission
                    logger.info(`🚗 Driver airtime sale detected - username: ${driverUsername}, driverId: ${driverId}, amount: ${amount}`);
                    
                    // Find the pending transaction to get recipient phone from single_sales collection
                    const pendingTransactionSnap = await firestore.collection('single_sales').doc(driverUsername).collection('sales')
                        .where('driverUsername', '==', driverUsername)
                        .where('type', '==', 'DRIVER_AIRTIME_SALE_PENDING')
                        .where('status', '==', 'PENDING')
                        .orderBy('createdAt', 'desc')
                        .limit(1)
                        .get();
                    
                    let recipientPhone = null;
                    if (!pendingTransactionSnap.empty) {
                        const pendingTx = pendingTransactionSnap.docs[0].data();
                        recipientPhone = pendingTx.recipientPhone;
                        logger.info(`✅ Found pending transaction with recipientPhone: ${recipientPhone}`);
                    } else {
                        logger.warn(`⚠️ No pending transaction found for driver ${driverUsername}, using customer phone as fallback`);
                        recipientPhone = mpesaNumber; // Fallback to customer phone
                    }
                    
                    if (!recipientPhone) {
                        logger.error(`❌ No recipient phone found for driver ${driverUsername}`);
                        return res.json({ "ResultCode": 0, "ResultDesc": "No recipient phone found" });
                    }
                    
                    // Detect carrier and send airtime
                    const carrier = detectCarrier(recipientPhone);
                    logger.info(`📱 Sending airtime to ${recipientPhone}, carrier: ${carrier}, amount: ${amount}`);
                    
                    let airtimeResult;
                    if (carrier === 'Safaricom') {
                        airtimeResult = await sendSafaricomAirtime(recipientPhone, amount);
                    } else {
                        airtimeResult = await sendAfricasTalkingAirtime(recipientPhone, amount, carrier);
                    }
                    
                    if (airtimeResult && airtimeResult.status === 'SUCCESS') {
                        // --- START OF NEW COMMISSION LOGIC ---
                        let commissionPercentage = 0;
                        const commissionSettingsDoc = await firestore.collection('airtime_bonuses').doc('current_settings').get();
    
                      if (commissionSettingsDoc.exists) {
                          const settings = commissionSettingsDoc.data();
                          if (carrier === 'Safaricom') {
                              commissionPercentage = settings.safaricomPercentage || 0;
                          } else {
                              commissionPercentage = settings.africastalkingPercentage || 0;
                            }
                      } else {
                          logger.warn(`⚠️ airtime_bonuses/current_settings document not found. Commission will be 0.`);
                          }

                      const commissionAmount = amount * (commissionPercentage / 100);
    
                        logger.info(`💰 Driver commission calculation - driverId: ${driverId}, amount: ${amount}, carrier: ${carrier}, commissionPercentage: ${commissionPercentage}%, commissionAmount: ${commissionAmount}`);
    
                        if (commissionAmount > 0) {
                            await userRef.update({
                                commissionEarned: FieldValue.increment(commissionAmount),
                                lastCommissionUpdate: now
                            });
                            logger.info(`✅ Commission awarded to driver ${driverId}: ${commissionAmount}`);
                        }
                        
                        // Log successful airtime sale in single_sales collection
                        const saleId = `SINGLE_SALE_${Date.now()}_${driverId}`;
                        const organizationName = userData.username || userData.displayName || userData.name || userData.shopName || userData.organizationName || userData.orgName || userData.email || userData.phoneNumber || driverId || 'unknown';
                        
                        // Log the user data for debugging if organizationName is still 'unknown'
                        if (organizationName === 'unknown') {
                            logger.warn(`⚠️ Could not find organization name for driver ${driverId}. User data:`, {
                                userData: userData,
                                availableFields: Object.keys(userData || {})
                            });
                        } else {
                            logger.info(`✅ Found organization name for driver ${driverId}: ${organizationName}`);
                        }
                        
                        try {
                            await firestore.collection('single_sales').doc(organizationName).collection('sales').doc(saleId).set({
                                saleId,
                                type: 'DRIVER_AIRTIME_SALE_C2B',
                                userId: driverId,
                                userType: 'driver',
                                organizationName,
                                phoneNumber: recipientPhone,
                                amount,
                                telco: carrier,
                                recipientName: '',
                                status: 'SUCCESS',
                                message: 'Airtime sent via C2B confirmation',
                                commissionEarned: commissionAmount,
                                customerPhone: mpesaNumber,
                                transactionId,
                                createdAt: now,
                                lastUpdated: now
                            });
                            logger.info(`✅ Successfully wrote single sale for driver: ${organizationName}, saleId: ${saleId}, phoneNumber: ${recipientPhone}, amount: ${amount}`);
                        } catch (err) {
                            logger.error(`❌ Failed to write single sale for driver: ${organizationName}, saleId: ${saleId}`, { 
                                error: err.message, 
                                stack: err.stack,
                                organizationName,
                                saleId,
                                phoneNumber: recipientPhone,
                                amount,
                                driverId
                            });
                        }
                        
                        // Driver sales are now stored only in single_sales collection
                        logger.info(`✅ Driver airtime sale completed - airtime sent to ${recipientPhone}, commission awarded: ${commissionAmount}`);
                    } else {
                        logger.error(`❌ Failed to send airtime for driver ${driverId}: ${airtimeResult?.message || 'Unknown error'}`);
                    }
                    
                } else {
                    // SCENARIO 1: Account Number - Wallet top-up
                    logger.info(`✅ Found user: ${userDoc.id}, current wallet balance: ${userData.walletBalance || 0}`);
                    
                    // Fetch bonus percentage (global or per-user)
                    const bonusDoc = await firestore.collection('wallet_bonuses').doc('current_settings').get();
                    if (bonusDoc.exists) {
                        bonusPercentage = bonusDoc.data().percentage || 0;
                        logger.info(`📊 Global bonus percentage: ${bonusPercentage}%`);
                    } else {
                        logger.warn(`⚠️ No wallet_bonuses/current_settings document found`);
                    }
                    
                    // Per-user override
                    if (userData.walletBonusPercentage !== undefined) {
                        bonusPercentage = userData.walletBonusPercentage;
                        logger.info(`📊 Using per-user bonus percentage: ${bonusPercentage}%`);
                    }
                    
                    bonusApplied = amount * (bonusPercentage / 100);
                    const totalToAdd = amount + bonusApplied;
                    
                    logger.info(`💰 Bonus calculation: amount=${amount}, bonusPercentage=${bonusPercentage}%, bonusApplied=${bonusApplied}, totalToAdd=${totalToAdd}`);
                    
                    await userRef.update({
                        walletBalance: FieldValue.increment(totalToAdd),
                        lastWalletUpdate: now
                    });
                    
                    // --- Set hasMadeFirstTopUp to true if this is the first deposit ---
                    if (!userData.hasMadeFirstTopUp) {
                        await userRef.update({ hasMadeFirstTopUp: true });
                        logger.info(`🎉 Set hasMadeFirstTopUp to true for user ${userDoc.id} (${userCollection})`);
                    }
                    
                    // Get the appropriate name field based on user collection
                    let displayName = 'unknown';
                    if (userCollection === 'drivers') {
                        displayName = userData.username || userData.displayName || userData.name || userData.shopName || userData.organizationName || userData.orgName || userData.email || userData.phoneNumber || userDoc.id || 'unknown';
                    } else if (userCollection === 'retailers') {
                        displayName = userData.shopName || userData.displayName || userData.name || userData.username || userData.organizationName || userData.orgName || userData.email || userData.phoneNumber || userDoc.id || 'unknown';
                    } else if (userCollection === 'organisations') {
                        displayName = userData.organizationName || userData.orgName || userData.displayName || userData.name || userData.username || userData.shopName || userData.email || userData.phoneNumber || userDoc.id || 'unknown';
                    }
                    
                    // Log the user data for debugging if displayName is still 'unknown'
                    if (displayName === 'unknown') {
                        logger.warn(`⚠️ Could not find display name for user ${userDoc.id} in collection ${userCollection}. User data:`, {
                            userData: userData,
                            availableFields: Object.keys(userData || {})
                        });
                    } else {
                        logger.info(`✅ Found display name for user ${userDoc.id}: ${displayName}`);
                    }
                    
                    walletUpdateResult = {
                        userId: userDoc.id,
                        userCollection: userCollection,
                        accountNumber: BillRefNumber,
                        incrementedBy: totalToAdd,
                        bonusApplied,
                        bonusPercentage,
                        organizationName: displayName
                    };
                    logger.info(`✅ Updated walletBalance for user ${userDoc.id} (${userCollection}, accountNumber: ${BillRefNumber}) by Ksh ${totalToAdd} (bonus: ${bonusApplied})`);
                }
            } else {
                logger.warn(`⚠️ No user found with accountNumber: ${BillRefNumber} for wallet update.`);
            }
        } else {
            // If phone, remove non-digits for topupNumber
            topupNumber = BillRefNumber.replace(/\D/g, '');
        }

        // Store in appropriate collection based on BillRefNumber type
        if (!isPhone) {
            // Account number (wallet top-up): store in bulk_transactions
            const bulkTransactionId = `WALLET_TOPUP_${Date.now()}_${transactionId}`;
            await bulkTransactionsCollection.doc(bulkTransactionId).set({
                transactionID: bulkTransactionId,
                type: 'WALLET_TOPUP',
                userId: walletUpdateResult?.userId || 'unknown',
                organizationName: walletUpdateResult?.organizationName || 'unknown',
                totalAmount: amount,
                requestCount: 1, // Single wallet top-up
                status: 'COMPLETED', // Wallet top-up is immediately completed
                jobId: null, // No job for wallet top-up
                createdAt: now,
                lastUpdated: now,
                walletUpdateResult: walletUpdateResult || null,
                walletBonusApplied: bonusApplied,
                walletBonusPercentage: bonusPercentage,
                payerMsisdn: mpesaNumber,
                payerName: customerName,
                billRefNumber: BillRefNumber,
                mpesaRawCallback: callbackData,
                originalTransactionId: transactionId // Keep reference to original M-Pesa transaction
            });
            logger.info(`✅ Recorded wallet top-up transaction ${transactionId} in 'bulk_transactions' collection as ${bulkTransactionId}.`);
        } else {
            // Phone number (airtime top-up): store in transactions collection
            await transactionsCollection.doc(transactionId).set({
                transactionID: transactionId,
                type: 'C2B_PAYMENT', // Explicitly mark type
                transactionTime: TransTime,
                amountReceived: amount, // Original amount paid by customer
                payerMsisdn: mpesaNumber,
                payerName: customerName,
                billRefNumber: BillRefNumber,
                mpesaRawCallback: callbackData,
                status: 'RECEIVED_PENDING_FULFILLMENT', // Set status to pending fulfillment
                fulfillmentStatus: 'PENDING', // Initial fulfillment status
                createdAt: now,
                lastUpdated: now,
                walletUpdateResult: walletUpdateResult || null,
                walletBonusApplied: bonusApplied,
                walletBonusPercentage: bonusPercentage
            });
            logger.info(`✅ Recorded airtime transaction ${transactionId} in 'transactions' collection.`);
        }

        // --- 2. Trigger the unified airtime fulfillment process only if phone number ---
        if (isPhone) {
            const fulfillmentResult = await processAirtimeFulfillment({
                transactionId: transactionId,
                originalAmountPaid: amount,
                payerMsisdn: mpesaNumber,
                payerName: customerName,
                topupNumber: topupNumber,
                sourceCallbackData: callbackData,
                requestType: 'C2B',
                // relatedSaleId is null here as C2B creates its own sale doc
                driverUsername: driverUsername, // Pass driver username if present
                driverId: driverId // Pass driver ID if present
            });
            logger.info(`C2B Confirmation for TransID ${transactionId} completed. Fulfillment Result:`, fulfillmentResult);
        }

        res.json({ "ResultCode": 0, "ResultDesc": "C2B Confirmation and Processing Complete." });

    } catch (error) {
        logger.error(`❌ CRITICAL ERROR in C2B Confirmation for TransID ${transactionId}:`, {
            message: error.message,
            stack: error.stack,
            callbackData: callbackData,
        });

        if (transactionId) {
            try {
                // Use set with merge instead of update to handle cases where document doesn't exist
                await transactionsCollection.doc(transactionId).set({
                    transactionID: transactionId,
                    type: 'C2B_PAYMENT',
                    status: 'CRITICAL_PROCESSING_ERROR',
                    errorMessage: `Critical server error during C2B processing: ${error.message}`,
                    lastUpdated: FieldValue.serverTimestamp(),
                    createdAt: FieldValue.serverTimestamp(),
                    mpesaRawCallback: callbackData
                }, { merge: true });
            } catch (updateError) {
                logger.error(`❌ Failed to create/update transaction ${transactionId} after critical error:`, updateError.message);
            }
        }
        res.json({ "ResultCode": 0, "ResultDesc": "Internal server error during processing. Please check logs." });
    }
});

// Daraja Reversal Result Endpoint
app.post('/daraja-reversal-result', async (req, res) => {
    try {
        const result = req.body?.Result;
        logger.info('📞 Received Daraja Reversal Result Callback:', result);

        const resultCode = result?.ResultCode;
        const resultDesc = result?.ResultDesc;
        const reversalTransactionId = result?.TransactionID;

        const params = result?.ResultParameters?.ResultParameter || [];

        // Extract parameters safely
        const extractParam = (key) => params.find(p => p.Key === key)?.Value;

        const originalTransactionId = extractParam('OriginalTransactionID');
        const amount = extractParam('Amount');
        const creditParty = extractParam('CreditPartyPublicName');
        const debitParty = extractParam('DebitPartyPublicName');

        if (!originalTransactionId) {
            logger.error("❌ Missing OriginalTransactionID in reversal callback", { rawCallback: req.body });
            return res.status(400).json({ ResultCode: 0, ResultDesc: "Missing OriginalTransactionID. Logged for manual review." });
        }

        const transactionRef = transactionsCollection.doc(originalTransactionId);
        const transactionDoc = await transactionRef.get();

        if (!transactionDoc.exists) {
            logger.warn(`⚠️ Reversal result received for unknown OriginalTransactionID: ${originalTransactionId}`);
            return res.json({ ResultCode: 0, ResultDesc: "Acknowledged - Unknown transaction." });
        }

        if (resultCode === 0) {
            logger.info(`✅ Reversal for TransID ${originalTransactionId} COMPLETED successfully.`);
            await transactionRef.update({
                status: 'REVERSED_SUCCESSFULLY',
                reversalConfirmationDetails: result,
                lastUpdated: FieldValue.serverTimestamp(),
            });
            await reconciledTransactionsCollection.doc(originalTransactionId).update({
                status: 'REVERSAL_CONFIRMED',
                reversalConfirmationDetails: result,
                lastUpdated: FieldValue.serverTimestamp(),
            });
        } else {
            logger.error(`❌ Reversal for TransID ${originalTransactionId} FAILED: ${resultDesc}`);
            await transactionRef.update({
                status: 'REVERSAL_FAILED_CONFIRMATION',
                reversalConfirmationDetails: result,
                errorMessage: `Reversal failed: ${resultDesc}`,
                lastUpdated: FieldValue.serverTimestamp(),
            });
            await failedReconciliationsCollection.doc(originalTransactionId).set({
                transactionId: originalTransactionId,
                reversalConfirmationDetails: result,
                reason: resultDesc,
                createdAt: FieldValue.serverTimestamp(),
            }, { merge: true });
        }

        res.json({ ResultCode: 0, ResultDesc: "Reversal result processed successfully." });

    } catch (error) {
        logger.error("❌ Error processing Daraja reversal callback", {
            message: error.message,
            stack: error.stack,
            rawBody: req.body,
        });
        res.status(500).json({ ResultCode: 0, ResultDesc: "Server error during reversal processing." });
    }
});


// --- Daraja Reversal Queue Timeout Endpoint ---
app.post('/daraja-reversal-timeout', async (req, res) => {
    const timeoutData = req.body;
    const now = new Date();
    const { OriginatorConversationID, ConversationID, ResultCode, ResultDesc } = timeoutData;

    logger.warn('⚠️ Received Daraja Reversal Queue Timeout Callback:', {
        OriginatorConversationID: OriginatorConversationID,
        ConversationID: ConversationID,
        ResultCode: ResultCode,
        ResultDesc: ResultDesc,
        fullCallback: timeoutData
    });

    try {
        let transactionIdToUpdate = OriginatorConversationID;

        const originalTransactionRef = transactionsCollection.doc(transactionIdToUpdate);
        const originalTransactionDoc = await originalTransactionRef.get();

        if (originalTransactionDoc.exists) {
            logger.info(`Updating transaction ${transactionIdToUpdate} with reversal timeout status.`);
            await originalTransactionRef.update({
                status: 'REVERSAL_TIMED_OUT', // New status for timed-out reversals
                reversalTimeoutDetails: timeoutData,
                lastUpdated: FieldValue.serverTimestamp(),
            });
        } else {
            logger.warn(`⚠️ Reversal Timeout received for unknown or unlinked TransID/OriginatorConversationID: ${transactionIdToUpdate}`);
        }

        // Always record the timeout in a dedicated collection for auditing/manual review
        await reversalTimeoutsCollection.add({
            transactionId: transactionIdToUpdate, // The ID you're tracking internally
            originatorConversationId: OriginatorConversationID,
            conversationId: ConversationID,
            resultCode: ResultCode,
            resultDesc: ResultDesc,
            fullCallbackData: timeoutData,
            createdAt: FieldValue.serverTimestamp(),
        });

        logger.info(`✅ Daraja Reversal Queue Timeout processed for ${transactionIdToUpdate}.`);
        res.json({ "ResultCode": 0, "ResultDesc": "Daraja Reversal Queue Timeout Received and Processed." });

    } catch (error) {
        logger.error(`❌ CRITICAL ERROR processing Daraja Reversal Queue Timeout for ${OriginatorConversationID || 'N/A'}:`, {
            message: error.message,
            stack: error.stack,
            timeoutData: timeoutData
        });
        // Still send a success response to Daraja to avoid repeated callbacks
        res.json({ "ResultCode": 0, "ResultDesc": "Internal server error during Queue Timeout processing." });
    }
});
        
// --- NEW AIRTIME BONUS API ENDPOINTS ---
const CURRENT_BONUS_DOC_PATH = 'airtime_bonuses/current_settings'; // Document path for current settings
// BONUS_HISTORY_COLLECTION is already defined at the top as a const

// GET current bonus percentages
app.get('/api/airtime-bonuses/current', async (req, res) => {
    try {
        const docRef = firestore.collection('airtime_bonuses').doc('current_settings');
        const docSnap = await docRef.get();

        if (docSnap.exists) {
            res.json(docSnap.data());
        } else {
            // If document doesn't exist, initialize it with default values
            logger.info('Initializing airtime_bonuses/current_settings with default values.');
            await docRef.set({ safaricomPercentage: 0, africastalkingPercentage: 0, lastUpdated: FieldValue.serverTimestamp() });
            res.json({ safaricomPercentage: 0, africastalkingPercentage: 0 });
        }
    } catch (error) {
        logger.error('Error fetching current airtime bonuses:', { message: error.message, stack: error.stack });
        res.status(500).json({ error: 'Failed to fetch current airtime bonuses.' });
    }
});

app.post('/api/trigger-daraja-reversal', async (req, res) =>{
    // Removed shortCode parameter as it's fetched from env
    const {transactionId, mpesaNumber, amount} = req.body;
    logger.info(`🔄 Attempting Daraja reversal for TransID: ${transactionId}, Amount: ${amount}`);
    try {
        const accessToken = await getDarajaAccessToken(); // Function to get Daraja access token

        if (!accessToken) {
            throw new Error("Failed to get Daraja access token for reversal.");
        }

        const url = process.env.MPESA_REVERSAL_URL; 
        const shortCode = process.env.MPESA_SHORTCODE; 
        const initiator = process.env.MPESA_INITIATOR_NAME; 
        const password=process.env.MPESA_SECURITY_PASSWORD;
        const securityCredential = generateSecurityCredential(password);  
        

        if (!url || !shortCode || !initiator || !securityCredential) {
            throw new Error("Missing Daraja reversal environment variables.");
        }

        const payload = {
            Initiator: initiator,
            SecurityCredential: securityCredential, // Use your actual security credential
            CommandID: "TransactionReversal",
            TransactionID: transactionId, // The M-Pesa TransID to be reversed
            Amount: amount, // The amount to reverse
            ReceiverParty: shortCode, 
            RecieverIdentifierType: "11",
            QueueTimeOutURL: process.env.MPESA_REVERSAL_QUEUE_TIMEOUT_URL, // URL for timeout callbacks
            ResultURL: process.env.MPESA_REVERSAL_RESULT_URL, // URL for result callbacks
            Remarks: `Airtime dispatch failed for ${transactionId}`,
            Occasion: "Failed Airtime Topup"
        };

        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`
        };

        const response = await axios.post(url, payload, { headers });

        logger.info(`✅ Daraja Reversal API response for TransID ${transactionId}:`, response.data);
        if (response.data && response.data.ResponseCode === '0') {
            return {
                success: true,
                message: "Reversal request accepted by Daraja.",
                data: response.data,
                // You might store the ConversationID for tracking if provided
                conversationId: response.data.ConversationID || null,
            };
        } else {
            const errorMessage = response.data ?
                `Daraja reversal request failed: ${response.data.ResponseDescription || 'Unknown error'}` :
                'Daraja reversal request failed with no response data.';
            logger.error(`❌ Daraja reversal request not accepted for TransID ${transactionId}: ${errorMessage}`);
            return {
                success: false,
                message: errorMessage,
                data: response.data,
            };
        }

    } catch (error) {
        const errorData = error.response ? error.response.data : error.message;
        logger.error(`❌ Exception during Daraja reversal for TransID ${transactionId}:`, {
            error: errorData,
            stack: error.stack
        });
        return {
            success: false,
            message: `Exception in reversal process: ${errorData.errorMessage || error.message}`,
            error: errorData
        };
    }
})

// POST to update bonus percentages and log history
app.post('/api/airtime-bonuses/update', async (req, res) => {
    const { safaricomPercentage, africastalkingPercentage, actor } = req.body; // 'actor' could be the authenticated user's ID/email

    if (typeof safaricomPercentage !== 'number' || typeof africastalkingPercentage !== 'number' || safaricomPercentage < 0 || africastalkingPercentage < 0) {
        logger.warn('Invalid bonus percentages received for update.', { safaricomPercentage, africastalkingPercentage });
        return res.status(400).json({ error: 'Invalid bonus percentages. Must be non-negative numbers.' });
    }

    try {
        const currentSettingsDocRef = firestore.collection('airtime_bonuses').doc('current_settings');
        const currentSettingsSnap = await currentSettingsDocRef.get();
        const oldSettings = currentSettingsSnap.exists ? currentSettingsSnap.data() : { safaricomPercentage: 0, africastalkingPercentage: 0 };

        const batch = firestore.batch();

        // Update the current settings document
        batch.set(currentSettingsDocRef, {
            safaricomPercentage: safaricomPercentage,
            africastalkingPercentage: africastalkingPercentage,
            lastUpdated: FieldValue.serverTimestamp(), // Use server timestamp
        }, { merge: true }); // Use merge to avoid overwriting other fields if they exist

        // Add history entries only if values have changed
        if (safaricomPercentage !== oldSettings.safaricomPercentage) {
            batch.set(bonusHistoryCollection.doc(), { // Use the initialized collection variable
                company: 'Safaricom',
                oldPercentage: oldSettings.safaricomPercentage || 0,
                newPercentage: safaricomPercentage,
                timestamp: FieldValue.serverTimestamp(),
                actor: actor || 'system', // Default to 'system' if actor is not provided
            });
            logger.info(`Safaricom bonus changed from ${oldSettings.safaricomPercentage} to ${safaricomPercentage} by ${actor || 'system'}.`);
        }
        if (africastalkingPercentage !== oldSettings.africastalkingPercentage) {
            batch.set(bonusHistoryCollection.doc(), { // Use the initialized collection variable
                company: 'AfricasTalking',
                oldPercentage: oldSettings.africastalkingPercentage || 0,
                newPercentage: africastalkingPercentage,
                timestamp: FieldValue.serverTimestamp(),
                actor: actor || 'system', // Default to 'system' if actor is not provided
            });
            logger.info(`AfricasTalking bonus changed from ${oldSettings.africastalkingPercentage} to ${africastalkingPercentage} by ${actor || 'system'}.`);
        }

        await batch.commit();
        res.json({ success: true, message: 'Bonus percentages updated successfully.' });

    } catch (error) {
        logger.error('Error updating airtime bonuses:', { message: error.message, stack: error.stack }); // Completed the error message
        res.status(500).json({ error: 'Failed to update airtime bonuses.' });
    }
});

// --- Endpoint to receive fulfillment requests from STK Server ---
app.post('/api/fulfill-airtime', async (req, res) => {
    const fulfillmentRequest = req.body;
    const now = FieldValue.serverTimestamp();

    logger.info('📦 Received fulfillment request from STK Server:', fulfillmentRequest);
    const {
        checkoutRequestID,
        merchantRequestID,
        mpesaReceiptNumber,
        amountPaid,
        recipientNumber,
        customerPhoneNumber,
        carrier
    } = fulfillmentRequest;
    
    if (!checkoutRequestID || !amountPaid || !recipientNumber || !customerPhoneNumber || !carrier) {
        logger.error('❌ Missing required fields in fulfillment request:', fulfillmentRequest);
        await errorsCollection.add({
            type: 'OFFLINE_FULFILLMENT_REQUEST_ERROR',
            error: 'Missing required fields in request body.',
            requestBody: fulfillmentRequest,
            createdAt: now,
        });
        return res.status(400).json({ success: false, message: 'Missing required fulfillment details.' });
    }
    // Respond with an error to the STK server
    return res.status(500).json({ success: false, message: 'Internal server error during fulfillment request processing.' });
});

//Keep live tracker
app.get("/ping", (req, res) => {
  res.status(200).send("pong");
});

// --- DRIVER ENDPOINTS ---

// 1. Register Driver
app.post('/api/register-driver', async (req, res) => {
  const { username, email, password, contactPerson, phoneNumber, idNumber } = req.body;
  
  if (!username || !email || !password || !contactPerson || !phoneNumber || !idNumber) {
    return res.status(400).json({ 
      success: false, 
      message: 'All fields are required' 
    });
  }

  try {
    // Check if driver already exists
    const existingDriver = await firestore.collection('drivers')
      .where('email', '==', email)
      .limit(1)
      .get();

    if (!existingDriver.empty) {
      return res.status(400).json({ 
        success: false, 
        message: 'Driver with this email already exists' 
      });
    }

    // Generate account number
    const accountNumber = `DaimaPay#${username.toLowerCase().replace(/\s+/g, '')}`;
    
    // Create driver document
    const driverRef = await firestore.collection('drivers').add({
      username,
      email,
      password: crypto.createHash('sha256').update(password).digest('hex'), // Hash password
      contactPerson,
      phoneNumber,
      idNumber,
      walletBalance: 0,
      commissionEarned: 0,
      accountNumber,
      createdAt: FieldValue.serverTimestamp(),
      userType: 'driver',
      totalTransactions: 0,
      hasMadeFirstTopUp: false,
      isSuspended: false,
      suspendedAt: null,
      failedLoginAttempts: 0,
      lastFailedAttempt: null
    });

    res.json({
      success: true,
      driverId: driverRef.id,
      message: 'Driver registered successfully'
    });
  } catch (error) {
    logger.error('Driver registration error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to register driver' 
    });
  }
});

// 2. Get Driver Wallet
app.get('/api/driver-wallet/:driverId', async (req, res) => {
  const { driverId } = req.params;

  try {
    const driverDoc = await firestore.collection('drivers').doc(driverId).get();
    
    if (!driverDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Driver not found' 
      });
    }

    const driverData = driverDoc.data();
    
    res.json({
      success: true,
      walletBalance: driverData.walletBalance || 0,
      commissionEarned: driverData.commissionEarned || 0,
      hasMadeFirstTopUp: driverData.hasMadeFirstTopUp || false
    });
  } catch (error) {
    logger.error('Get driver wallet error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to get driver wallet' 
    });
  }
});

// 3. Top Up Wallet (STK Push)
app.post('/api/driver-wallet/topup', async (req, res) => {
  const { driverId, amount, phoneNumber } = req.body;

  if (!driverId || !amount || !phoneNumber) {
    return res.status(400).json({ 
      success: false, 
      message: 'Missing required fields' 
    });
  }

  try {
    // Verify driver exists
    const driverDoc = await firestore.collection('drivers').doc(driverId).get();
    if (!driverDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Driver not found' 
      });
    }

    const driverData = driverDoc.data();
    const accountNumber = driverData.accountNumber;

    // Initiate STK Push using existing logic
    const timestamp = generateTimestamp();
    const password = generatePassword(SHORTCODE, PASSKEY, timestamp);
    const token = await getAccessToken();

    const payload = {
      BusinessShortCode: SHORTCODE,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: Number(amount),
      PartyA: phoneNumber,
      PartyB: SHORTCODE,
      PhoneNumber: phoneNumber,
      CallBackURL: STK_CALLBACK_URL,
      AccountReference: accountNumber,
      TransactionDesc: 'Driver Wallet Top Up'
    };

    const stkRes = await axios.post(
      'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
      payload,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );

    res.json({
      success: true,
      message: 'STK Push initiated for wallet top-up',
      merchantRequestID: stkRes.data.MerchantRequestID,
      checkoutRequestID: stkRes.data.CheckoutRequestID,
      walletBalance: driverData.walletBalance || 0
    });
  } catch (error) {
    logger.error('Driver wallet top-up error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to initiate wallet top-up' 
    });
  }
});

// 4. Get Driver Commission

// 4. Get Driver Commission
app.get('/api/driver-commission/:driverId', async (req, res) => {
  const { driverId } = req.params;

  try {
    const driverDoc = await firestore.collection('drivers').doc(driverId).get();
    
    if (!driverDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Driver not found' 
      });
    }

    const driverData = driverDoc.data();
    
    res.json({
      success: true,
      commissionEarned: driverData.commissionEarned || 0
    });
  } catch (error) {
    logger.error('Get driver commission error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to get driver commission' 
    });
  }
});

// 5. Withdraw Commission (B2C to driver)
app.post('/api/driver-commission/withdraw', async (req, res) => {
  const { driverId, amount, phoneNumber } = req.body;

  logger.info(`[WITHDRAWAL REQUEST] Received request for driverId: ${driverId}, phone: ${phoneNumber}, amount: ${amount}`);

  if (!driverId || !phoneNumber || typeof amount !== 'number' || amount <= 0) {
    logger.warn(`[WITHDRAWAL ERROR] Bad request - missing or invalid fields. driverId: ${driverId}, phone: ${phoneNumber}, amount: ${amount}`);
    return res.status(400).json({ 
      success: false, 
      message: 'Missing or invalid fields: driverId, phone, and a positive amount are required.' 
    });
  }

  // Normalize phone number
  const normalizePhoneNumber = (phone) => {
    const cleaned = phone.replace(/\D/g, '');
    if (cleaned.startsWith('254') && cleaned.length === 12) return `+${cleaned}`;
    if (cleaned.startsWith('0') && cleaned.length === 10) return `+254${cleaned.slice(1)}`;
    if (cleaned.startsWith('7') && cleaned.length === 9) return `+254${cleaned}`;
    logger.warn(`[PHONE NORMALIZATION] Invalid phone number format: ${phone}`);
    return null;
  };

  const normalizedPhone = normalizePhoneNumber(phoneNumber);
  if (!normalizedPhone) {
    logger.warn(`[WITHDRAWAL ERROR] Invalid phone number format provided: ${phoneNumber}`);
    return res.status(400).json({ 
      success: false, 
      message: 'Invalid phone number format. Please use a valid Kenyan Safaricom number.' 
    });
  }

  // Throttle to prevent duplicate requests
  const throttleKey = `${driverId}:${normalizedPhone}`;
  const THROTTLE_TIMEOUT_MS = 180_000; // 3 minutes
  const activeWithdrawals = new Map();

  if (activeWithdrawals.has(throttleKey)) {
    logger.warn(`[WITHDRAWAL THROTTLE] Duplicate request detected for ${throttleKey}.`);
    return res.status(429).json({ 
      success: false, 
      message: 'A withdrawal request for this driver and phone number is already being processed. Please try again shortly.' 
    });
  }

  // Acknowledge the request early to prevent client timeouts while processing
  res.status(200).json({ 
    success: true, 
    message: 'Withdrawal request received and processing initiated.' 
  });
  logger.info(`[WITHDRAWAL ACK] Acknowledged request for ${driverId}. Proceeding with background processing.`);

  try {
    activeWithdrawals.set(throttleKey, true);
    setTimeout(() => {
      activeWithdrawals.delete(throttleKey);
      logger.info(`[WITHDRAWAL THROTTLE] Throttle for ${throttleKey} expired and removed.`);
    }, THROTTLE_TIMEOUT_MS);

    // Verify driver exists and has sufficient commission
    const driverRef = firestore.collection('drivers').doc(driverId);
    const driverDoc = await driverRef.get();
    
    if (!driverDoc.exists) {
      logger.warn(`[WITHDRAWAL ERROR] Driver not found: ${driverId}. Aborting withdrawal.`);
      activeWithdrawals.delete(throttleKey);
      return;
    }

    const driverData = driverDoc.data();
    const availableCommission = driverData.commissionEarned || 0;
    
    if (availableCommission < amount) {
      logger.warn(`[WITHDRAWAL ERROR] Insufficient commission for driver ${driverId}. Available: ${availableCommission}, Requested: ${amount}.`);
      activeWithdrawals.delete(throttleKey);
      return;
    }

    // Get M-Pesa access token
    const getAccessToken = async () => {
      const consumerKey = process.env.WITHDRAWAL_CONSUMER_KEY;
      const consumerSecret = process.env.WITHDRAWAL_CONSUMER_SECRET;

      if (!consumerKey || !consumerSecret) {
        logger.error('[MPESA AUTH] WITHDRAWAL_CONSUMER_KEY or WITHDRAWAL_CONSUMER_SECRET not set in .env');
        throw new Error('M-Pesa API credentials are not configured.');
      }

      const auth = Buffer.from(`${consumerKey}:${consumerSecret}`).toString('base64');

      try {
        const response = await axios.get('https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials', {
          headers: { Authorization: `Basic ${auth}` }
        });

        if (!response.data.access_token) {
          throw new Error('Access token not found in M-Pesa authentication response.');
        }
        
        logger.info('[MPESA AUTH] Successfully retrieved M-Pesa access token.');
        return response.data.access_token;
      } catch (err) {
        logger.error(`[MPESA AUTH FATAL] Error during access token retrieval: ${err.message}`);
        throw err;
      }
    };

    // Encrypt password using certificate
    const encryptPassword = async (password) => {
      try {
        const certPath = process.env.WITHDRAWAL_MPESA_CERT_PATH;
        if (!certPath) {
          logger.error('[CERT ENCRYPTION] WITHDRAWAL_MPESA_CERT_PATH is not set in .env');
          throw new Error('WITHDRAWAL_MPESA_CERT_PATH is not set in environment variables.');
        }

        const fs = require('fs');
        const forge = require('node-forge');
        const path = require('path');

        const absolutePath = path.resolve(certPath);
        const certBuffer = fs.readFileSync(absolutePath, 'utf8');

        const cert = forge.pki.certificateFromPem(certBuffer);
        if (!cert || !cert.publicKey) {
          throw new Error('Invalid M-Pesa certificate or missing public key.');
        }

        const encrypted = cert.publicKey.encrypt(password, 'RSAES-PKCS1-V1_5');
        logger.info('[CERT ENCRYPTION] Password encrypted successfully.');
        return Buffer.from(encrypted).toString('base64');
      } catch (err) {
        logger.error(`[CERT ENCRYPTION FATAL] Error during password encryption: ${err.message}`);
        throw err;
      }
    };

    const token = await getAccessToken();
    const mpesaInitiatorPassword = process.env.WITHDRAWAL_INITIATOR_PASSWORD;
    if (!mpesaInitiatorPassword) {
      logger.error('[WITHDRAWAL ERROR] WITHDRAWAL_INITIATOR_PASSWORD is not set in .env.');
      activeWithdrawals.delete(throttleKey);
      return;
    }
    
    const password = await encryptPassword(mpesaInitiatorPassword);
    const { v4: uuidv4 } = require('uuid');
    const transactionId = uuidv4();

    const shortcode = process.env.WITHDRAWAL_SHORTCODE;
    const initiatorName = process.env.WITHDRAWAL_INITIATOR_NAME;
    const baseUrl = process.env.WITHDRAWAL_BASE_URL;

    if (!shortcode || !initiatorName || !baseUrl) {
      logger.error('[WITHDRAWAL ERROR] Missing M-Pesa configuration in .env (WITHDRAWAL_SHORTCODE, WITHDRAWAL_INITIATOR_NAME, WITHDRAWAL_BASE_URL).');
      activeWithdrawals.delete(throttleKey);
      return;
    }

    const payload = {
      OriginatorConversationID: transactionId,
      InitiatorName: initiatorName,
      SecurityCredential: password,
      CommandID: 'BusinessPayment', // B2C transaction
      Amount: amount,
      PartyA: shortcode,
      PartyB: normalizedPhone.replace('+', ''), // M-Pesa expects phone without '+'
      Remarks: 'Commission Withdrawal',
      QueueTimeOutURL: `${baseUrl}/withdraw/timeout?driverId=${driverId}&transactionId=${transactionId}`,
      ResultURL: `${baseUrl}/withdraw/result?driverId=${driverId}&transactionId=${transactionId}`,
      Occasion: 'Commission withdrawal',
    };

    // Store transaction in driver_transactions collection
    await firestore.collection('driver_transactions').add({
      driverId,
      type: 'COMMISSION_WITHDRAWAL',
      amount: -amount,
      phoneNumber: normalizedPhone,
      status: 'PENDING',
      transactionId: transactionId,
      mpesa_request_payload: payload,
      createdAt: FieldValue.serverTimestamp()
    });
    logger.info(`[WITHDRAWAL DB] Transaction ${transactionId} created in driver_transactions as pending.`);

    logger.info(`[WITHDRAWAL INIT] Initiating M-Pesa B2C for driver ${driverId} (${normalizedPhone}) for KES ${amount}. Transaction ID: ${transactionId}`);

    const mpesaResponse = await axios.post(
      'https://api.safaricom.co.ke/mpesa/b2c/v1/paymentrequest',
      payload,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        }
      }
    );

    const mpesaResponseData = mpesaResponse.data;

    if (!mpesaResponse.ok) {
      logger.error(`[MPESA API ERROR] M-Pesa B2C API call failed for transaction ${transactionId}: ${mpesaResponse.status} - ${JSON.stringify(mpesaResponseData)}`);

      // Update transaction status in driver_transactions collection
      const transactionQuery = await firestore.collection('driver_transactions')
        .where('transactionId', '==', transactionId)
        .limit(1)
        .get();
      
      if (!transactionQuery.empty) {
        const transactionDoc = transactionQuery.docs[0];
        await transactionDoc.ref.update({
          status: 'FAILED_API_ERROR',
          completed_at: FieldValue.serverTimestamp(),
          mpesa_response_error: mpesaResponseData,
        });
      }
      
      activeWithdrawals.delete(throttleKey);
      return;
    }

    logger.info(`[MPESA API SUCCESS] M-Pesa B2C API call successful for transaction ${transactionId}. Response: ${JSON.stringify(mpesaResponseData)}`);

    // Update transaction with M-Pesa response data
    const transactionQuery = await firestore.collection('driver_transactions')
      .where('transactionId', '==', transactionId)
      .limit(1)
      .get();
    
    if (!transactionQuery.empty) {
      const transactionDoc = transactionQuery.docs[0];
      await transactionDoc.ref.update({
        mpesa_response: mpesaResponseData,
        lastUpdated: FieldValue.serverTimestamp()
      });
    }

  } catch (err) {
    logger.error(`[WITHDRAWAL FATAL] Uncaught error during withdrawal initiation for driver ${driverId}: ${err.message}`, err.stack);
    activeWithdrawals.delete(throttleKey);
  }
});

// 6. Commission to Wallet
app.post('/api/driver-commission/topup-wallet', async (req, res) => {
  const { driverId, amount } = req.body;

  if (!driverId || !amount) {
    return res.status(400).json({ 
      success: false, 
      message: 'Missing required fields' 
    });
  }

  try {
    // Transfer commission to wallet
    const driverRef = firestore.collection('drivers').doc(driverId);
    
    await firestore.runTransaction(async (tx) => {
      const driverDoc = await tx.get(driverRef);
      if (!driverDoc.exists) {
        throw new Error('Driver not found');
      }

      const driverData = driverDoc.data();
      const currentCommission = driverData.commissionEarned || 0;
      
      if (currentCommission < amount) {
        throw new Error('Insufficient commission balance');
      }

      // Transfer commission to wallet
      tx.update(driverRef, {
        commissionEarned: FieldValue.increment(-amount),
        walletBalance: FieldValue.increment(amount),
        lastWalletUpdate: FieldValue.serverTimestamp()
      });

      // Log transaction in driver_transactions collection
      await firestore.collection('driver_transactions').add({
        driverId,
        type: 'COMMISSION_TO_WALLET',
        amount: amount,
        status: 'COMPLETED',
        createdAt: FieldValue.serverTimestamp()
      });
    });

    const updatedDriver = await driverRef.get();
    const updatedData = updatedDriver.data();

    res.json({
      success: true,
      message: 'Commission transferred to wallet successfully',
      commissionEarned: updatedData.commissionEarned,
      walletBalance: updatedData.walletBalance
    });
  } catch (error) {
    logger.error('Commission to wallet error:', error);
    res.status(500).json({ 
      success: false, 
      message: error.message || 'Failed to transfer commission to wallet' 
    });
  }
});


// 7. Sell Airtime (Wallet or Customer)
app.post('/api/driver-airtime/sell', async (req, res) => {
  const { driverId, amount, recipientPhone, paymentMethod, customerPhone } = req.body;

  if (!driverId || !amount || !recipientPhone || !paymentMethod) {
    return res.status(400).json({ 
      success: false, 
      message: 'Missing required fields' 
    });
  }

  if (amount < 5){
    return res.status(400).json({ 
      success: false, 
      message: 'Minimum airtime amount is KES 5' 
    });
  }

  if (paymentMethod === 'customer' && !customerPhone) {
    return res.status(400).json({ 
      success: false, 
      message: 'Customer phone number required for customer payment method' 
    });
  }

  try {
  // Verify driver exists
    const driverRef = firestore.collection('drivers').doc(driverId);
    const driverDoc = await driverRef.get();

    if (!driverDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Driver not found' 
      });
    }

    const driverData = driverDoc.data();
    let transactionId = `DRIVER_AIRTIME_${Date.now()}_${driverId}`;

    if (paymentMethod === 'wallet') {
      // Check wallet balance
      const currentBalance = driverData.walletBalance || 0;
      if (currentBalance < amount) {
        return res.status(400).json({ 
          success: false, 
          message: 'Insufficient wallet balance' 
        });
      }

      // Deduct from wallet and send airtime
      await firestore.runTransaction(async (tx) => {
        const updatedDriverDoc = await tx.get(driverRef);
        const updatedDriverData = updatedDriverDoc.data();

        if (updatedDriverData.walletBalance < amount) {
          throw new Error('Insufficient wallet balance');
        }

      // Deduct from wallet
        tx.update(driverRef, {
          walletBalance: FieldValue.increment(-amount),
          totalTransactions: FieldValue.increment(1),
          lastWalletUpdate: FieldValue.serverTimestamp()
        });
      });

      // Send airtime
    const carrier = detectCarrier(recipientPhone);
      let airtimeResult;

      logger.info(`📱 Sending airtime via driver wallet - driverId: ${driverId}, recipientPhone: ${recipientPhone}, amount: ${amount}, carrier: ${carrier}`);

      if (carrier === 'Safaricom') {
        airtimeResult = await sendSafaricomAirtime(recipientPhone, amount);
      } else {
        airtimeResult = await sendAfricasTalkingAirtime(recipientPhone, amount, carrier);
      }

      logger.info(`📱 Airtime send result - driverId: ${driverId}, status: ${airtimeResult.status}, message: ${airtimeResult.message}`);

      if (airtimeResult.status === 'SUCCESS') {
        // float balance update
        const carrierLogicalName = carrier === 'Safaricom' ? 'Safaricom' : 'AfricasTalking';
        await updateCarrierFloatBalance(carrierLogicalName, -amount);

        //deduct from wallet

        // --- START OF COMMISSION LOGIC FOR WALLET SALES ---
        let commissionPercentage = 0;
        const commissionSettingsDoc = await firestore.collection('airtime_bonuses').doc('current_settings').get();

        if (commissionSettingsDoc.exists) {
            const settings = commissionSettingsDoc.data();
            if (carrier === 'Safaricom') {
              commissionPercentage = settings.safaricomPercentage || 0;
            } else {
              commissionPercentage = settings.africastalkingPercentage || 0;
            }
        } else {
          logger.warn(`⚠️ airtime_bonuses/current_settings document not found. Commission will be 0.`);
        }

        const commissionAmount = amount * (commissionPercentage / 100);

        logger.info(`💰 Driver wallet sale commission calculation - driverId: ${driverId}, amount: ${amount}, carrier: ${carrier}, commissionPercentage: ${commissionPercentage}%, commissionAmount: ${commissionAmount}`);

        if (commissionAmount > 0) {
              await driverRef.update({
                commissionEarned: FieldValue.increment(commissionAmount), // Track total commission earned
                lastCommissionUpdate: FieldValue.serverTimestamp()
            });
          logger.info(`✅ Commission awarded to driver ${driverId} for wallet sale: ${commissionAmount}`);
        }
        // --- END OF COMMISSION LOGIC FOR WALLET SALES ---

      // Log successful transaction in single_sales collection
        const saleId = `DRIVER_SALE_${Date.now()}_${driverId}`;
        await firestore.collection('single_sales').doc(driverData.username).collection('sales').doc(saleId).set({
          driverId,
          type: 'DRIVER_AIRTIME_SALE_WALLET', // Changed type for clarity
          amount: amount,
          recipientPhone,
          carrier,
          commissionEarned: commissionAmount, // Now correctly set
          commissionPercentage: commissionPercentage, // Added commission percentage
          status: 'SUCCESS',
          transactionId,
          paymentMethod: 'wallet',
          createdAt: FieldValue.serverTimestamp()
        });

        res.json({
          success: true,
          message: 'Airtime sent successfully',
          transactionId,
          commissionEarned: commissionAmount, // Now correctly set
          commissionPercentage: commissionPercentage // Now correctly set
        });
      } else {
      // Refund wallet if airtime failed
        await driverRef.update({
          walletBalance: FieldValue.increment(amount),
          totalTransactions: FieldValue.increment(-1)
        });

        res.json({
          success: false,
          message: 'Failed to send airtime',
          transactionId
       });
      }
    } else if (paymentMethod === 'customer') {
    // Initiate STK Push to customer
      const timestamp = generateTimestamp();
      const password = generatePassword(SHORTCODE, PASSKEY, timestamp);
      const token = await getAccessToken();

    // Use driverUsername as AccountReference (truncated if needed)
      const driverUsername = req.body.driverUsername || driverData.username || 'driver';
      const truncatedAccountRef = driverUsername.length > 20 ? driverUsername.substring(0, 20) : driverUsername;

      logger.info(`📝 Driver STK Push - driverUsername: ${driverUsername}, truncated: ${truncatedAccountRef}`);

      const payload = {
        BusinessShortCode: SHORTCODE,
        Password: password,
        Timestamp: timestamp,
        TransactionType: 'CustomerPayBillOnline',
        Amount: Number(amount),
        PartyA: customerPhone,
        PartyB: SHORTCODE,
        PhoneNumber: customerPhone,
        CallBackURL: STK_CALLBACK_URL,
        AccountReference: truncatedAccountRef,
        TransactionDesc: 'Driver Airtime Sale'
      };

      const stkRes = await axios.post(
        'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
        payload,
        {
        headers: {
          Authorization: `Bearer ${token}`,
         'Content-Type': 'application/json'
          }
        }
      );

      // Log pending transaction with recipient phone for C2B retrieval in single_sales collection
      const saleId = `DRIVER_SALE_${Date.now()}_${driverId}`;
      await firestore.collection('single_sales').doc(driverData.username).collection('sales').doc(saleId).set({
        driverId,
        type: 'DRIVER_AIRTIME_SALE_PENDING',
        amount: amount,
        recipientPhone,
        customerPhone,
        status: 'PENDING',
        transactionId,
        merchantRequestID: stkRes.data.MerchantRequestID,
        checkoutRequestID: stkRes.data.CheckoutRequestID,
        driverUsername: driverData.username,
        paymentMethod: 'customer',
        createdAt: FieldValue.serverTimestamp()
       });

      res.json({
         success: true,
         message: 'STK Push initiated for customer payment',
         transactionId,
         merchantRequestID: stkRes.data.MerchantRequestID,
         checkoutRequestID: stkRes.data.CheckoutRequestID
       });
     }
  } catch (error) {
    logger.error('Driver airtime sale error:', error);
    res.status(500).json({ 
       success: false, 
       message: error.message || 'Failed to process airtime sale' 
     });
   }
});

// 8.5. Check/Set Driver Commission Percentage
app.get('/api/driver-commission-check', async (req, res) => {
  try {
    const commissionDoc = await firestore.collection('wallet_bonuses').doc('drivers_comm').get();
    
    if (!commissionDoc.exists) {
      // Create the document with default 5% commission
      await firestore.collection('wallet_bonuses').doc('drivers_comm').set({
        percentage: 5,
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp()
      });
      
      logger.info('✅ Created drivers_comm document with 5% commission');
      res.json({
        success: true,
        message: 'Created drivers_comm document with 5% commission',
        percentage: 5
      });
    } else {
      const data = commissionDoc.data();
      res.json({
        success: true,
        message: 'Commission document exists',
        percentage: data.percentage || 0,
        data: data
      });
    }
  } catch (error) {
    logger.error('Driver commission check error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to check commission settings' 
    });
  }
});

// 8. Get Driver Transactions
app.get('/api/driver-transactions/:driverId', async (req, res) => {
  const { driverId } = req.params;

  try {
    // Verify driver exists
    const driverDoc = await firestore.collection('drivers').doc(driverId).get();
    if (!driverDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Driver not found' 
      });
    }

    // Get driver's transactions from driver_transactions collection
    const transactionsSnapshot = await firestore.collection('driver_transactions')
      .where('driverId', '==', driverId)
      .orderBy('createdAt', 'desc')
      .limit(50)
      .get();

    const transactions = transactionsSnapshot.docs.map(doc => {
      const data = doc.data();
      return {
        transactionId: data.transactionId || doc.id,
        type: data.type,
        amount: data.amount,
        date: data.createdAt,
        status: data.status,
        recipientPhone: data.recipientPhone,
        commissionEarned: data.commissionEarned
      };
    });

    res.json({
      success: true,
      transactions
    });
  } catch (error) {
    logger.error('Get driver transactions error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to get driver transactions' 
    });
  }
});

// 9. Get Driver Profile
app.get('/api/driver-profile/:driverId', async (req, res) => {
  const { driverId } = req.params;

  try {
    const driverDoc = await firestore.collection('drivers').doc(driverId).get();
    
    if (!driverDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Driver not found' 
      });
    }

    const driverData = driverDoc.data();
    
    res.json({
      success: true,
      profile: {
        username: driverData.username,
        email: driverData.email,
        contactPerson: driverData.contactPerson,
        phoneNumber: driverData.phoneNumber,
        idNumber: driverData.idNumber
      }
    });
  } catch (error) {
    logger.error('Get driver profile error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to get driver profile' 
    });
  }
});

// 10. Update Driver Profile
app.put('/api/driver-profile/:driverId', async (req, res) => {
  const { driverId } = req.params;
  const { username, contactPerson, phoneNumber, idNumber } = req.body;

  if (!username || !contactPerson || !phoneNumber || !idNumber) {
    return res.status(400).json({ 
      success: false, 
      message: 'All fields are required' 
    });
  }

  try {
    const driverRef = firestore.collection('drivers').doc(driverId);
    const driverDoc = await driverRef.get();
    
    if (!driverDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Driver not found' 
      });
    }

    // Update driver profile
    await driverRef.update({
      username,
      contactPerson,
      phoneNumber,
      idNumber
    });

    res.json({
      success: true,
      message: 'Driver profile updated successfully'
    });
  } catch (error) {
    logger.error('Update driver profile error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update driver profile' 
    });
  }
});

// --- END DRIVER ENDPOINTS ---

// Start the server
app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
    console.log(`Server running on port ${PORT}`);
});

app.set('trust proxy', 1);

function generateTimestamp() {
  const now = new Date();
  const yyyy = now.getFullYear();
  const MM = String(now.getMonth() + 1).padStart(2, '0');
  const dd = String(now.getDate()).padStart(2, '0');
  const HH = String(now.getHours()).padStart(2, '0');
  const mm = String(now.getMinutes()).padStart(2, '0');
  const ss = String(now.getSeconds()).padStart(2, '0');
  return `${yyyy}${MM}${dd}${HH}${mm}${ss}`;
}

// --- BULK AIRTIME ENDPOINT (REMOVED DUPLICATE) ---
// This endpoint was removed because it was processing airtime synchronously
// and only logging to bulk_airtime_logs without creating bulk_sales records.
// The queue-based endpoint below handles bulk airtime properly.
// --- BULK AIRTIME QUEUE ENDPOINTS ---
// 1. Submit a bulk airtime job

// COMMENTED OUT FOR TESTING - BULK AIRTIME ENDPOINT
// app.post('/api/bulk-airtime', async (req, res) => {
//   const { requests, totalAmount, userId } = req.body;
//  logger.info(`🔍 Incoming bulk-airtime payload: ${JSON.stringify(req.body)}`);

//   if (!Array.isArray(requests) || requests.length === 0 || !totalAmount || !userId) {
//     return res.status(400).json({ error: 'Missing required fields.' });
//   }

//   // Fetch discounts
//   let safaricomPct = 10, africastalkingPct = 2;
//   try {
//     const safDoc = await firestore.collection('airtime_bonuses').doc('current_settings').get();
//     if (safDoc.exists) {
//       const safData = safDoc.data();
//       if (safData.safaricomPercentage !== undefined) safaricomPct = Number(safData.safaricomPercentage);
//       if (safData.africastalkingPercentage !== undefined) africastalkingPct = Number(safData.africastalkingPercentage);
//     }
//   } catch (err) {
//     logger.warn('⚠️ Failed to fetch discount settings. Using defaults.');
//   }

//   // Calculate backend discounted total
//   const discountedTotal = requests.reduce((sum, r) => {
//     const telco = (r.telco || '').toLowerCase();
//     const amount = Number(r.amount || 0);

//     if (telco === 'safaricom') {
//       return sum + (amount - (amount * safaricomPct / 100));
//     } else if (['airtel', 'telkom', 'equitel', 'faiba'].includes(telco)) {
//       return sum + (amount - (amount * africastalkingPct / 100));
//     } else {
//       return sum + amount;
//     }
//   }, 0);

//   // Validate totalAmount from frontend
//   if (Math.abs(Number(totalAmount) - discountedTotal) > 0.01) {
//     logger.warn(`❌ Discount mismatch - client: ${totalAmount}, server: ${discountedTotal}`);
//     return res.status(400).json({ error: 'totalAmount does not match discounted sum of request amounts.' });
//   }

//   // Fetch organization data
//   let organizationName = 'unknown';
//   let userRef = null;
//   let userData = null;

//   try {
//     const organisationsDoc = await firestore.collection('organisations').doc(userId).get();

//     if (!organisationsDoc.exists) {
//       return res.status(400).json({ error: 'Bulk airtime is only available for organisations. User not found in organisations collection.' });
//     }

//     userData = organisationsDoc.data();
//     userRef = organisationsDoc.ref;
//     organizationName = userData.organizationName || userData.orgName || 'unknown';

//     const currentBalance = userData.walletBalance || 0;
//     if (currentBalance < discountedTotal) {
//       return res.status(400).json({ error: 'Insufficient wallet balance.' });
//     }

//     logger.info(`✅ Wallet check passed: userId=${userId}, balance=${currentBalance}, required=${discountedTotal}`);
//   } catch (err) {
//     logger.error('❌ Wallet balance check error:', err);
//     return res.status(400).json({ error: err.message || 'Failed to check wallet balance.' });
//   }

//   try {
//     // Save job
//     const jobDoc = await bulkAirtimeJobsCollection.add({
//       userId,
//       organizationName,
//       requests,
//       totalAmount: discountedTotal,
//       status: 'pending',
//       createdAt: FieldValue.serverTimestamp(),
//       updatedAt: FieldValue.serverTimestamp(),
//       results: [],
//       currentIndex: 0
//     });

//     // Save transaction
//     const bulkTransactionId = `BULK_${Date.now()}_${jobDoc.id}`;
//     await bulkTransactionsCollection.doc(bulkTransactionId).set({
//       transactionID: bulkTransactionId,
//       type: 'BULK_AIRTIME_PURCHASE',
//       userId,
//       organizationName,
//       totalAmount: discountedTotal,
//       requestCount: requests.length,
//       status: 'PENDING_PROCESSING',
//       jobId: jobDoc.id,
//       createdAt: FieldValue.serverTimestamp(),
//       lastUpdated: FieldValue.serverTimestamp(),
//       actualAmountCharged: 0,
//       successfulCount: 0,
//       failedCount: 0
//     });

//     logger.info(`✅ Bulk airtime job + transaction created. JobId: ${jobDoc.id}, Amount Charged: ${discountedTotal}`);
//     res.json({ jobId: jobDoc.id, bulkTransactionId });
//   } catch (err) {
//     logger.error('❌ Failed to create bulk airtime job or transaction:', err);
//     res.status(500).json({ error: 'Failed to create bulk airtime job.' });
//   }
// });

// 2. Poll job status/results - COMMENTED OUT FOR TESTING
// app.get('/api/bulk-airtime-status/:jobId', async (req, res) => {
//   const { jobId } = req.params;
//   try {
//     const jobDoc = await bulkAirtimeJobsCollection.doc(jobId).get();
//     if (!jobDoc.exists) {
//       return res.status(404).json({ error: 'Job not found.' });
//     }
//     res.json(jobDoc.data());
//   } catch (err) {
//     console.error('Failed to fetch bulk airtime job:', err);
//     res.status(500).json({ error: 'Failed to fetch job.' });
//   }
// });

// 3. Background worker to process jobs - COMMENTED OUT FOR TESTING
// const BULK_AIRTIME_WORKER_INTERVAL = 10000; // 10 seconds
// const BULK_AIRTIME_RECIPIENT_DELAY = 3000; // 3 seconds

// async function processBulkAirtimeJobs() {
//   try {
//     logger.info('🔄 Bulk airtime worker starting...');
//     console.log('🔍 DEBUG: Bulk worker - Firestore instance:', !!firestore);
//     console.log('🔍 DEBUG: Bulk worker - Collection reference:', !!bulkAirtimeJobsCollection);
//     
//     // Get jobs with status 'pending' or 'processing'
//     console.log('🔍 DEBUG: About to query bulkAirtimeJobsCollection...');
//     const jobsSnap = await bulkAirtimeJobsCollection
//       .where('status', 'in', ['pending', 'processing'])
//       .orderBy('createdAt')
//       .limit(2) // process up to 2 jobs at a time
//       .get();
//     console.log('🔍 DEBUG: Query completed successfully');
    
//     logger.info(`📊 Found ${jobsSnap.docs.length} bulk airtime jobs to process`);
//     for (const jobDoc of jobsSnap.docs) {
//       const job = jobDoc.data();
//       const jobId = jobDoc.id;
//       let { requests, results = [], currentIndex = 0, status, organizationName, userId, totalAmount } = job;
      
//       // Skip if already completed or processing
//       if (status === 'completed' || status === 'processing') {
//         logger.info(`⏭️ Skipping job ${jobId} - status: ${status}`);
//         continue;
//       }
      
//       // Mark job as processing immediately to prevent race conditions
//       await bulkAirtimeJobsCollection.doc(jobId).update({
//         status: 'processing',
//         updatedAt: FieldValue.serverTimestamp()
//       });
      
//       if (!Array.isArray(requests) || currentIndex >= requests.length) {
//         // Already done
//         await bulkAirtimeJobsCollection.doc(jobId).update({
//           status: 'completed',
//           updatedAt: FieldValue.serverTimestamp()
//         });
        
//         // Update bulk transaction status
//         const bulkTransactionQuery = await bulkTransactionsCollection
//           .where('jobId', '==', jobId)
//           .limit(1)
//           .get();
//         if (!bulkTransactionQuery.empty) {
//           const bulkTransactionDoc = bulkTransactionQuery.docs[0];
//           await bulkTransactionDoc.ref.update({
//             status: 'COMPLETED',
//             lastUpdated: FieldValue.serverTimestamp(),
//             actualAmountCharged: totalSuccessfulAmount,
//             successfulCount: successfulResults.length,
//             failedCount: results.length - successfulResults.length
//           });
//           logger.info(`✅ Updated bulk transaction with final amounts - actualCharged: ${totalSuccessfulAmount}, successful: ${successfulResults.length}, failed: ${results.length - successfulResults.length}`);
//         }
//         continue;
//       }
//       // Mark as processing
//       if (status !== 'processing') {
//         await bulkAirtimeJobsCollection.doc(jobId).update({
//           status: 'processing',
//           updatedAt: FieldValue.serverTimestamp()
//         });
//       }
//       // Process up to 5 recipients per run (to avoid long locks)
//       let processed = 0;
//       while (currentIndex < requests.length && processed < 5) {
//         const { phoneNumber, amount, telco, name } = requests[currentIndex];
        
//         // Check if this recipient has already been processed
//         if (results[currentIndex] && results[currentIndex].status) {
//           logger.info(`⏭️ Skipping already processed recipient ${currentIndex + 1}/${requests.length} - phone: ${phoneNumber}, status: ${results[currentIndex].status}`);
//           currentIndex++;
//           continue;
//         }
        
//         let recipientStatus = 'FAILED';
//         let message = '';
//         let dispatchResult = null;
//         try {
//           let result;
//           if (telco && telco.toLowerCase() === 'safaricom') {
//             result = await sendSafaricomAirtime(phoneNumber, amount);
//             if (result && result.status === 'SUCCESS') {
//               recipientStatus = 'SUCCESS';
//               message = 'Airtime sent via Safaricom';
//             } else {
//               // Fallback to Africa's Talking
//               result = await sendAfricasTalkingAirtime(phoneNumber, amount, telco);
//               if (result && result.status === 'SUCCESS') {
//                 recipientStatus = 'SUCCESS';
//                 message = 'Airtime sent via Africa\'s Talking fallback';
//               } else {
//                 message = result && result.message ? result.message : 'Both Safaricom and fallback failed';
//               }
//             }
//           } else {
//             result = await sendAfricasTalkingAirtime(phoneNumber, amount, telco);
//             if (result && result.status === 'SUCCESS') {
//               recipientStatus = 'SUCCESS';
//               message = 'Airtime sent via Africa\'s Talking';
//             } else {
//               message = result && result.message ? result.message : 'Africa\'s Talking failed';
//             }
//           }
//           dispatchResult = result;
//         } catch (err) {
//           message = err.message || 'Exception during airtime dispatch';
//         }
//         results[currentIndex] = { phoneNumber, amount, telco, name, status: recipientStatus, message };
        
//         // Create bulk sale record for successful airtime sends
//         if (recipientStatus === 'SUCCESS') {
//           // ✅ New: Update carrier float balance
//           const carrierLogicalName = telco === 'Safaricom' ? 'safaricomFloat' : 'africasTalkingFloat';
//           await updateCarrierFloatBalance(carrierLogicalName, -request.amount);

//           // ✅ New: Write bulk sale record to Firestore
//           const saleId = `BULK_SALE_${Date.now()}_${currentIndex}`;
//           logger.info(`🔄 Attempting to write bulk sale for org: ${organizationName}, saleId: ${saleId}, phoneNumber: ${phoneNumber}, amount: ${amount}`);
//           
//           try {
//             await bulkSalesCollection.doc(organizationName).collection('sales').doc(saleId).set({
//               saleId,
//               type: 'BULK_AIRTIME_SALE',
//               userId,
//               organizationName,
//               jobId,
//               phoneNumber,
//               amount,
//               telco,
//               recipientName: name,
//               status: 'SUCCESS',
//               message,
//               dispatchResult,
//               createdAt: FieldValue.serverTimestamp(),
//               lastUpdated: FieldValue.serverTimestamp()
//             });
//             logger.info(`✅ Successfully wrote bulk sale for org: ${organizationName}, saleId: ${saleId}, phoneNumber: ${phoneNumber}, amount: ${amount}`);
//           } catch (err) {
//             logger.error(`❌ Failed to write bulk sale for org: ${organizationName}, saleId: ${saleId}, phoneNumber: ${phoneNumber}, amount: ${amount}`, { 
//               error: err.message, 
//               stack: err.stack,
//               organizationName,
//               saleId,
//               phoneNumber,
//               amount,
//               jobId
//             });
//           }
//         } else {
//           logger.warn(`⚠️ Skipping bulk sale write for failed airtime send - phoneNumber: ${phoneNumber}, status: ${recipientStatus}, message: ${message}`);
//         }
//         
//         // Update job after each recipient
//         await bulkAirtimeJobsCollection.doc(jobId).update({
//           results,
//           currentIndex: currentIndex + 1,
//           updatedAt: FieldValue.serverTimestamp()
//         });
//         currentIndex++;
//         processed++;
//         // Wait 3 seconds before next recipient
//         if (currentIndex < requests.length) {
//           await new Promise(resolve => setTimeout(resolve, BULK_AIRTIME_RECIPIENT_DELAY));
//         }
//       }
//       // If all done, mark as completed and deduct wallet for successful sends
//       if (currentIndex >= requests.length) {
//         const successfulResults = results.filter(r => r.status === 'SUCCESS');
//         
//         // START OF FIX
//         const totalSuccessfulAmount = totalAmount; 
//         // END OF FIX
//         
//         // Check if wallet has already been deducted for this job
//         const jobData = await bulkAirtimeJobsCollection.doc(jobId).get();
//         const jobStatus = jobData.data()?.status;
//         
//         if (jobStatus === 'completed') {
//           logger.warn(`⚠️ Job ${jobId} already completed, skipping wallet deduction`);
//         } else {
//           logger.info(`💰 Deducting wallet for successful sends - jobId: ${jobId}, successfulCount: ${successfulResults.length}, totalAmount: ${totalSuccessfulAmount}`);
//           
//           try {
//             // Bulk airtime is only for organisations
//             const organisationsDoc = await firestore.collection('organisations').doc(userId).get();
//             
//             if (!organisationsDoc.exists) {
//               throw new Error('User not found in organisations collection during wallet deduction.');
//             }
//             
//             const userRef = organisationsDoc.ref;
//             
//             await firestore.runTransaction(async (tx) => {
//               const userDoc = await tx.get(userRef);
//               if (!userDoc.exists) {
//                 throw new Error('User not found during wallet deduction.');
//               }
//               const userData = userDoc.data();
//               const currentBalance = userData.walletBalance || 0;
//               
//               // Deduct only the amount for successful sends
//               tx.update(userRef, {
//                 walletBalance: FieldValue.increment(-totalSuccessfulAmount),
//                 lastWalletUpdate: FieldValue.serverTimestamp()
//               });
//               
//               logger.info(`✅ Wallet deduction completed - userId: ${userId}, deductedAmount: ${totalSuccessfulAmount}, newBalance: ${currentBalance - totalSuccessfulAmount}`);
//             });
//           } catch (err) {
//             logger.error(`❌ Failed to deduct wallet for job ${jobId}:`, err);
//             // Continue with job completion even if wallet deduction fails
//           }
//         }
//         
//         await bulkAirtimeJobsCollection.doc(jobId).update({
//           status: 'completed',
//           updatedAt: FieldValue.serverTimestamp(),
//           totalSuccessfulAmount: totalSuccessfulAmount,
//           successfulCount: successfulResults.length,
//           failedCount: results.length - successfulResults.length
//         });
//       }
//     }
//     logger.info('✅ Bulk airtime worker completed processing cycle');
//   } catch (err) {
//     logger.error('❌ Bulk airtime worker error:', err);
//     console.error('Bulk airtime worker error:', err);
//     
//     // If there was an error, try to reset any stuck 'processing' jobs to 'pending'
//     try {
//       const stuckJobs = await bulkAirtimeJobsCollection
//         .where('status', '==', 'processing')
//         .where('updatedAt', '<', new Date(Date.now() - 5 * 60 * 1000)) // 5 minutes ago
//         .get();
//       
//       for (const stuckJob of stuckJobs.docs) {
//         await stuckJob.ref.update({
//           status: 'pending',
//           updatedAt: FieldValue.serverTimestamp()
//         });
//         logger.info(`🔄 Reset stuck job ${stuckJob.id} from processing to pending`);
//       }
//     } catch (resetError) {
//       logger.error('❌ Failed to reset stuck jobs:', resetError);
//     }
//   }
// }
// setInterval(processBulkAirtimeJobs, BULK_AIRTIME_WORKER_INTERVAL);
// --- END BULK AIRTIME QUEUE ENDPOINTS ---

// --- STK PUSH INITIATION ENDPOINT ---
app.post('/api/mpesa/stkpush', async (req, res) => {
  const { amount, phoneNumber, accountNumber } = req.body;
  
  logger.info('🚀 STK Push endpoint called - /api/mpesa/stkpush', { 
    amount, 
    phoneNumber, 
    accountNumber,
    body: req.body 
  });
  
  if (!amount || !phoneNumber || !accountNumber) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  try {
    // Use existing timestamp and password generation functions/variables
    const timestamp = generateTimestamp();
    const password = generatePassword(SHORTCODE, PASSKEY, timestamp);
    // Use existing token function (getAccessToken or getDarajaAccessToken)
    const token = await getAccessToken();

    // Truncate AccountReference to M-Pesa limits (max 20 characters)
    const truncatedAccountRef = accountNumber.length > 20 ? accountNumber.substring(0, 20) : accountNumber;
    
    const payload = {
      BusinessShortCode: SHORTCODE,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: Number(amount),
      PartyA: phoneNumber,
      PartyB: SHORTCODE,
      PhoneNumber: phoneNumber,
      CallBackURL: STK_CALLBACK_URL,
      AccountReference: truncatedAccountRef,
      TransactionDesc: 'Wallet Top Up'
    };
    
    logger.info('📤 STK Push payload being sent to M-Pesa:', payload);

    const stkRes = await axios.post(
      'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
      payload,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    logger.info('STK Push Request Sent to Daraja:', stkRes.data);
    
    const {
      ResponseCode,
      ResponseDescription,
      CustomerMessage,
      CheckoutRequestID,
      MerchantRequestID
    } = stkRes.data;
    
    // Create stk_transaction record if M-Pesa successfully accepted the push request
    if (ResponseCode === '0') {
      await stkTransactionsCollection.doc(CheckoutRequestID).set({
        checkoutRequestID: CheckoutRequestID,
        merchantRequestID: MerchantRequestID,
        phoneNumber: phoneNumber,
        amount: Number(amount),
        recipient: accountNumber, // For wallet top-up, recipient is the account number
        carrier: 'N/A', // Not applicable for wallet top-up
        initialRequestAt: FieldValue.serverTimestamp(),
        stkPushStatus: 'PUSH_INITIATED',
        stkPushPayload: payload,
        darajaResponse: stkRes.data,
        customerName: null,
        serviceType: 'wallet_topup',
        reference: accountNumber,
        lastUpdated: FieldValue.serverTimestamp(),
      });
      logger.info(`✅ STK Transaction document ${CheckoutRequestID} created for wallet top-up.`);
    } else {
      logger.error('❌ STK Push Request Failed by Daraja:', stkRes.data);
      await errorsCollection.add({
        type: 'STK_PUSH_INITIATION_FAILED_BY_DARJA',
        error: ResponseDescription,
        requestPayload: payload,
        mpesaResponse: stkRes.data,
        createdAt: FieldValue.serverTimestamp(),
        checkoutRequestID: CheckoutRequestID,
      });
    }
    
    res.json({
      message: 'STK Push initiated. Await callback for confirmation.',
      merchantRequestID: stkRes.data.MerchantRequestID,
      checkoutRequestID: stkRes.data.CheckoutRequestID,
      responseDescription: stkRes.data.ResponseDescription
    });
  } catch (err) {
    console.error('STK Push error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to initiate STK Push.' });
  }
});

// --- DRIVER STK PUSH INITIATION ENDPOINT ---
app.post('/api/driver/stkpush', async (req, res) => {
  const { amount, customerPhone, driverUsername, recipientPhone, telco } = req.body;
  
  logger.info('🚀 STK Push endpoint called - /api/driver/stkpush', { 
    amount, 
    customerPhone, 
    driverUsername, 
    recipientPhone, 
    telco,
    body: req.body 
  });
  
  if (!amount || !customerPhone || !driverUsername || !recipientPhone || !telco) {
    return res.status(400).json({ error: 'Missing required fields: amount, customerPhone, driverUsername, recipientPhone, telco.' });
  }

  try {
    // Validate driver exists
    const driverDoc = await firestore.collection('drivers').where('username', '==', driverUsername).limit(1).get();
    if (driverDoc.empty) {
      return res.status(400).json({ error: 'Driver not found with the provided username.' });
    }

    const timestamp = generateTimestamp();
    const password = generatePassword(SHORTCODE, PASSKEY, timestamp);
    const token = await getAccessToken();

    // Always use driverUsername as AccountReference, regardless of what frontend sends
    const accountReference = req.body.driverUsername;
    
    // Truncate to M-Pesa limits (max 20 characters)
    const truncatedAccountRef = accountReference.length > 20 ? accountReference.substring(0, 20) : accountReference;
    
    logger.info(`📝 AccountReference processing - driverUsername: ${driverUsername}, truncated: ${truncatedAccountRef}`);
    
    const payload = {
      BusinessShortCode: SHORTCODE,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: Number(amount),
      PartyA: customerPhone,
      PartyB: SHORTCODE,
      PhoneNumber: customerPhone,
      CallBackURL: STK_CALLBACK_URL,
      AccountReference: truncatedAccountRef,
      TransactionDesc: 'Driver Airtime Sale'
    };
    
    logger.info('📤 Driver STK Push payload being sent to M-Pesa:', payload);

    const stkRes = await axios.post(
      'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
      payload,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    logger.info('Driver STK Push Request Sent to Daraja:', stkRes.data);
    
    const {
      ResponseCode,
      ResponseDescription,
      CustomerMessage,
      CheckoutRequestID,
      MerchantRequestID
    } = stkRes.data;
    
    // Create stk_transaction record if M-Pesa successfully accepted the push request
    if (ResponseCode === '0') {
      await stkTransactionsCollection.doc(CheckoutRequestID).set({
        checkoutRequestID: CheckoutRequestID,
        merchantRequestID: MerchantRequestID,
        phoneNumber: customerPhone,
        amount: Number(amount),
        recipient: recipientPhone,
        carrier: telco,
        initialRequestAt: FieldValue.serverTimestamp(),
        stkPushStatus: 'PUSH_INITIATED',
        stkPushPayload: payload,
        darajaResponse: stkRes.data,
        customerName: null,
        serviceType: 'driver_airtime_sale',
        reference: driverUsername,
        driverUsername: driverUsername,
        lastUpdated: FieldValue.serverTimestamp(),
      });
      logger.info(`✅ STK Transaction document ${CheckoutRequestID} created for driver airtime sale.`);
    } else {
      logger.error('❌ Driver STK Push Request Failed by Daraja:', stkRes.data);
      await errorsCollection.add({
        type: 'STK_PUSH_INITIATION_FAILED_BY_DARJA',
        error: ResponseDescription,
        requestPayload: payload,
        mpesaResponse: stkRes.data,
        createdAt: FieldValue.serverTimestamp(),
        checkoutRequestID: CheckoutRequestID,
        driverUsername: driverUsername,
      });
    }
    
    logger.info(`🚗 Driver STK Push initiated - driver: ${driverUsername}, customer: ${customerPhone}, recipient: ${recipientPhone}, amount: ${amount}`);
    
    res.json({
      message: 'Driver STK Push initiated. Await callback for confirmation.',
      merchantRequestID: stkRes.data.MerchantRequestID,
      checkoutRequestID: stkRes.data.CheckoutRequestID,
      responseDescription: stkRes.data.ResponseDescription,
      driverUsername: driverUsername,
      recipientPhone: recipientPhone,
      telco: telco
    });
  } catch (err) {
    logger.error('Driver STK Push error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to initiate Driver STK Push.' });
  }
});

// --- SINGLE AIRTIME ENDPOINT ---
app.post('/api/single-airtime', async (req, res) => {
    const { requests, totalAmount, userId, userType } = req.body;
    
    if (!Array.isArray(requests) || requests.length !== 1 || !totalAmount || !userId) {
        return res.status(400).json({ error: 'Invalid request format. Expected single airtime request.' });
    }

    const { phoneNumber, amount, telco, name } = requests[0];
    
    if (!phoneNumber || !amount || !telco) {
        return res.status(400).json({ error: 'Missing required fields: phoneNumber, amount, telco.' });
    }

    // Get user data to extract organization/shop/username and deduct wallet balance
    let organizationName = 'unknown';
    let userData = null;
    let userRef = null;
    let detectedUserType = null;
    
    try {
        // Check both retailers and drivers collections
        const [retailersDoc, driversDoc] = await Promise.all([
            firestore.collection('retailers').doc(userId).get(),
            firestore.collection('drivers').doc(userId).get()
        ]);
        
        if (retailersDoc.exists) {
            userData = retailersDoc.data();
            userRef = retailersDoc.ref;
            detectedUserType = 'retailer';
            // Retailers have shopName
            organizationName = userData.shopName || userData.organizationName || 'unknown';
        } else if (driversDoc.exists) {
            userData = driversDoc.data();
            userRef = driversDoc.ref;
            detectedUserType = 'driver';
            // Drivers have username
            organizationName = userData.username || userData.organizationName || 'unknown';
        } else {
            return res.status(400).json({ error: 'Single airtime is only available for drivers and retailers. User not found in either collection.' });
        }
        
        // Validate userType if provided
        if (userType && userType !== detectedUserType) {
            console.warn(`User type mismatch: expected ${userType}, detected ${detectedUserType} for userId: ${userId}`);
        }
        
        // check wallet balance before sending airtime
        await firestore.runTransaction(async (tx) => {
            const userDoc = await tx.get(userRef);
            if (!userDoc.exists) {
                throw new Error('User not found.');
            }
            const currentBalance = userData.walletBalance || 0;
            if (currentBalance < totalAmount) {
                throw new Error('Insufficient wallet balance.');
            }
        });
    } catch (err) {
        console.error('Single airtime wallet deduction error:', err);
        return res.status(400).json({ error: err.message || 'Failed to deduct wallet balance.' });
    }

    // Send airtime
    let status = 'FAILED';
    let message = '';
    let dispatchResult = null;
    
    try {
        let result;
        if (telco && telco.toLowerCase() === 'safaricom') {
            result = await sendSafaricomAirtime(phoneNumber, amount);
            if (result && result.status === 'SUCCESS') {
                status = 'SUCCESS';
                message = 'Airtime sent via Safaricom';
            } else {
                // Fallback to Africa's Talking
                result = await sendAfricasTalkingAirtime(phoneNumber, amount, telco);
                if (result && result.status === 'SUCCESS') {
                    status = 'SUCCESS';
                    message = 'Airtime sent via Africa\'s Talking fallback';
                } else {
                    message = result && result.message ? result.message : 'Both Safaricom and fallback failed';
                }
            }
        } else {
            // Non-Safaricom: use Africa's Talking
            result = await sendAfricasTalkingAirtime(phoneNumber, amount, telco);
            if (result && result.status === 'SUCCESS') {
                status = 'SUCCESS';
                message = 'Airtime sent via Africa\'s Talking';
            } else {
                message = result && result.message ? result.message : 'Africa\'s Talking failed';
            }
        }
        dispatchResult = result;
    } catch (err) {
        message = err.message || 'Exception during airtime dispatch';
    }

    // Handle commission for drivers on successful airtime sends
    if (status === 'SUCCESS') {
      const carrierLogicalName = telco === 'Safaricom' ? 'safaricomFloat' : 'africasTalkingFloat';
        await updateCarrierFloatBalance(carrierLogicalName, -amount);

       // Deduct wallet AFTER successful send
       try {
        await userRef.update({
            walletBalance: FieldValue.increment(-totalAmount),
            lastWalletUpdate: FieldValue.serverTimestamp()
        });
        logger.info(`✅ Wallet deducted for successful single airtime send - userId: ${userId}, amount: ${totalAmount}`);
        } catch (err) {
          logger.error(`❌ Failed to deduct wallet after successful airtime send - userId: ${userId}: ${err.message}`);
    }

        // --- NEW COMMISSION LOGIC ---
        let commissionAmount = 0;
        let commissionPercentage = 0;

        if (detectedUserType === 'driver') {
            try {
                const commissionSettingsDoc = await firestore.collection('airtime_bonuses').doc('current_settings').get();
                if (commissionSettingsDoc.exists) {
                    const settings = commissionSettingsDoc.data();
                    if (telco.toLowerCase() === 'safaricom') {
                        commissionPercentage = settings.safaricomPercentage || 0;
                    } else {
                        commissionPercentage = settings.africastalkingPercentage || 0;
                    }
                } else {
                    logger.warn(`⚠️ airtime_bonuses/current_settings document not found. Commission will be 0.`);
                }
                commissionAmount = amount * (commissionPercentage / 100);

                if (commissionAmount > 0) {
                    await userRef.update({
                        commissionEarned: FieldValue.increment(commissionAmount),
                        lastCommissionUpdate: FieldValue.serverTimestamp()
                    });
                    logger.info(`✅ Commission of ${commissionAmount} awarded to driver ${userId} for single airtime sale.`);
                }
            } catch (err) {
                logger.error(`❌ Failed to award commission to driver ${userId}: ${err.message}`);
            }
        }
        // --- END OF NEW COMMISSION LOGIC ---

        // Create single sale record for successful airtime sends
        const saleId = `SINGLE_SALE_${Date.now()}`;
        logger.info(`🔄 Attempting to write single sale for ${detectedUserType}: ${organizationName}, saleId: ${saleId}, phoneNumber: ${phoneNumber}, amount: ${amount}`);
        
        try {
            await singleSalesCollection.doc(organizationName).collection('sales').doc(saleId).set({
                saleId,
                type: 'SINGLE_AIRTIME_SALE',
                userId,
                userType: detectedUserType,
                organizationName,
                phoneNumber,
                amount,
                telco,
                recipientName: name || '',
                status: 'SUCCESS',
                message,
                dispatchResult,
                commissionEarned: commissionAmount,
                commissionPercentage: commissionPercentage,
                createdAt: FieldValue.serverTimestamp(),
                lastUpdated: FieldValue.serverTimestamp()
            });
            logger.info(`✅ Successfully wrote single sale for ${detectedUserType}: ${organizationName}, saleId: ${saleId}, phoneNumber: ${phoneNumber}, amount: ${amount}`);
        } catch (err) {
            logger.error(`❌ Failed to write single sale for ${detectedUserType}: ${organizationName}, saleId: ${saleId}, phoneNumber: ${phoneNumber}, amount: ${amount}`, { 
                error: err.message, 
                stack: err.stack,
                organizationName,
                saleId,
                phoneNumber,
                amount,
                userId,
                userType: detectedUserType
            });
        }
    } else {
        // --- REFUNDING LOGIC (UNCOMMENTED) ---
        try {
            await userRef.update({
                walletBalance: FieldValue.increment(totalAmount), // Refund the deducted amount
                lastWalletUpdate: FieldValue.serverTimestamp()
            });
            logger.info(`✅ Wallet refunded for failed single airtime send - userId: ${userId}, refundedAmount: ${totalAmount}`);
        } catch (refundErr) {
            logger.error(`❌ Failed to refund wallet for failed single airtime send - userId: ${userId}: ${refundErr.message}`);
        }
        // --- END REFUNDING LOGIC ---
        logger.warn(`⚠️ Skipping single sale write for failed airtime send - phoneNumber: ${phoneNumber}, status: ${status}, message: ${message}`);
    }

    res.json({ 
        success: status === 'SUCCESS',
        status,
        message,
        phoneNumber,
        amount,
        telco,
        userType: detectedUserType
    });
});

// --- ADMIN BULK ENDPOINTS (CORPORATE USERS ONLY) ---

// Get all bulk transactions for admin
app.get('/api/admin/bulk-transactions', async (req, res) => {
  try {
    const { page = 1, limit = 20, status, organizationName, startDate, endDate } = req.query;
    const pageNumber = parseInt(page);
    const pageSize = parseInt(limit);
    const offset = (pageNumber - 1) * pageSize;

    let query = bulkTransactionsCollection.orderBy('createdAt', 'desc');

    // Apply filters
    if (status) {
      query = query.where('status', '==', status);
    }
    if (organizationName) {
      // Ensure we're filtering by the correct organization name field
      query = query.where('organizationName', '==', organizationName);
    }
    if (startDate && endDate) {
      const start = new Date(startDate);
      const end = new Date(endDate);
      query = query.where('createdAt', '>=', start).where('createdAt', '<=', end);
    }

    // Get total count for pagination
    const countSnapshot = await query.get();
    const totalCount = countSnapshot.size;

    // Get paginated results
    const snapshot = await query.limit(pageSize).offset(offset).get();
    const transactions = [];

    for (const doc of snapshot.docs) {
      const data = doc.data();
      
      // Validate that this is a corporate transaction
      if (!data.organizationName) {
        console.warn(`Transaction ${doc.id} missing organizationName, skipping...`);
        continue;
      }
      
      transactions.push({
        id: doc.id,
        ...data,
        createdAt: data.createdAt?.toDate?.() || data.createdAt,
        lastUpdated: data.lastUpdated?.toDate?.() || data.lastUpdated
      });
    }

    res.json({
      transactions,
      pagination: {
        currentPage: pageNumber,
        pageSize,
        totalCount,
        totalPages: Math.ceil(totalCount / pageSize)
      }
    });
  } catch (error) {
    console.error('Error fetching bulk transactions:', error);
    res.status(500).json({ error: 'Failed to fetch bulk transactions' });
  }
});

// Get all bulk sales for admin
app.get('/api/admin/bulk-sales', async (req, res) => {
  try {
    const { page = 1, limit = 20, organizationName, status, startDate, endDate } = req.query;
    const pageNumber = parseInt(page);
    const pageSize = parseInt(limit);
    const offset = (pageNumber - 1) * pageSize;

    let allSales = [];
    let totalCount = 0;

    if (organizationName) {
      // Get sales for specific organization
      const salesSnapshot = await bulkSalesCollection.doc(organizationName).collection('sales')
        .orderBy('createdAt', 'desc')
        .get();
      
      allSales = salesSnapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data(),
        createdAt: doc.data().createdAt?.toDate?.() || doc.data().createdAt,
        lastUpdated: doc.data().lastUpdated?.toDate?.() || doc.data().lastUpdated
      }));
    } else {
      // Get all sales from all organizations (corporate users only)
      const orgsSnapshot = await bulkSalesCollection.get();
      for (const orgDoc of orgsSnapshot.docs) {
        const salesSnapshot = await orgDoc.ref.collection('sales')
          .orderBy('createdAt', 'desc')
          .get();
        
        const orgSales = salesSnapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data(),
          createdAt: doc.data().createdAt?.toDate?.() || doc.data().createdAt,
          lastUpdated: doc.data().lastUpdated?.toDate?.() || doc.data().lastUpdated
        }));
        allSales.push(...orgSales);
      }
    }

    // Apply filters
    if (status) {
      allSales = allSales.filter(sale => sale.status === status);
    }
    if (startDate && endDate) {
      const start = new Date(startDate);
      const end = new Date(endDate);
      allSales = allSales.filter(sale => {
        const saleDate = sale.createdAt instanceof Date ? sale.createdAt : new Date(sale.createdAt);
        return saleDate >= start && saleDate <= end;
      });
    }

    totalCount = allSales.length;

    // Apply pagination
    const paginatedSales = allSales.slice(offset, offset + pageSize);

    res.json({
      sales: paginatedSales,
      pagination: {
        currentPage: pageNumber,
        pageSize,
        totalCount,
        totalPages: Math.ceil(totalCount / pageSize)
      }
    });
  } catch (error) {
    console.error('Error fetching bulk sales:', error);
    res.status(500).json({ error: 'Failed to fetch bulk sales' });
  }
});

// Get all single sales for  users
app.get('/api/admin/single-sales', async (req, res) => {
  try {
    const { page = 1, limit = 20, organizationName, status, startDate, endDate, userType } = req.query;
    const pageNumber = parseInt(page);
    const pageSize = parseInt(limit);
    const offset = (pageNumber - 1) * pageSize;

    let allSales = [];
    let totalCount = 0;

    if (organizationName) {
      // Get sales for specific organization/user
      const salesSnapshot = await firestore.collection('single_sales').doc(organizationName).collection('sales')
        .orderBy('createdAt', 'desc')
        .get();
      
      allSales = salesSnapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data(),
        createdAt: doc.data().createdAt?.toDate?.() || doc.data().createdAt,
        lastUpdated: doc.data().lastUpdated?.toDate?.() || doc.data().lastUpdated
      }));
    } else {
      // Get all sales from all organizations/users
      const orgsSnapshot = await firestore.collection('single_sales').get();
      for (const orgDoc of orgsSnapshot.docs) {
        const salesSnapshot = await orgDoc.ref.collection('sales')
          .orderBy('createdAt', 'desc')
          .get();
        
        const orgSales = salesSnapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data(),
          createdAt: doc.data().createdAt?.toDate?.() || doc.data().createdAt,
          lastUpdated: doc.data().lastUpdated?.toDate?.() || doc.data().lastUpdated
        }));
        allSales.push(...orgSales);
      }
    }

    // Apply filters
    if (status) {
      allSales = allSales.filter(sale => sale.status === status);
    }
    if (userType) {
      allSales = allSales.filter(sale => sale.userType === userType);
    }
    if (startDate && endDate) {
      const start = new Date(startDate);
      const end = new Date(endDate);
      allSales = allSales.filter(sale => {
        const saleDate = sale.createdAt instanceof Date ? sale.createdAt : new Date(sale.createdAt);
        return saleDate >= start && saleDate <= end;
      });
    }

    totalCount = allSales.length;

    // Apply pagination
    const paginatedSales = allSales.slice(offset, offset + pageSize);

    res.json({
      sales: paginatedSales,
      pagination: {
        currentPage: pageNumber,
        pageSize,
        totalCount,
        totalPages: Math.ceil(totalCount / pageSize)
      }
    });
  } catch (error) {
    console.error('Error fetching single sales:', error);
    res.status(500).json({ error: 'Failed to fetch single sales' });
  }
});

// Get single sales for specific user (driver, retailer, organization)
app.get('/api/user/single-sales/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20, status, startDate, endDate } = req.query;
    const pageNumber = parseInt(page);
    const pageSize = parseInt(limit);
    const offset = (pageNumber - 1) * pageSize;

    // Get sales for specific user
    const salesSnapshot = await firestore.collection('single_sales').doc(userId).collection('sales')
      .orderBy('createdAt', 'desc')
      .get();
    
    let allSales = salesSnapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      createdAt: doc.data().createdAt?.toDate?.() || doc.data().createdAt,
      lastUpdated: doc.data().lastUpdated?.toDate?.() || doc.data().lastUpdated
    }));

    // Apply filters
    if (status) {
      allSales = allSales.filter(sale => sale.status === status);
    }
    if (startDate && endDate) {
      const start = new Date(startDate);
      const end = new Date(endDate);
      allSales = allSales.filter(sale => {
        const saleDate = sale.createdAt instanceof Date ? sale.createdAt : new Date(sale.createdAt);
        return saleDate >= start && saleDate <= end;
      });
    }

    const totalCount = allSales.length;
    const paginatedSales = allSales.slice(offset, offset + pageSize);

    res.json({
      sales: paginatedSales,
      pagination: {
        currentPage: pageNumber,
        pageSize,
        totalCount,
        totalPages: Math.ceil(totalCount / pageSize)
      }
    });
  } catch (error) {
    console.error('Error fetching user single sales:', error);
    res.status(500).json({ error: 'Failed to fetch user single sales' });
  }
});

// Get bulk transaction details with associated sales
app.get('/api/admin/bulk-transactions/:transactionId', async (req, res) => {
  try {
    const { transactionId } = req.params;
    
    // Get transaction details
    const transactionDoc = await bulkTransactionsCollection.doc(transactionId).get();
    if (!transactionDoc.exists) {
      return res.status(404).json({ error: 'Bulk transaction not found' });
    }

    const transactionData = transactionDoc.data();
    
    // Validate this is a corporate transaction
    if (!transactionData.organizationName) {
      return res.status(400).json({ error: 'Invalid transaction: missing organization name' });
    }
    
    // Get associated sales
    const salesSnapshot = await bulkSalesCollection.doc(transactionData.organizationName)
      .collection('sales')
      .where('jobId', '==', transactionData.jobId)
      .get();

    const sales = salesSnapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      createdAt: doc.data().createdAt?.toDate?.() || doc.data().createdAt,
      lastUpdated: doc.data().lastUpdated?.toDate?.() || doc.data().lastUpdated
    }));

    res.json({
      transaction: {
        id: transactionDoc.id,
        ...transactionData,
        createdAt: transactionData.createdAt?.toDate?.() || transactionData.createdAt,
        lastUpdated: transactionData.lastUpdated?.toDate?.() || transactionData.lastUpdated
      },
      sales
    });
  } catch (error) {
    console.error('Error fetching bulk transaction details:', error);
    res.status(500).json({ error: 'Failed to fetch bulk transaction details' });
  }
});

// Get bulk transaction statistics for admin dashboard
app.get('/api/admin/bulk-statistics', async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const start = startDate ? new Date(startDate) : new Date(new Date().setDate(new Date().getDate() - 30));
    const end = endDate ? new Date(endDate) : new Date();

    // Get transactions in date range (corporate users only)
    const transactionsSnapshot = await bulkTransactionsCollection
      .where('createdAt', '>=', start)
      .where('createdAt', '<=', end)
      .get();

    const transactions = transactionsSnapshot.docs.map(doc => doc.data());
    
    // Calculate statistics
    const totalTransactions = transactions.length;
    const totalAmount = transactions.reduce((sum, tx) => sum + (tx.totalAmount || 0), 0);
    const completedTransactions = transactions.filter(tx => tx.status === 'COMPLETED').length;
    const pendingTransactions = transactions.filter(tx => tx.status === 'PENDING_PROCESSING').length;
    
    // Get organization breakdown (corporate organizations only)
    const orgBreakdown = {};
    transactions.forEach(tx => {
      const org = tx.organizationName || 'unknown';
      if (!orgBreakdown[org]) {
        orgBreakdown[org] = { count: 0, amount: 0 };
      }
      orgBreakdown[org].count++;
      orgBreakdown[org].amount += tx.totalAmount || 0;
    });

    res.json({
      period: { start, end },
      summary: {
        totalTransactions,
        totalAmount,
        completedTransactions,
        pendingTransactions,
        successRate: totalTransactions > 0 ? (completedTransactions / totalTransactions * 100).toFixed(2) : 0
      },
      organizationBreakdown: orgBreakdown
    });
  } catch (error) {
    console.error('Error fetching bulk statistics:', error);
    res.status(500).json({ error: 'Failed to fetch bulk statistics' });
  }
});

// --- USER BULK HISTORY ENDPOINTS (CORPORATE USERS ONLY) ---

// Get user's bulk airtime history
app.get('/api/user/bulk-history/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20, status, startDate, endDate } = req.query;
    const pageNumber = parseInt(page);
    const pageSize = parseInt(limit);
    const offset = (pageNumber - 1) * pageSize;

    // Verify user is a corporate user
    const userDoc = await firestore.collection('organisations').doc(userId).get();
    if (!userDoc.exists) {
      return res.status(403).json({ error: 'Access denied. Bulk airtime is only available for corporate users.' });
    }

    const userData = userDoc.data();
    const organizationName = userData.organizationName;

    // Get user's bulk transactions
    let transactionsQuery = bulkTransactionsCollection
      .where('userId', '==', userId)
      .orderBy('createdAt', 'desc');

    // Apply filters
    if (status) {
      transactionsQuery = transactionsQuery.where('status', '==', status);
    }
    if (startDate && endDate) {
      const start = new Date(startDate);
      const end = new Date(endDate);
      transactionsQuery = transactionsQuery.where('createdAt', '>=', start).where('createdAt', '<=', end);
    }

    const transactionsSnapshot = await transactionsQuery.get();
    const transactions = [];

    for (const doc of transactionsSnapshot.docs) {
      const data = doc.data();
      transactions.push({
        id: doc.id,
        ...data,
        createdAt: data.createdAt?.toDate?.() || data.createdAt,
        lastUpdated: data.lastUpdated?.toDate?.() || data.lastUpdated
      });
    }

    // Get user's bulk sales (using organization name)
    const userSales = [];
    if (organizationName) {
      const salesSnapshot = await bulkSalesCollection.doc(organizationName).collection('sales')
        .where('userId', '==', userId)
        .orderBy('createdAt', 'desc')
        .get();
      
      const orgSales = salesSnapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data(),
        createdAt: doc.data().createdAt?.toDate?.() || doc.data().createdAt,
        lastUpdated: doc.data().lastUpdated?.toDate?.() || doc.data().lastUpdated
      }));
      userSales.push(...orgSales);
    }

    // Get user's bulk airtime logs
    const logsSnapshot = await firestore.collection('bulk_airtime_logs')
      .where('userId', '==', userId)
      .orderBy('requestedAt', 'desc')
      .get();

    const logs = logsSnapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      requestedAt: doc.data().requestedAt?.toDate?.() || doc.data().requestedAt
    }));

    // Apply pagination to combined results
    const allHistory = [
      ...transactions.map(tx => ({ ...tx, type: 'transaction' })),
      ...userSales.map(sale => ({ ...sale, type: 'sale' })),
      ...logs.map(log => ({ ...log, type: 'log' }))
    ].sort((a, b) => {
      const dateA = a.createdAt || a.requestedAt;
      const dateB = b.createdAt || b.requestedAt;
      return new Date(dateB) - new Date(dateA);
    });

    const totalCount = allHistory.length;
    const paginatedHistory = allHistory.slice(offset, offset + pageSize);

    res.json({
      history: paginatedHistory,
      pagination: {
        currentPage: pageNumber,
        pageSize,
        totalCount,
        totalPages: Math.ceil(totalCount / pageSize)
      },
      summary: {
        totalTransactions: transactions.length,
        totalSales: userSales.length,
        totalLogs: logs.length,
        successfulTransactions: transactions.filter(tx => tx.status === 'COMPLETED').length,
        successfulSales: userSales.filter(sale => sale.status === 'SUCCESS').length
      }
    });
  } catch (error) {
    console.error('Error fetching user bulk history:', error);
    res.status(500).json({ error: 'Failed to fetch user bulk history' });
  }
});

// Get user's bulk transaction details
app.get('/api/user/bulk-transactions/:transactionId', async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { userId } = req.query; // For security, verify user owns this transaction

    // Verify user is a corporate user
    const userDoc = await firestore.collection('organisations').doc(userId).get();
    if (!userDoc.exists) {
      return res.status(403).json({ error: 'Access denied. Bulk airtime is only available for corporate users.' });
    }

    const userData = userDoc.data();
    const organizationName = userData.organizationName;

    const transactionDoc = await bulkTransactionsCollection.doc(transactionId).get();
    if (!transactionDoc.exists) {
      return res.status(404).json({ error: 'Bulk transaction not found' });
    }

    const transactionData = transactionDoc.data();
    
    // Security check - ensure user owns this transaction
    if (transactionData.userId !== userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Validate organization name matches
    if (transactionData.organizationName !== organizationName) {
      return res.status(403).json({ error: 'Organization mismatch' });
    }

    // Get associated sales
    const salesSnapshot = await bulkSalesCollection.doc(organizationName)
      .collection('sales')
      .where('jobId', '==', transactionData.jobId)
      .where('userId', '==', userId)
      .get();

    const sales = salesSnapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      createdAt: doc.data().createdAt?.toDate?.() || doc.data().createdAt,
      lastUpdated: doc.data().lastUpdated?.toDate?.() || doc.data().lastUpdated
    }));

    // Get associated logs
    const logsSnapshot = await firestore.collection('bulk_airtime_logs')
      .where('userId', '==', userId)
      .where('jobId', '==', transactionData.jobId)
      .orderBy('requestIndex')
      .get();

    const logs = logsSnapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      requestedAt: doc.data().requestedAt?.toDate?.() || doc.data().requestedAt
    }));

    res.json({
      transaction: {
        id: transactionDoc.id,
        ...transactionData,
        createdAt: transactionData.createdAt?.toDate?.() || transactionData.createdAt,
        lastUpdated: transactionData.lastUpdated?.toDate?.() || transactionData.lastUpdated
      },
      sales,
      logs
    });
  } catch (error) {
    console.error('Error fetching user bulk transaction details:', error);
    res.status(500).json({ error: 'Failed to fetch bulk transaction details' });
  }
});

// Get user's bulk statistics
app.get('/api/user/bulk-statistics/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { startDate, endDate } = req.query;
    const start = startDate ? new Date(startDate) : new Date(new Date().setDate(new Date().getDate() - 30));
    const end = endDate ? new Date(endDate) : new Date();

    // Verify user is a corporate user
    const userDoc = await firestore.collection('organisations').doc(userId).get();
    if (!userDoc.exists) {
      return res.status(403).json({ error: 'Access denied. Bulk airtime is only available for corporate users.' });
    }

    const userData = userDoc.data();
    const organizationName = userData.organizationName;

    // Get user's transactions in date range
    const transactionsSnapshot = await bulkTransactionsCollection
      .where('userId', '==', userId)
      .where('createdAt', '>=', start)
      .where('createdAt', '<=', end)
      .get();

    const transactions = transactionsSnapshot.docs.map(doc => doc.data());

    // Get user's sales in date range (using organization name)
    const userSales = [];
    if (organizationName) {
      const salesSnapshot = await bulkSalesCollection.doc(organizationName).collection('sales')
        .where('userId', '==', userId)
        .where('createdAt', '>=', start)
        .where('createdAt', '<=', end)
        .get();
      
      const orgSales = salesSnapshot.docs.map(doc => doc.data());
      userSales.push(...orgSales);
    }

    // Calculate statistics
    const totalTransactions = transactions.length;
    const totalAmount = transactions.reduce((sum, tx) => sum + (tx.totalAmount || 0), 0);
    const completedTransactions = transactions.filter(tx => tx.status === 'COMPLETED').length;
    const successfulSales = userSales.filter(sale => sale.status === 'SUCCESS').length;
    const totalSales = userSales.length;

    res.json({
      period: { start, end },
      summary: {
        totalTransactions,
        totalAmount,
        completedTransactions,
        totalSales,
        successfulSales,
        successRate: totalTransactions > 0 ? (completedTransactions / totalTransactions * 100).toFixed(2) : 0,
        salesSuccessRate: totalSales > 0 ? (successfulSales / totalSales * 100).toFixed(2) : 0
      }
    });
  } catch (error) {
    console.error('Error fetching user bulk statistics:', error);
    res.status(500).json({ error: 'Failed to fetch user bulk statistics' });
  }
}); 
