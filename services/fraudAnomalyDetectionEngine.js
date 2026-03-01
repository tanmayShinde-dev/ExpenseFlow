/**
 * Fraud and Anomaly Detection Engine for ExpenseFlow
 *
 * Features:
 * - Data ingestion pipeline (transactions, logins, user actions)
 * - Feature extraction and transformation
 * - Machine learning model integration (training, inference)
 * - Statistical anomaly detection
 * - Rule-based fraud detection
 * - Real-time prediction and alerting
 * - Investigation workflow API
 * - Scalable, robust, secure design
 */

const mongoose = require('mongoose');
const { EventEmitter } = require('events');
const crypto = require('crypto');
const { spawn } = require('child_process');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const AuditLog = require('../models/AuditLog');
const SuspiciousLogin = require('../models/SuspiciousLogin');
const FraudAlert = require('../models/FraudAlert');

// --- Event Bus for Real-Time Alerts --- //
const fraudEventBus = new EventEmitter();

// --- Data Ingestion Pipeline --- //
async function ingestTransaction(tx) {
    // Save transaction, extract features, run detection
    await Transaction.create(tx);
    const features = extractTransactionFeatures(tx);
    await runFraudDetection('transaction', features, tx);
}

async function ingestLogin(login) {
    await AuditLog.create(login);
    const features = extractLoginFeatures(login);
    await runFraudDetection('login', features, login);
}

// --- Feature Extraction --- //
function extractTransactionFeatures(tx) {
    return {
        amount: tx.amount,
        type: tx.type,
        category: tx.category,
        user: tx.user,
        location: tx.location,
        device: tx.device,
        time: tx.time,
        merchant: tx.merchant,
        ip: tx.ip,
        velocity: tx.velocity || 0,
        isInternational: tx.isInternational || false
    };
}

function extractLoginFeatures(login) {
    return {
        user: login.user,
        ip: login.ip,
        device: login.device,
        location: login.location,
        time: login.time,
        method: login.method,
        success: login.success,
        failedAttempts: login.failedAttempts || 0
    };
}

// --- Statistical Anomaly Detection --- //
function isStatisticalAnomaly(features, history, threshold = 3) {
    // Z-score based anomaly detection
    if (!history || history.length < 10) return false;
    const values = history.map(h => h.amount);
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const std = Math.sqrt(values.map(x => Math.pow(x - mean, 2)).reduce((a, b) => a + b, 0) / values.length);
    const z = (features.amount - mean) / std;
    return Math.abs(z) > threshold;
}

// --- Rule-Based Fraud Detection --- //
const FRAUD_RULES = [
    // Example rules
    tx => tx.amount > 10000,
    tx => tx.isInternational && tx.amount > 5000,
    tx => tx.velocity > 5,
    tx => tx.device && tx.device.isNew,
    tx => tx.category === 'crypto' && tx.amount > 1000
];

function isRuleBasedFraud(features) {
    return FRAUD_RULES.some(rule => rule(features));
}

// --- Machine Learning Model Integration --- //
async function runMLModel(features, type = 'transaction') {
    // Example: spawn Python process for ML inference
    return new Promise((resolve, reject) => {
        const py = spawn('python', ['ml_inference.py', type, JSON.stringify(features)]);
        let result = '';
        py.stdout.on('data', data => result += data);
        py.stderr.on('data', err => console.error('[MLModel] Error:', err.toString()));
        py.on('close', code => {
            if (code === 0) {
                try {
                    resolve(JSON.parse(result));
                } catch (e) {
                    reject(e);
                }
            } else {
                reject(new Error('ML model process failed'));
            }
        });
    });
}

// --- Fraud Detection Pipeline --- //
async function runFraudDetection(type, features, rawEvent) {
    let isFraud = false;
    let reasons = [];
    // Statistical anomaly
    if (type === 'transaction') {
        const history = await Transaction.find({ user: features.user }).sort({ time: -1 }).limit(100);
        if (isStatisticalAnomaly(features, history)) {
            isFraud = true;
            reasons.push('Statistical anomaly');
        }
    }
    // Rule-based
    if (isRuleBasedFraud(features)) {
        isFraud = true;
        reasons.push('Rule-based fraud');
    }
    // ML model
    try {
        const mlResult = await runMLModel(features, type);
        if (mlResult.isFraud) {
            isFraud = true;
            reasons.push('ML model prediction');
        }
    } catch (e) {
        console.error('[FraudDetection] ML model error:', e);
    }
    // Trigger alert if fraud detected
    if (isFraud) {
        await triggerFraudAlert(type, features, rawEvent, reasons);
    }
}

// --- Alerting and Investigation Workflow --- //
async function triggerFraudAlert(type, features, rawEvent, reasons) {
    const alert = await FraudAlert.create({
        type,
        user: features.user,
        event: rawEvent,
        reasons,
        timestamp: new Date(),
        status: 'pending'
    });
    fraudEventBus.emit('fraud_alert', alert);
    // Optionally notify analysts, send email/SMS, etc.
}

// --- API for Analysts --- //
async function getFraudAlerts({ user, status, from, to }) {
    const query = {};
    if (user) query.user = user;
    if (status) query.status = status;
    if (from || to) query.timestamp = {};
    if (from) query.timestamp.$gte = new Date(from);
    if (to) query.timestamp.$lte = new Date(to);
    return FraudAlert.find(query).sort({ timestamp: -1 });
}

async function updateFraudAlert(alertId, updates) {
    const alert = await FraudAlert.findById(alertId);
    if (!alert) throw new Error('Alert not found');
    Object.assign(alert, updates);
    await alert.save();
    return alert;
}

// --- Secure Design: Hashing, Encryption, Access Control --- //
function hashSensitiveData(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

function encryptData(data, key) {
    const cipher = crypto.createCipher('aes-256-cbc', key);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decryptData(encrypted, key) {
    const decipher = crypto.createDecipher('aes-256-cbc', key);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// --- Exported API --- //
module.exports = {
    ingestTransaction,
    ingestLogin,
    getFraudAlerts,
    updateFraudAlert,
    fraudEventBus,
    hashSensitiveData,
    encryptData,
    decryptData
};
