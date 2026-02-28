const express = require('express');
const http = require('http');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();

const authRoutes = require('./routes/auth');
const expenseRoutes = require('./routes/expenses');
const syncRoutes = require('./routes/sync');
const splitsRoutes = require('./routes/splits');
const groupsRoutes = require('./routes/groups');
const backupRoutes = require('./routes/backups');
const backupService = require('./services/backupService');
const twoFactorAuthRoutes = require('./routes/twoFactorAuth');
const cron = require('node-cron');

// Distributed real-time sync dependencies
const Redis = require('ioredis');
const redisPub = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const redisSub = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// Redis pub/sub channel for distributed sync
const SYNC_CHANNEL = 'expenseflow:sync';

const app = express();
const server = http.createServer(app);

// Initialize Asynchronous Listeners (Issue #711)
require('./listeners/EmailListeners').init();
require('./listeners/AuditListeners').init();


/* ================================
   SECURITY
================================ */

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: [
        "'self'",
        "https:",
        "wss:",
        "http://localhost:3000",
        "ws://localhost:3000"
      ]
    }
  }
}));

/* ================================
   CORS (VERCEL SAFE)
================================ */

app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

/* ================================
   BODY PARSER
================================ */

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(require('./middleware/encryptionInterceptor'));
app.use(require('./middleware/validationInterceptor'));
app.use(require('./middleware/auditInterceptor'));
app.use(require('./middleware/auditTraceability'));
app.use(require('./middleware/tenantResolver'));
// Inject Circuit Breaker protection early in the pipeline
// We pass 'TRANSACTION' as a default, though specific routers might override it
app.use(require('./middleware/complianceGuard')('TRANSACTION'));
app.use(require('./middleware/leakageGuard'));
app.use(require('./middleware/liquidityGuard'));
app.use(require('./middleware/balanceGuard'));
app.use(require('./middleware/governanceGuard'));
app.use(require('./middleware/journalInterceptor'));
app.use(require('./middleware/fieldMasker'));
app.use(require('./middleware/performanceInterceptor'));
app.use(require('./middleware/leakageMonitor'));



/* ================================
   DATABASE CONNECTION
================================ */

async function connectDatabase() {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 5000
    });

    console.log('✅ MongoDB connected');

    // Cron jobs only in development
    if (process.env.NODE_ENV !== 'production') {
      try {
        const CronJobs = require('./jobs/cronJobs');
        CronJobs.init();

        require('./jobs/trendAnalyzer').start();
        require('./jobs/reportScheduler').start();
        require('./jobs/accessAuditor').start();
        require('./jobs/forecastRetrainer').start();
        require('./jobs/taxonomyAuditor').start();
        require('./jobs/conflictCleaner').start();
        require('./jobs/logRotator').start();
        require('./jobs/searchIndexer').start();
        require('./jobs/searchPruner').start();
        require('./jobs/conflictPruner').start();
        require('./jobs/liquidityAnalyzer').start();
        require('./jobs/liquidityRebalancer').start();
        require('./jobs/policyAuditor').start();
        require('./jobs/journalApplier').start();
        require('./jobs/metricFlusher').start();
        require('./jobs/integrityAuditor').start();
        require('./jobs/cachePruner').start();
        require('./jobs/velocityCalculator').start();
        require('./jobs/keyRotator').start();
        require('./jobs/neuralReindexer').start(); // Issue #796: Semantic search re-indexer



        // Start resilient orchestrator
        require('./services/jobOrchestrator').start();



        console.log('✓ Cron jobs initialized');
      } catch (err) {
        console.log('Cron jobs skipped:', err.message);
      }
    }

  } catch (err) {
    console.error('❌ MongoDB connection error:', err.message);
  }
}

  // Listen for client expense changes and broadcast to Redis
  socket.on('expense_created', (expense) => {
    io.emit('expense_created', expense);
    redisPub.publish(SYNC_CHANNEL, JSON.stringify({ type: 'expense_created', expense }));
  });

  socket.on('expense_updated', (expense) => {
    io.emit('expense_updated', expense);
    redisPub.publish(SYNC_CHANNEL, JSON.stringify({ type: 'expense_updated', expense }));
  });

  socket.on('expense_deleted', (data) => {
    io.emit('expense_deleted', data);
    redisPub.publish(SYNC_CHANNEL, JSON.stringify({ type: 'expense_deleted', data }));
  });

  socket.on('disconnect', () => {
    console.log(`User ${socket.user.name} disconnected`);
  });
});

// Listen for Redis sync events and broadcast to local clients
redisSub.subscribe(SYNC_CHANNEL, (err) => {
  if (err) console.error('Redis subscribe error:', err);
});

redisSub.on('message', (channel, message) => {
  if (channel !== SYNC_CHANNEL) return;
  try {
    const payload = JSON.parse(message);
    if (payload.type === 'expense_created') {
      io.emit('expense_created', payload.expense);
    } else if (payload.type === 'expense_updated') {
      io.emit('expense_updated', payload.expense);
    } else if (payload.type === 'expense_deleted') {
      io.emit('expense_deleted', payload.data);
    }
  } catch (e) {
    console.error('Redis sync event error:', e);
  }
});

// Routes
app.use('/api/auth', require('./middleware/rateLimiter').authLimiter, authRoutes);
app.use('/api/expenses', require('./middleware/rateLimiter').expenseLimiter, expenseRoutes);
app.use('/api/sync', syncRoutes);
app.use('/api/notifications', require('./routes/notifications'));
app.use('/api/receipts', require('./middleware/rateLimiter').uploadLimiter, require('./routes/receipts'));
app.use('/api/budgets', require('./routes/budgets'));
app.use('/api/goals', require('./routes/goals'));
app.use('/api/analytics', require('./routes/analytics'));
app.use('/api/currency', require('./routes/currency'));
app.use('/api/groups', require('./routes/groups'));
app.use('/api/splits', require('./routes/splits'));
app.use('/api/workspaces', require('./routes/workspaces'));
app.use('/api/analytics', require('./routes/analytics'));
app.use('/api/export', require('./routes/export'));
app.use('/api/forecasting', require('./routes/forecasting'));
app.use('/api/governance', require('./routes/governance'));
app.use('/api/taxonomy', require('./routes/taxonomy'));
app.use('/api/sync', require('./routes/sync'));
app.use('/api/admin', require('./routes/admin'));
app.use('/api/ledger', require('./routes/ledger'));
app.use('/api/treasury', require('./routes/treasury'));
app.use('/api/search', require('./routes/search'));
app.use('/api/conflicts', require('./routes/conflicts'));
app.use('/api/forensics', require('./routes/forensics'));

app.use('/api/telemetry', require('./routes/telemetry'));
app.use('/api/vault', require('./routes/vault'));
app.use('/api/jobs', require('./routes/jobs'));






/* ================================
   STATIC FILES (ONLY DEV)
================================ */

if (process.env.NODE_ENV !== 'production') {
  const path = require('path');
  app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
}

/* ================================
   HEALTH CHECK
================================ */

app.get('/', (req, res) => {
  res.json({ status: 'Server running 🚀' });
});

/* ================================
   ERROR HANDLER
================================ */

app.use(require('./middleware/globalErrorHandler'));

/* ================================
   SERVER START (ONLY DEV)
================================ */

const PORT = process.env.PORT || 5000;

if (process.env.NODE_ENV !== 'production') {
  server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
  });
}

/* ================================
   EXPORT FOR VERCEL
================================ */

module.exports = app;

