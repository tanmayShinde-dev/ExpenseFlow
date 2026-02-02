const express = require('express');
const Joi = require('joi');
const Transaction = require('../models/Transaction');
const budgetService = require('../services/budgetService');
const categorizationService = require('../services/categorizationService');
const exportService = require('../services/exportService');
const currencyService = require('../services/currencyService');
const aiService = require('../services/aiService');
const User = require('../models/User');
const auth = require('../middleware/auth');
const { ExpenseSchemas, validateRequest, validateQuery } = require('../middleware/inputValidator');
const { expenseLimiter, exportLimiter } = require('../middleware/rateLimiter');
const router = express.Router();

const expenseSchema = Joi.object({
  description: Joi.string().trim().max(100).required(),
  amount: Joi.number().min(0.01).required(),
  currency: Joi.string().uppercase().optional(),
  category: Joi.string().valid('food', 'transport', 'entertainment', 'utilities', 'healthcare', 'shopping', 'other').required(),
  type: Joi.string().valid('income', 'expense').required(),
  merchant: Joi.string().trim().max(50).optional(),
  date: Joi.date().optional(),
  workspaceId: Joi.string().hex().length(24).optional()
});

// GET all expenses (Transactions)
router.get('/', auth, validateQuery(ExpenseSchemas.filter), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;

    const user = await User.findById(req.user._id);
    const workspaceId = req.query.workspaceId;
    const query = workspaceId
      ? { workspace: workspaceId }
      : { user: req.user._id, workspace: null };

    const total = await Transaction.countDocuments(query);

    const expenses = await Transaction.find(query)
      .sort({ date: -1 })
      .skip(skip)
      .limit(limit);

    // Convert to user preference
    const convertedExpenses = await Promise.all(expenses.map(async (expense) => {
      const expenseObj = expense.toObject();
      if (expenseObj.originalCurrency !== user.preferredCurrency) {
        try {
          const conversion = await currencyService.convertCurrency(
            expenseObj.originalAmount,
            expenseObj.originalCurrency,
            user.preferredCurrency
          );
          expenseObj.displayAmount = conversion.convertedAmount;
          expenseObj.displayCurrency = user.preferredCurrency;
        } catch (error) {
          expenseObj.displayAmount = expenseObj.amount;
          expenseObj.displayCurrency = expenseObj.originalCurrency;
        }
      } else {
        expenseObj.displayAmount = expenseObj.amount;
        expenseObj.displayCurrency = expenseObj.originalCurrency;
      }
      return expenseObj;
    }));

    res.json({
      success: true,
      data: convertedExpenses,
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST new expense (Transaction)
router.post('/', auth, expenseLimiter, validateRequest(ExpenseSchemas.create), async (req, res) => {
  try {
    // Use the new TransactionService but maintain expected response format
    const transactionService = require('../services/transactionService');
    const io = req.app.get('io');

    // Create transaction
    const transaction = await transactionService.createTransaction(req.body, req.user._id, io);

    const user = await User.findById(req.user._id);
    const response = transaction.toObject();

    if (response.originalCurrency !== user.preferredCurrency && response.convertedAmount) {
      response.displayAmount = response.convertedAmount;
      response.displayCurrency = user.preferredCurrency;
    } else {
      response.displayAmount = response.amount;
      response.displayCurrency = response.originalCurrency;
    }

    res.status(201).json(response);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT update expense
router.put('/:id', auth, async (req, res) => {
  try {
    const transaction = await Transaction.findOne({ _id: req.params.id, user: req.user._id });
    if (!transaction) return res.status(404).json({ error: 'Expense not found' });

    if (req.body.amount && req.body.type === 'expense') {
      const oldAmount = transaction.convertedAmount || transaction.amount;
      await budgetService.updateGoalProgress(req.user._id, oldAmount, transaction.category);
    }

    Object.assign(transaction, req.body);

    if (req.body.amount || req.body.currency) {
      const user = await User.findById(req.user._id);
      const currency = req.body.currency || transaction.originalCurrency || 'INR';
      if (currency !== user.preferredCurrency) {
        const conversion = await currencyService.convertCurrency(req.body.amount || transaction.amount, currency, user.preferredCurrency);
        transaction.convertedAmount = conversion.convertedAmount;
        transaction.convertedCurrency = user.preferredCurrency;
        transaction.exchangeRate = conversion.exchangeRate;
      }
      transaction.originalAmount = req.body.amount || transaction.amount;
      transaction.originalCurrency = currency;
    }

    await transaction.save();

    if (req.body.amount && req.body.type === 'expense') {
      const newAmount = transaction.convertedAmount || transaction.amount;
      await budgetService.updateGoalProgress(req.user._id, -newAmount, transaction.category);
    }

    res.json(transaction);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE expense
router.delete('/:id', auth, async (req, res) => {
  try {
    const transaction = await Transaction.findOneAndDelete({ _id: req.params.id, user: req.user._id });
    if (!transaction) return res.status(404).json({ error: 'Expense not found' });

    if (transaction.type === 'expense') {
      const amount = transaction.convertedAmount || transaction.amount;
      await budgetService.updateGoalProgress(req.user._id, amount, transaction.category);
    }

    res.json({ message: 'Expense deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;