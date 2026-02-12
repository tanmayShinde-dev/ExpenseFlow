// Budget service with real implementation
const Budget = require('../models/Budget');
const Goal = require('../models/Goal');
const Expense = require('../models/Expense');
const logger = require('../utils/logger');

class BudgetService {
  async checkBudgetAlerts(userId) {
    try {
      logger.info(`Checking budget alerts for user ${userId}`);

      // Get all active budgets for the user
      const budgets = await Budget.find({
        user: userId,
        isActive: true,
        endDate: { $gte: new Date() }
      });

      const alerts = [];

      for (const budget of budgets) {
        // Calculate spent amount for this budget period
        const spent = await this._calculateSpentAmount(userId, budget);

        // Update the spent field in the budget
        budget.spent = spent;
        budget.lastCalculated = new Date();
        await budget.save();

        // Check if alert threshold is exceeded
        const spentPercentage = (spent / budget.amount) * 100;
        if (spentPercentage >= budget.alertThreshold) {
          alerts.push({
            budgetId: budget._id,
            name: budget.name,
            category: budget.category,
            spent: spent,
            budgetAmount: budget.amount,
            percentage: Math.round(spentPercentage),
            threshold: budget.alertThreshold,
            remaining: Math.max(0, budget.amount - spent),
            period: budget.period
          });
        }
      }

      logger.info(`Found ${alerts.length} budget alerts for user ${userId}`);
      return { alerts };
    } catch (error) {
      logger.error(`Error checking budget alerts for user ${userId}:`, error);
      throw error;
    }
  }

  async updateGoalProgress(userId, amount, category) {
    try {
      logger.info(`Updating goal progress for user ${userId}: ${amount} in ${category}`);

      // Find active goals that match the category or are general
      const goals = await Goal.find({
        user: userId,
        status: 'active',
        isActive: true,
        $or: [
          { category: category },
          { category: 'general' }
        ]
      });

      const updates = [];

      for (const goal of goals) {
        // Update current amount
        const previousAmount = goal.currentAmount;
        goal.currentAmount += amount;

        // Check milestones
        const progressPercentage = (goal.currentAmount / goal.targetAmount) * 100;
        const achievedMilestones = [];

        for (const milestone of goal.milestones) {
          if (!milestone.achieved && progressPercentage >= milestone.percentage) {
            milestone.achieved = true;
            milestone.achievedDate = new Date();
            achievedMilestones.push(milestone);
          }
        }

        // Check if goal is completed
        if (goal.currentAmount >= goal.targetAmount && goal.status === 'active') {
          goal.status = 'completed';
        }

        await goal.save();

        updates.push({
          goalId: goal._id,
          title: goal.title,
          previousAmount: previousAmount,
          newAmount: goal.currentAmount,
          targetAmount: goal.targetAmount,
          progress: Math.round(progressPercentage),
          achievedMilestones: achievedMilestones.length,
          status: goal.status
        });
      }

      logger.info(`Updated ${updates.length} goals for user ${userId}`);
      return { success: true, updates };
    } catch (error) {
      logger.error(`Error updating goal progress for user ${userId}:`, error);
      throw error;
    }
  }

  // Helper method to calculate spent amount for a budget
  async _calculateSpentAmount(userId, budget) {
    try {
      const matchConditions = {
        user: userId,
        date: {
          $gte: budget.startDate,
          $lte: budget.endDate
        }
      };

      // Add category filter if not 'all'
      if (budget.category !== 'all') {
        matchConditions.category = budget.category;
      }

      const result = await Expense.aggregate([
        { $match: matchConditions },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]);

      return result.length > 0 ? result[0].total : 0;
    } catch (error) {
      logger.error(`Error calculating spent amount for budget ${budget._id}:`, error);
      return 0;
    }
  }
}

module.exports = new BudgetService();
