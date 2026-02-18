# Probabilistic Cash-Flow Forecasting & Stress-Testing

## 🚀 Overview
Issue #678 upgrades the application's simple "predicted expenses" into a professional-grade **Stochastic Forecasting Engine**. It uses historical spending velocity and Monte Carlo simulations to provide a probabilistic view of future liquidity, identifying potential cash-flow cranches before they happen.

## 🏗️ Technical Architecture

### 1. Stochastic Core (`utils/simulationMath.js`)
Uses the **Box-Muller Transform** to generate random samples from a Normal Distribution based on the user's historical spending mean and standard deviation.

### 2. Monte Carlo Engine (`services/forecastingEngine.js`)
Rather than a single line on a graph, the engine runs 1,000+ potential "futures" (iterations).
- **Paths**: Each iteration creates a random walk of the user's balance over 90–365 days.
- **Aggregation**: The resulting "fan" of possibilities is aggregated into confidence intervals (P5, P50, P95).

### 3. Stress-Testing ("What-If") (`models/ForecastScenario.js`)
Users can create scenarios to stress-test their liquidity:
- **Income Loss**: Simulate a 20%, 50%, or 100% loss in income.
- **Spending Spikes**: Simulate inflation or lifestyle changes.
- **One-time Impacts**: Add specific events (e.g., "Car repair in 45 days").

### 4. Background Evolution (`jobs/forecastRetrainer.js`)
A weekly job that re-calibrates spending velocity based on the most recent 6 months of data, ensuring that as a user's habits change, their forecasts evolve automatically.

## 📊 Output Metrics

### `Risk of Insolvency`
The percentage of simulation iterations where the user's balance dropped below zero. A value > 10% triggers high-priority alerts.

### `Confidence Bands`
- **P5 (Worst Case)**: Only 5% of simulations were worse than this. Useful for conservative planning.
- **P50 (Median Case)**: The most likely outcome.
- **P95 (Best Case)**: Only 5% of simulations were better than this.

## 🛠️ API Reference

### `POST /api/forecasting/run`
Runs a simulation. Can optionally take a `scenarioId` to apply stress-test filters.

### `POST /api/forecasting/scenarios`
Creates a new saved scenario (e.g., "Recession Prep" or "House Purchase").

## ✅ Implementation Checklist
- [x] Normal Distribution sampling engine.
- [x] Monte Carlo iterator with balance path tracking.
- [x] Confidence interval (Percentile) calculation.
- [x] Scenario-based stress test parameters.
- [x] Nightly retraining background job.
- [x] Integration with `AnalyticsService` for dashboard insights.

## 🧪 Testing
Run the simulation test suite:
```bash
npx mocha tests/forecasting.test.js
```
