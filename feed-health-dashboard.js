/**
 * Feed Health Dashboard UI
 * Real-time visualization of feed reliability, provider health, and alerts
 */

class FeedHealthDashboard {
  constructor() {
    this.config = {
      refreshInterval: 30000, // 30 seconds
      chartUpdateInterval: 60000, // 1 minute
      alertDisplayTime: 10000 // 10 seconds
    };

    this.dashboardData = {
      feeds: [],
      providers: [],
      alerts: [],
      stats: {}
    };

    this.charts = new Map();
    this.refreshTimers = new Map();
  }

  /**
   * Initialize dashboard
   */
  async init() {
    try {
      this.createDashboardLayout();
      await this.loadInitialData();
      this.startAutoRefresh();

      console.log('[FeedHealthDashboard] Initialized');
      return true;

    } catch (error) {
      console.error('[FeedHealthDashboard] Init error:', error);
      return false;
    }
  }

  /**
   * Create dashboard layout
   */
  createDashboardLayout() {
    const container = document.getElementById('feed-health-dashboard');

    if (!container) {
      console.error('[FeedHealthDashboard] Container not found');
      return;
    }

    container.innerHTML = `
      <div class="feed-health-container">
        <!-- Header -->
        <div class="fh-header">
          <h1>Feed Health & Resilience Monitor</h1>
          <div class="fh-controls">
            <button id="fh-refresh-btn" class="btn btn-primary">
              Refresh Now
            </button>
            <button id="fh-settings-btn" class="btn btn-secondary">
              Settings
            </button>
          </div>
        </div>

        <!-- Overall Health Summary -->
        <div class="fh-summary-grid">
          <div class="fh-summary-card">
            <div class="summary-label">Total Feeds</div>
            <div class="summary-value" id="fh-total-feeds">-</div>
            <div class="summary-trend" id="fh-feeds-trend"></div>
          </div>

          <div class="fh-summary-card">
            <div class="summary-label">Healthy</div>
            <div class="summary-value healthy" id="fh-healthy-feeds">-</div>
            <div class="summary-percent" id="fh-healthy-percent">-</div>
          </div>

          <div class="fh-summary-card">
            <div class="summary-label">Safe Mode</div>
            <div class="summary-value warning" id="fh-safe-mode-count">-</div>
            <div class="summary-percent" id="fh-safe-mode-percent">-</div>
          </div>

          <div class="fh-summary-card">
            <div class="summary-label">Critical</div>
            <div class="summary-value critical" id="fh-critical-count">-</div>
            <div class="summary-percent" id="fh-critical-percent">-</div>
          </div>

          <div class="fh-summary-card">
            <div class="summary-label">Provider Health</div>
            <div class="summary-value" id="fh-avg-provider-health">-</div>
            <div class="summary-trend" id="fh-provider-trend"></div>
          </div>

          <div class="fh-summary-card">
            <div class="summary-label">Active Alerts</div>
            <div class="summary-value alert" id="fh-active-alerts">-</div>
            <div class="summary-trend" id="fh-alerts-trend"></div>
          </div>
        </div>

        <!-- Tabs -->
        <div class="fh-tabs">
          <button class="fh-tab-btn active" data-tab="feeds-tab">
            Feeds
          </button>
          <button class="fh-tab-btn" data-tab="providers-tab">
            Providers
          </button>
          <button class="fh-tab-btn" data-tab="consensus-tab">
            Consensus
          </button>
          <button class="fh-tab-btn" data-tab="alerts-tab">
            Alerts
          </button>
          <button class="fh-tab-btn" data-tab="drift-tab">
            Drift
          </button>
        </div>

        <!-- Feeds Tab -->
        <div id="feeds-tab" class="fh-tab-content active">
          <div class="fh-section">
            <h2>Feed Status</h2>
            <div class="fh-feeds-list" id="fh-feeds-list">
              <!-- Populated dynamically -->
            </div>
          </div>
        </div>

        <!-- Providers Tab -->
        <div id="providers-tab" class="fh-tab-content">
          <div class="fh-section">
            <h2>Provider Rankings</h2>
            <div class="fh-provider-ranking" id="fh-provider-ranking">
              <!-- Populated dynamically -->
            </div>
          </div>

          <div class="fh-section">
            <h2>Provider Health Scores</h2>
            <div id="fh-provider-chart" style="height: 400px;"></div>
          </div>
        </div>

        <!-- Consensus Tab -->
        <div id="consensus-tab" class="fh-tab-content">
          <div class="fh-section">
            <h2>Consensus Statistics</h2>
            <div id="fh-consensus-stats" class="fh-stats-grid">
              <!-- Populated dynamically -->
            </div>
          </div>

          <div class="fh-section">
            <h2>Conflict Trends</h2>
            <div id="fh-conflict-chart" style="height: 300px;"></div>
          </div>
        </div>

        <!-- Alerts Tab -->
        <div id="alerts-tab" class="fh-tab-content">
          <div class="fh-section">
            <h2>Recent Alerts</h2>
            <div class="fh-alerts-list" id="fh-alerts-list">
              <!-- Populated dynamically -->
            </div>
          </div>
        </div>

        <!-- Drift Tab -->
        <div id="drift-tab" class="fh-tab-content">
          <div class="fh-section">
            <h2>Drift-Detected Feeds</h2>
            <div id="fh-drift-feeds" class="fh-drift-list">
              <!-- Populated dynamically -->
            </div>
          </div>

          <div class="fh-section">
            <h2>Drift Patterns</h2>
            <div id="fh-drift-chart" style="height: 300px;"></div>
          </div>
        </div>

        <!-- Safe Mode Panel -->
        <div class="fh-safe-mode-panel">
          <h3>Safe Mode Status</h3>
          <div id="fh-safe-mode-status" class="fh-safe-mode-list">
            <!-- Populated dynamically -->
          </div>
        </div>
      </div>
    `;

    this.attachEventListeners();
  }

  /**
   * Attach event listeners
   */
  attachEventListeners() {
    // Refresh button
    document.getElementById('fh-refresh-btn')?.addEventListener('click', () => {
      this.refresh();
    });

    // Tab buttons
    document.querySelectorAll('.fh-tab-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        this.switchTab(e.target.dataset.tab);
      });
    });
  }

  /**
   * Load initial dashboard data
   */
  async loadInitialData() {
    try {
      const [feedsResp, providersResp] = await Promise.all([
        fetch('/api/feed-health/feeds'),
        fetch('/api/feed-health/providers')
      ]);

      const feeds = await feedsResp.json();
      const providers = await providersResp.json();

      this.dashboardData.feeds = feeds.feeds || [];
      this.dashboardData.providers = providers.providers || [];

      this.renderDashboard();

    } catch (error) {
      console.error('[FeedHealthDashboard] Load error:', error);
      this.showError('Failed to load dashboard data');
    }
  }

  /**
   * Render entire dashboard
   */
  renderDashboard() {
    this.renderSummary();
    this.renderFeedsTab();
    this.renderProvidersTab();
    this.renderConsensusTab();
    this.renderAlertsTab();
    this.renderDriftTab();
    this.renderSafeModePanel();
  }

  /**
   * Render summary cards
   */
  renderSummary() {
    const feeds = this.dashboardData.feeds;

    const healthy = feeds.filter(f => f.healthStatus === 'EXCELLENT' || f.healthStatus === 'GOOD').length;
    const safeMode = feeds.filter(f => f.safeMode.enabled).length;
    const critical = feeds.filter(f => f.healthStatus === 'CRITICAL').length;

    const avgHealth = feeds.length > 0
      ? (feeds.reduce((sum, f) => sum + f.overallHealth, 0) / feeds.length).toFixed(0)
      : 0;

    const avgProviderHealth = this.dashboardData.providers.length > 0
      ? (this.dashboardData.providers.reduce((sum, p) => sum + p.healthScore, 0) / this.dashboardData.providers.length).toFixed(0)
      : 0;

    // Update DOM
    document.getElementById('fh-total-feeds').textContent = feeds.length;
    document.getElementById('fh-healthy-feeds').textContent = healthy;
    document.getElementById('fh-healthy-percent').textContent = feeds.length > 0 ? `${(healthy / feeds.length * 100).toFixed(0)}%` : '-';
    document.getElementById('fh-safe-mode-count').textContent = safeMode;
    document.getElementById('fh-safe-mode-percent').textContent = feeds.length > 0 ? `${(safeMode / feeds.length * 100).toFixed(0)}%` : '-';
    document.getElementById('fh-critical-count').textContent = critical;
    document.getElementById('fh-critical-percent').textContent = feeds.length > 0 ? `${(critical / feeds.length * 100).toFixed(0)}%` : '-';
    document.getElementById('fh-avg-provider-health').textContent = `${avgProviderHealth}%`;
  }

  /**
   * Render feeds tab
   */
  renderFeedsTab() {
    const feedsList = document.getElementById('fh-feeds-list');
    const feeds = this.dashboardData.feeds;

    feedsList.innerHTML = feeds.map(feed => `
      <div class="fh-feed-card ${feed.healthStatus.toLowerCase()}">
        <div class="fh-feed-header">
          <span class="fh-feed-id">${feed.feedId}</span>
          <span class="fh-health-badge">${feed.healthStatus}</span>
          ${feed.safeMode.enabled ? '<span class="fh-safe-mode-badge">SAFE MODE</span>' : ''}
          ${feed.drift.detected ? '<span class="fh-drift-badge">DRIFT</span>' : ''}
        </div>

        <div class="fh-feed-metrics">
          <div class="metric">
            <span class="label">Health:</span>
            <div class="health-bar">
              <div class="health-fill" style="width: ${feed.overallHealth}%"></div>
            </div>
            <span class="value">${feed.overallHealth}%</span>
          </div>

          <div class="metric">
            <span class="label">Agreement:</span>
            <span class="value">${feed.consensus.agreementRate}%</span>
          </div>

          <div class="metric">
            <span class="label">Conflicts:</span>
            <span class="value">${feed.consensus.conflictCount}</span>
          </div>

          <div class="metric">
            <span class="label">Alerts:</span>
            <span class="value alert">${feed.alerts}</span>
          </div>
        </div>

        <div class="fh-feed-actions">
          <button class="btn btn-xs btn-secondary" onclick="feedHealthDashboard.viewFeedDetails('${feed.feedId}')">
            Details
          </button>
          ${!feed.safeMode.enabled ? `
            <button class="btn btn-xs btn-warning" onclick="feedHealthDashboard.activateSafeMode('${feed.feedId}')">
              Activate Safe Mode
            </button>
          ` : `
            <button class="btn btn-xs btn-success" onclick="feedHealthDashboard.deactivateSafeMode('${feed.feedId}')">
              Deactivate Safe Mode
            </button>
          `}
        </div>
      </div>
    `).join('');
  }

  /**
   * Render providers tab
   */
  renderProvidersTab() {
    const ranking = document.getElementById('fh-provider-ranking');
    const providers = this.dashboardData.providers.sort((a, b) => b.healthScore - a.healthScore);

    ranking.innerHTML = providers.map((provider, index) => `
      <div class="fh-provider-row">
        <span class="rank">#${index + 1}</span>
        <span class="provider-id">${provider.providerId}</span>
        <span class="provider-type">${provider.type}</span>
        <div class="health-bar" style="flex: 1; margin: 0 15px;">
          <div class="health-fill" style="width: ${provider.healthScore}%"></div>
        </div>
        <span class="health-score">${provider.healthScore.toFixed(1)}%</span>
        <span class="status-badge ${provider.status.toLowerCase()}">${provider.status}</span>
      </div>
    `).join('');
  }

  /**
   * Render consensus tab
   */
  renderConsensusTab() {
    const statsContainer = document.getElementById('fh-consensus-stats');

    const avgAgreement = this.dashboardData.feeds.length > 0
      ? (this.dashboardData.feeds.reduce((sum, f) => sum + f.consensus.agreementRate, 0) / this.dashboardData.feeds.length).toFixed(1)
      : 0;

    const totalConflicts = this.dashboardData.feeds.reduce((sum, f) => sum + f.consensus.conflictCount, 0);

    statsContainer.innerHTML = `
      <div class="stat-card">
        <div class="stat-value">${avgAgreement}%</div>
        <div class="stat-label">Avg Agreement</div>
      </div>

      <div class="stat-card">
        <div class="stat-value">${totalConflicts}</div>
        <div class="stat-label">Total Conflicts</div>
      </div>

      <div class="stat-card">
        <div class="stat-value">${this.dashboardData.feeds.length}</div>
        <div class="stat-label">Feeds Monitored</div>
      </div>

      <div class="stat-card">
        <div class="stat-value">${this.dashboardData.providers.length}</div>
        <div class="stat-label">Providers</div>
      </div>
    `;
  }

  /**
   * Render alerts tab
   */
  renderAlertsTab() {
    const alertsList = document.getElementById('fh-alerts-list');

    const allAlerts = [];
    this.dashboardData.feeds.forEach(feed => {
      if (feed.alerts && Array.isArray(feed.alerts)) {
        feed.alerts.forEach(alert => {
          allAlerts.push({
            ...alert,
            feedId: feed.feedId
          });
        });
      }
    });

    alertsList.innerHTML = allAlerts.slice(0, 20).map(alert => `
      <div class="fh-alert-item ${alert.severity?.toLowerCase() || 'info'}">
        <div class="alert-header">
          <span class="severity-badge">${alert.severity || 'INFO'}</span>
          <span class="alert-type">${alert.type || 'Unknown'}</span>
          <span class="feed-id">${alert.feedId}</span>
        </div>
        <div class="alert-message">${alert.message || ''}</div>
        <div class="alert-time">${new Date(alert.timestamp).toLocaleString()}</div>
      </div>
    `).join('');

    if (allAlerts.length === 0) {
      alertsList.innerHTML = '<div class="empty-state">No alerts</div>';
    }
  }

  /**
   * Render drift tab
   */
  renderDriftTab() {
    const driftFeedsContainer = document.getElementById('fh-drift-feeds');

    const driftFeeds = this.dashboardData.feeds.filter(f => f.drift.detected);

    driftFeedsContainer.innerHTML = driftFeeds.map(feed => `
      <div class="fh-drift-card">
        <div class="drift-header">
          <span class="feed-id">${feed.feedId}</span>
          <span class="drift-pct">${feed.drift.percentage}%</span>
        </div>
        <div class="drift-message">
          Data drift detected - ${feed.drift.percentage}% deviation from baseline
        </div>
        <button class="btn btn-xs btn-secondary" onclick="feedHealthDashboard.investigateDrift('${feed.feedId}')">
          Investigate
        </button>
      </div>
    `).join('');

    if (driftFeeds.length === 0) {
      driftFeedsContainer.innerHTML = '<div class="empty-state">No drift detected</div>';
    }
  }

  /**
   * Render safe mode panel
   */
  renderSafeModePanel() {
    const safeModeStatus = document.getElementById('fh-safe-mode-status');

    const safeModeFeeds = this.dashboardData.feeds.filter(f => f.safeMode.enabled);

    safeModeStatus.innerHTML = safeModeFeeds.map(feed => `
      <div class="safe-mode-item">
        <div class="sm-header">
          <span class="feed-id">${feed.feedId}</span>
          <span class="provider">${feed.safeMode.fallbackProvider}</span>
          <span class="mode">${feed.safeMode.mode || 'CONSERVATIVE'}</span>
        </div>
        <div class="sm-reason">${feed.safeMode.reason}</div>
      </div>
    `).join('');

    if (safeModeFeeds.length === 0) {
      safeModeStatus.innerHTML = '<div class="empty-state">No feeds in safe mode</div>';
    }
  }

  /**
   * Switch tab
   */
  switchTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.fh-tab-content').forEach(tab => {
      tab.classList.remove('active');
    });

    // Deactivate all buttons
    document.querySelectorAll('.fh-tab-btn').forEach(btn => {
      btn.classList.remove('active');
    });

    // Show selected tab
    document.getElementById(tabName)?.classList.add('active');
    document.querySelector(`[data-tab="${tabName}"]`)?.classList.add('active');
  }

  /**
   * Activate safe mode for feed
   */
  async activateSafeMode(feedId) {
    try {
      const response = await fetch(
        `/api/feed-health/feeds/${feedId}/safe-mode/activate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reason: 'Manual activation',
            mode: 'CONSERVATIVE'
          })
        }
      );

      const result = await response.json();

      if (result.success) {
        this.showSuccess(`Safe mode activated for ${feedId}`);
        await this.refresh();
      } else {
        this.showError(result.error);
      }

    } catch (error) {
      this.showError(`Failed to activate safe mode: ${error.message}`);
    }
  }

  /**
   * Deactivate safe mode
   */
  async deactivateSafeMode(feedId) {
    try {
      const response = await fetch(
        `/api/feed-health/feeds/${feedId}/safe-mode/deactivate`,
        { method: 'POST' }
      );

      const result = await response.json();

      if (result.success) {
        this.showSuccess(`Safe mode deactivated for ${feedId}`);
        await this.refresh();
      } else {
        this.showError(result.error);
      }

    } catch (error) {
      this.showError(`Failed to deactivate safe mode: ${error.message}`);
    }
  }

  /**
   * View feed details (placeholder)
   */
  viewFeedDetails(feedId) {
    console.log(`[FeedHealthDashboard] View details for ${feedId}`);
    // Would open detailed view
  }

  /**
   * Investigate drift (placeholder)
   */
  investigateDrift(feedId) {
    console.log(`[FeedHealthDashboard] Investigate drift for ${feedId}`);
    // Would open drift analysis
  }

  /**
   * Refresh dashboard
   */
  async refresh() {
    await this.loadInitialData();
    this.showSuccess('Dashboard refreshed');
  }

  /**
   * Start auto-refresh
   */
  startAutoRefresh() {
    const timer = setInterval(() => {
      this.refresh();
    }, this.config.refreshInterval);

    this.refreshTimers.set('main', timer);
  }

  /**
   * Show success message
   */
  showSuccess(message) {
    console.log(`[FeedHealthDashboard] Success: ${message}`);
    // Would show toast notification
  }

  /**
   * Show error message
   */
  showError(message) {
    console.error(`[FeedHealthDashboard] Error: ${message}`);
    // Would show error notification
  }
}

// Global instance
const feedHealthDashboard = new FeedHealthDashboard();

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  feedHealthDashboard.init();
});
