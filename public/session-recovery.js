// Session Recovery JavaScript
// Issue #881: Session Hijacking Prevention & Recovery

class SessionRecoveryManager {
    constructor() {
        this.recoveryToken = this.getQueryParam('token');
        this.hijackingEventId = this.getQueryParam('eventId');
        this.currentStep = 'verification';
        this.completedActions = new Set();
        this.codeTimer = null;
        
        this.init();
    }

    init() {
        if (!this.recoveryToken && !this.hijackingEventId) {
            this.showToast('Invalid recovery link', 'error');
            setTimeout(() => window.location.href = '/', 3000);
            return;
        }

        this.setupEventListeners();
        this.loadIncidentDetails();
        this.startCodeTimer();
    }

    setupEventListeners() {
        // Verification form
        document.getElementById('verification-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.verifyCode();
        });

        // Resend code
        document.getElementById('resend-code-btn')?.addEventListener('click', () => {
            this.resendCode();
        });

        // Action buttons
        document.querySelectorAll('.btn-action').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const action = e.target.dataset.action;
                this.handleAction(action);
            });
        });

        // Complete recovery
        document.getElementById('complete-recovery-btn')?.addEventListener('click', () => {
            this.completeRecovery();
        });

        // View forensics
        document.getElementById('view-forensics-btn')?.addEventListener('click', () => {
            this.viewForensics();
        });

        // Change password form
        document.getElementById('change-password-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.changePassword();
        });

        // Password strength check
        document.getElementById('new-password')?.addEventListener('input', (e) => {
            this.checkPasswordStrength(e.target.value);
        });

        // Modal close buttons
        document.querySelectorAll('.close').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.target.closest('.modal').classList.remove('active');
            });
        });

        // Close modal on outside click
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.remove('active');
                }
            });
        });
    }

    async loadIncidentDetails() {
        try {
            // In a real implementation, this would fetch from API
            // For now, using URL params or mock data
            
            const mockDetails = {
                detectionTime: new Date().toLocaleString(),
                riskScore: '85/100 (High)',
                suspiciousLocation: 'Moscow, Russia',
                detectionMethod: 'Impossible Location + Device Swap'
            };

            document.getElementById('detection-time').textContent = mockDetails.detectionTime;
            document.getElementById('risk-score').textContent = mockDetails.riskScore;
            document.getElementById('suspicious-location').textContent = mockDetails.suspiciousLocation;
            document.getElementById('detection-method').textContent = mockDetails.detectionMethod;
        } catch (error) {
            console.error('Failed to load incident details:', error);
        }
    }

    async verifyCode() {
        const code = document.getElementById('verification-code').value;
        const btn = document.getElementById('verify-btn');

        if (!code || code.length !== 6) {
            this.showToast('Please enter a valid 6-digit code', 'error');
            return;
        }

        btn.disabled = true;
        btn.textContent = 'Verifying...';

        try {
            const response = await fetch('/api/session-recovery/verify-step-up', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    recoveryToken: this.recoveryToken,
                    code: code,
                    method: 'EMAIL_CODE'
                })
            });

            const data = await response.json();

            if (data.success) {
                this.showToast('Identity verified successfully!', 'success');
                this.recoveryToken = data.recoveryToken;
                this.goToStep('actions');
                this.stopCodeTimer();
            } else {
                this.showToast(data.message || 'Verification failed', 'error');
                if (data.attemptsRemaining !== undefined) {
                    this.showToast(`${data.attemptsRemaining} attempts remaining`, 'info');
                }
            }
        } catch (error) {
            console.error('Verification error:', error);
            this.showToast('Verification failed. Please try again.', 'error');
        } finally {
            btn.disabled = false;
            btn.textContent = 'Verify Identity';
        }
    }

    async resendCode() {
        const btn = document.getElementById('resend-code-btn');
        btn.disabled = true;
        btn.textContent = 'Sending...';

        try {
            const response = await fetch('/api/session-recovery/resend-code', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    recoveryToken: this.recoveryToken
                })
            });

            const data = await response.json();

            if (data.success) {
                this.showToast('Verification code resent to your email', 'success');
                this.startCodeTimer(data.expiresIn * 60);
            } else {
                this.showToast(data.message || 'Failed to resend code', 'error');
            }
        } catch (error) {
            console.error('Resend error:', error);
            this.showToast('Failed to resend code', 'error');
        } finally {
            btn.disabled = false;
            btn.textContent = 'Resend Code';
        }
    }

    async handleAction(action) {
        switch (action) {
            case 'change-password':
                this.showModal('change-password-modal');
                break;
            case 'revoke-sessions':
                await this.revokeSessions();
                break;
            case 'enable-2fa':
                await this.enable2FA();
                break;
            case 'review-log':
                await this.reviewSecurityLog();
                break;
        }
    }

    async changePassword() {
        const newPassword = document.getElementById('new-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;

        if (newPassword !== confirmPassword) {
            this.showToast('Passwords do not match', 'error');
            return;
        }

        if (newPassword.length < 8) {
            this.showToast('Password must be at least 8 characters', 'error');
            return;
        }

        try {
            const response = await fetch('/api/session-recovery/change-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Recovery-Token': this.recoveryToken
                },
                body: JSON.stringify({
                    newPassword,
                    confirmPassword
                })
            });

            const data = await response.json();

            if (data.success) {
                this.showToast('Password changed successfully!', 'success');
                this.markActionComplete('change-password');
                this.hideModal('change-password-modal');
                document.getElementById('change-password-form').reset();
            } else {
                this.showToast(data.message || 'Failed to change password', 'error');
            }
        } catch (error) {
            console.error('Change password error:', error);
            this.showToast('Failed to change password', 'error');
        }
    }

    async revokeSessions() {
        if (!confirm('This will sign you out from all devices. Continue?')) {
            return;
        }

        try {
            const response = await fetch('/api/session-recovery/revoke-sessions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Recovery-Token': this.recoveryToken
                }
            });

            const data = await response.json();

            if (data.success) {
                this.showToast(`All sessions revoked (${data.result.revokedCount} sessions)`, 'success');
                this.markActionComplete('revoke-sessions');
            } else {
                this.showToast(data.message || 'Failed to revoke sessions', 'error');
            }
        } catch (error) {
            console.error('Revoke sessions error:', error);
            this.showToast('Failed to revoke sessions', 'error');
        }
    }

    async enable2FA() {
        try {
            const response = await fetch('/api/session-recovery/enable-2fa', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Recovery-Token': this.recoveryToken
                }
            });

            const data = await response.json();

            if (data.success) {
                this.showToast('Two-factor authentication enabled!', 'success');
                this.markActionComplete('enable-2fa');
                
                if (data.result.secret) {
                    this.showToast('Please save your 2FA backup codes', 'info');
                }
            } else {
                this.showToast(data.message || 'Failed to enable 2FA', 'error');
            }
        } catch (error) {
            console.error('Enable 2FA error:', error);
            this.showToast('Failed to enable 2FA', 'error');
        }
    }

    async reviewSecurityLog() {
        try {
            const response = await fetch('/api/session-recovery/security-log', {
                method: 'GET',
                headers: {
                    'X-Recovery-Token': this.recoveryToken
                }
            });

            const data = await response.json();

            if (data.success) {
                this.displaySecurityLog(data.events);
                this.showModal('security-log-modal');
                this.markActionComplete('review-log');
            } else {
                this.showToast(data.message || 'Failed to load security log', 'error');
            }
        } catch (error) {
            console.error('Review log error:', error);
            this.showToast('Failed to load security log', 'error');
        }
    }

    displaySecurityLog(events) {
        const container = document.getElementById('security-log-content');
        container.innerHTML = '';

        if (!events || events.length === 0) {
            container.innerHTML = '<p style="text-align: center; color: #718096;">No recent events</p>';
            return;
        }

        events.forEach(event => {
            const logItem = document.createElement('div');
            logItem.className = `log-item ${event.severity}`;
            logItem.innerHTML = `
                <div class="log-header">
                    <span class="log-type">${this.formatEventType(event.eventType)}</span>
                    <span class="log-time">${new Date(event.createdAt).toLocaleString()}</span>
                </div>
                <div class="log-details">
                    IP: ${event.ipAddress || 'N/A'}<br>
                    ${event.details ? this.formatEventDetails(event.details) : ''}
                </div>
            `;
            container.appendChild(logItem);
        });
    }

    formatEventType(type) {
        return type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    formatEventDetails(details) {
        if (typeof details === 'string') return details;
        if (typeof details === 'object') {
            return Object.entries(details)
                .map(([key, value]) => `${key}: ${value}`)
                .join(', ');
        }
        return '';
    }

    async completeRecovery() {
        if (this.completedActions.size < 2) {
            this.showToast('Please complete at least 2 security actions', 'info');
            return;
        }

        try {
            const response = await fetch('/api/session-recovery/complete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Recovery-Token': this.recoveryToken
                }
            });

            const data = await response.json();

            if (data.success) {
                this.showToast('Recovery completed successfully!', 'success');
                this.goToStep('complete');
            } else {
                this.showToast(data.message || 'Failed to complete recovery', 'error');
            }
        } catch (error) {
            console.error('Complete recovery error:', error);
            this.showToast('Failed to complete recovery', 'error');
        }
    }

    async viewForensics() {
        try {
            const response = await fetch(`/api/session-recovery/forensics/${this.hijackingEventId}`, {
                method: 'GET',
                headers: {
                    'X-Recovery-Token': this.recoveryToken
                }
            });

            const data = await response.json();

            if (data.success) {
                this.displayForensics(data.report);
                this.showModal('forensics-modal');
            } else {
                this.showToast(data.message || 'Failed to load forensic report', 'error');
            }
        } catch (error) {
            console.error('View forensics error:', error);
            this.showToast('Failed to load forensic report', 'error');
        }
    }

    displayForensics(report) {
        const container = document.getElementById('forensics-content');
        container.innerHTML = `
            <div class="forensics-section">
                <h4>Detection Summary</h4>
                <p><strong>Detection Method:</strong> ${report.detection.detectionMethod}</p>
                <p><strong>Risk Score:</strong> ${report.detection.riskScore}/100</p>
                <p><strong>Confidence Level:</strong> ${(report.detection.confidenceLevel * 100).toFixed(0)}%</p>
                <p><strong>Indicators:</strong> ${report.detection.indicators.length}</p>
            </div>

            <div class="forensics-section">
                <h4>Session Information</h4>
                <p><strong>Original IP:</strong> ${report.session.originalIP}</p>
                <p><strong>Suspicious IP:</strong> ${report.session.suspiciousIP}</p>
                <p><strong>Original Location:</strong> ${report.session.originalLocation?.city}, ${report.session.originalLocation?.country}</p>
                <p><strong>Suspicious Location:</strong> ${report.session.suspiciousLocation?.city}, ${report.session.suspiciousLocation?.country}</p>
            </div>

            <div class="forensics-section">
                <h4>Analysis</h4>
                <p>${report.analysis.summary}</p>
                <p><strong>Attack Vector:</strong> ${report.analysis.attackVector}</p>
                <p><strong>Impact:</strong> ${report.analysis.impactAssessment}</p>
            </div>

            <div class="forensics-section">
                <h4>Recommendations</h4>
                <ul>
                    ${report.recommendations.map(r => `
                        <li><strong>${r.recommendation}</strong> - ${r.action}</li>
                    `).join('')}
                </ul>
            </div>
        `;
    }

    markActionComplete(action) {
        this.completedActions.add(action);
        
        // Update UI
        const item = document.querySelector(`.action-item[data-action="${action}"]`);
        if (item) {
            item.classList.add('completed');
            item.querySelector('.status-icon.incomplete').style.display = 'none';
            item.querySelector('.status-icon.complete').style.display = 'flex';
            item.querySelector('.btn-action').disabled = true;
            item.querySelector('.btn-action').textContent = 'Completed';
        }

        // Update progress
        this.updateProgress();
    }

    updateProgress() {
        const total = 4;
        const completed = this.completedActions.size;
        const percentage = (completed / total) * 100;

        document.getElementById('recovery-progress').style.width = `${percentage}%`;
        document.getElementById('completed-count').textContent = completed;

        // Enable complete button if minimum actions are done
        const completeBtn = document.getElementById('complete-recovery-btn');
        if (completed >= 2) {
            completeBtn.disabled = false;
        }
    }

    goToStep(step) {
        // Hide all steps
        document.querySelectorAll('.recovery-step').forEach(s => s.classList.remove('active'));
        
        // Show target step
        document.getElementById(`step-${step}`).classList.add('active');
        
        this.currentStep = step;
    }

    showModal(modalId) {
        document.getElementById(modalId).classList.add('active');
    }

    hideModal(modalId) {
        document.getElementById(modalId).classList.remove('active');
    }

    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icon = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ';
        
        toast.innerHTML = `
            <span class="toast-icon">${icon}</span>
            <span class="toast-message">${message}</span>
        `;

        const container = document.getElementById('toast-container');
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, 5000);
    }

    startCodeTimer(seconds = 600) {
        this.stopCodeTimer();
        
        let timeLeft = seconds;
        const timerElement = document.getElementById('code-timer');

        this.codeTimer = setInterval(() => {
            timeLeft--;
            
            const minutes = Math.floor(timeLeft / 60);
            const secs = timeLeft % 60;
            timerElement.textContent = `${minutes}:${secs.toString().padStart(2, '0')}`;

            if (timeLeft <= 0) {
                this.stopCodeTimer();
                timerElement.textContent = 'Expired';
                timerElement.style.color = '#ef4444';
            }
        }, 1000);
    }

    stopCodeTimer() {
        if (this.codeTimer) {
            clearInterval(this.codeTimer);
            this.codeTimer = null;
        }
    }

    checkPasswordStrength(password) {
        const strengthBar = document.getElementById('strength-bar');
        const strengthText = document.getElementById('strength-text');

        let strength = 0;
        
        if (password.length >= 8) strength++;
        if (password.length >= 12) strength++;
        if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
        if (/\d/.test(password)) strength++;
        if (/[^a-zA-Z0-9]/.test(password)) strength++;

        strengthBar.className = 'strength-bar';
        
        if (strength <= 2) {
            strengthBar.classList.add('weak');
            strengthText.textContent = 'Weak';
            strengthText.style.color = '#ef4444';
        } else if (strength <= 3) {
            strengthBar.classList.add('medium');
            strengthText.textContent = 'Medium';
            strengthText.style.color = '#f59e0b';
        } else {
            strengthBar.classList.add('strong');
            strengthText.textContent = 'Strong';
            strengthText.style.color = '#10b981';
        }
    }

    getQueryParam(name) {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get(name);
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.recoveryManager = new SessionRecoveryManager();
});
