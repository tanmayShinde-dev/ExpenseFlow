// alertService.js
// Simple alerting utility for critical errors (e.g., email, Slack, etc.)
// For demo: logs to console. Replace with real alerting (e.g., nodemailer, webhook) as needed.

module.exports = {
  notifyAdmin: async function (subject, message) {
    // TODO: Integrate with email, SMS, or other alerting system
    console.log('[ALERT] ' + subject + ': ' + message);
    // Example: sendEmailToAdmin(subject, message);
  }
};
