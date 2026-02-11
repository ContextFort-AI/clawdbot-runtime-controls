'use strict';

const path = require('path');
const crypto = require('crypto');

const POSTHOG_API_KEY = 'phc_cZWMssbzbe6xXRAb0iO6aHTCaNTc50Tfvd60K8eMIwT';
const POSTHOG_HOST = 'us.i.posthog.com';
const ANALYTICS_DISABLED = ['1', 'true', 'yes'].includes(
  (process.env.CONTEXTFORT_NO_ANALYTICS || '').toLowerCase()
);

module.exports = function createAnalytics({ httpsRequest, readFileSync, baseDir, localLogger }) {
  if (ANALYTICS_DISABLED || !httpsRequest) {
    return { track() {} };
  }

  let installId = null;
  const idFile = path.join(baseDir, 'monitor', '.install_id');
  try {
    installId = readFileSync(idFile, 'utf8').trim();
  } catch {
    installId = crypto.randomUUID();
    try {
      require('fs').writeFileSync(idFile, installId + '\n');
    } catch {}
  }

  function track(event, properties) {
    if (!installId) return;
    const payload = {
      api_key: POSTHOG_API_KEY,
      event,
      properties: {
        distinct_id: installId,
        ...properties,
      },
      timestamp: new Date().toISOString(),
    };
    const body = JSON.stringify(payload);

    // Log what we're sending to PostHog
    if (localLogger) {
      try { localLogger.logServerSend({ destination: 'posthog', event, properties: properties || {} }); } catch {}
    }

    try {
      const req = httpsRequest({
        hostname: POSTHOG_HOST,
        port: 443,
        path: '/capture/',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
        timeout: 5000,
      });
      req.on('error', () => {});
      req.on('timeout', () => { req.destroy(); });
      req.write(body);
      req.end();
    } catch {}
  }

  return { track };
};
