import { createRedactor } from '../core/redact.js';
import type { HttpClient, Logger, Notifier } from '../types.js';

function notificationText(title: string, body: string): string {
  return createRedactor().redact(`${title}\n${body}`);
}

export function createConsoleNotifier(log: Logger): Notifier {
  return {
    async notify(title, body) {
      log.info(notificationText(title, body));
    },
  };
}

export function createWebhookNotifier(url: string, http: HttpClient): Notifier {
  return {
    async notify(title, body) {
      const text = notificationText(title, body);
      try {
        const response = await http.request({
          method: 'POST',
          url,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text, content: text }),
        });
        if (response.status < 200 || response.status >= 300) throw new Error('Webhook rejected notification.');
      } catch {
        // Neither transport errors nor response bodies are safe notification diagnostics.
        throw new Error('Unable to deliver webhook notification.');
      }
    },
  };
}

export function combineNotifiers(...notifiers: Notifier[]): Notifier {
  return {
    async notify(title, body, signal) {
      const results = await Promise.allSettled(notifiers.map(notifier => notifier.notify(title, body, signal)));
      if (results.some(result => result.status === 'rejected')) {
        throw new Error('Unable to deliver one or more notifications.');
      }
    },
  };
}
