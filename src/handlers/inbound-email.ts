/**
 * UDT Identity Provider — Inbound Email Handler
 *
 * Triggered by SES when an email is received at twin@twinsmith.ai.
 * Extracts the sender's email, calls the request-token flow, and
 * replies with their access token.
 *
 * // Why: Users should be able to send an email to get access to their
 * // Digital Twin. This is the ultimate zero-friction onboarding:
 * // send an email, get a login link back. No website visit needed
 * // for the initial request.
 *
 * @module handlers/inbound-email
 */

import { loadConfig, createKeyStore } from '../config.js';
import { isDomainAllowed } from '../domain.js';
import { generateToken, currentMonth } from '../token.js';
import { sendTokenEmail, sendRejectionEmail } from '../email.js';

// Why: Reuse key store across warm invocations.
const keyStore = createKeyStore();

/**
 * Compute the "valid through" date string.
 */
function computeValidThrough(): string {
  const now = new Date();
  const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 3);
  const monthNames = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December',
  ];
  return `${monthNames[nextMonth.getMonth()]} ${nextMonth.getDate()}, ${nextMonth.getFullYear()}`;
}

/**
 * SES inbound email event shape.
 * // Why: SES wraps the email metadata in a specific event structure.
 * // We only need the sender's email — we don't read the body at all.
 */
interface SESEvent {
  Records: Array<{
    ses: {
      mail: {
        source: string;
        commonHeaders: {
          from: string[];
          to: string[];
          subject: string;
        };
      };
      receipt: {
        recipients: string[];
      };
    };
  }>;
}

/**
 * Lambda handler for SES inbound email.
 *
 * // Why: This turns "send an email to twin@twinsmith.ai" into a fully
 * // automated token delivery. The user doesn't need to know our API
 * // endpoint or visit a website. Just send an email from your work
 * // account and you'll get a login link back.
 */
export async function handler(event: SESEvent): Promise<void> {
  console.log('Inbound email event:', JSON.stringify(event, null, 2));

  for (const record of event.Records) {
    const senderEmail = record.ses.mail.source.toLowerCase().trim();
    const recipient = record.ses.receipt.recipients[0]?.toLowerCase() || '';

    console.log(`Inbound email from ${senderEmail} to ${recipient}`);

    try {
      const config = await loadConfig();

      // Check domain
      if (!isDomainAllowed(senderEmail, config.allowedDomains)) {
        console.log(`Domain not allowed for ${senderEmail} — sending rejection`);
        await sendRejectionEmail({
          to: senderEmail,
          fromAddress: config.sesFromAddress,
          fromName: config.sesFromName,
          constellationName: config.constellationId,
          supportEmail: config.supportEmail,
        });
        continue;
      }

      // Generate token and send
      const key = await keyStore.getCurrentKey();
      const month = currentMonth();
      const token = generateToken(senderEmail, month, key, config.constellationId);
      const validThrough = computeValidThrough();

      await sendTokenEmail({
        to: senderEmail,
        token,
        constellationName: config.constellationId,
        loginUrl: config.loginUrl,
        validThrough,
        fromAddress: config.sesFromAddress,
        fromName: config.sesFromName,
      });

      console.log(`Token sent to ${senderEmail} via inbound email flow`);
    } catch (err) {
      console.error(`Error processing inbound email from ${senderEmail}:`, err);
    }
  }
}
