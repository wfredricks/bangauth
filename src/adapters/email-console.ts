/**
 * BangAuth — Console Email Adapter
 *
 * Prints emails to stdout instead of sending them. Perfect for development,
 * demos, and constellation MVP where you want to see the access codes in logs.
 *
 * // Why: Email delivery is slow, complex, and costs money. For dev/demo mode,
 * // just printing the code to the console is instant, free, and perfect for
 * // testing. In production Docker logs, you can still see the codes fly by.
 *
 * @module adapters/email-console
 */

import type { SendTokenEmailParams, SendRejectionEmailParams, SendResetEmailParams } from '../types.js';

/**
 * Console email adapter — prints to stdout instead of sending.
 */
export class ConsoleEmailAdapter {
  /**
   * Print a token email to console.
   *
   * // Why: The access code is the most important part — extract it and make
   * // it obvious in the logs. The rest is informational.
   */
  async sendTokenEmail(params: SendTokenEmailParams): Promise<void> {
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('📧  TOKEN EMAIL (console adapter — not actually sent)');
    console.log('═══════════════════════════════════════════════════════════');
    console.log(`To: ${params.to}`);
    console.log(`Subject: ${params.constellationName} Access Token`);
    console.log('───────────────────────────────────────────────────────────');
    console.log('🔑  ACCESS TOKEN:');
    console.log(`    ${params.token}`);
    console.log('───────────────────────────────────────────────────────────');
    console.log(`Login URL: ${params.loginUrl}`);
    console.log(`Valid through: ${params.validThrough}`);
    console.log('═══════════════════════════════════════════════════════════\n');
  }

  /**
   * Print a rejection email to console.
   */
  async sendRejectionEmail(params: SendRejectionEmailParams): Promise<void> {
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('❌  REJECTION EMAIL (console adapter — not actually sent)');
    console.log('═══════════════════════════════════════════════════════════');
    console.log(`To: ${params.to}`);
    console.log(`Subject: ${params.constellationName} — Access Request`);
    console.log('───────────────────────────────────────────────────────────');
    console.log('Your email domain is not authorized for this constellation.');
    if (params.supportEmail) {
      console.log(`Contact: ${params.supportEmail}`);
    }
    console.log('═══════════════════════════════════════════════════════════\n');
  }

  /**
   * Print an MFA reset email to console.
   */
  async sendMfaResetEmail(params: SendResetEmailParams): Promise<void> {
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('🔄  MFA RESET EMAIL (console adapter — not actually sent)');
    console.log('═══════════════════════════════════════════════════════════');
    console.log(`To: ${params.to}`);
    console.log(`Subject: ${params.constellationName} — MFA Reset Request`);
    console.log('───────────────────────────────────────────────────────────');
    console.log('🔗  RESET URL:');
    console.log(`    ${params.resetUrl}`);
    console.log('───────────────────────────────────────────────────────────');
    console.log('This link expires in 15 minutes.');
    console.log('═══════════════════════════════════════════════════════════\n');
  }
}
