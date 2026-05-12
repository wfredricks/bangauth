/**
 * UDT Identity Provider — Email Sender
 *
 * Sends access tokens to users via AWS SES with a clean, professional HTML template.
 *
 * // Why: Email is the delivery mechanism for tokens. Users don't generate tokens
 * // themselves — they request one, and it arrives in their inbox. This is
 * // intentional: the email address IS the identity, so proving you can receive
 * // email at that address proves you are who you claim to be.
 *
 * @module email
 */

import { SESv2Client, SendEmailCommand } from '@aws-sdk/client-sesv2';
import type { SendTokenEmailParams, SendRejectionEmailParams, SendResetEmailParams } from './types.js';

// Why: Module-level client singleton — reused across warm Lambda invocations.
const ses = new SESv2Client({});

/**
 * Build the HTML email body for a token delivery.
 *
 * // Why: A well-formatted HTML email with clear instructions reduces support
 * // requests. The monospace token block makes copy-paste reliable. The
 * // validity date sets expectations so users don't panic when it expires.
 *
 * @param params - Email parameters including token, constellation name, and login URL.
 * @returns Object with subject line and HTML body.
 */
export function buildTokenEmail(params: SendTokenEmailParams): {
  subject: string;
  html: string;
} {
  // Why: Extract month name for the subject line — "Your May 2026 DLA PIEE Access Token"
  // is much more human-friendly than "Your 2026-05 dla-piee Access Token."
  const monthNames = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December',
  ];
  const now = new Date();
  const monthName = monthNames[now.getMonth()];
  const year = now.getFullYear();

  const subject = `Your ${monthName} ${year} ${params.constellationName} Access Token`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${subject}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      line-height: 1.6;
      color: #333333;
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
      background-color: #f5f5f5;
    }
    .container {
      background-color: #ffffff;
      border-radius: 8px;
      padding: 32px;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
    .header {
      text-align: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 2px solid #e8e8e8;
    }
    .header h1 {
      font-size: 20px;
      color: #1a1a2e;
      margin: 0;
    }
    .header p {
      font-size: 14px;
      color: #666666;
      margin: 8px 0 0 0;
    }
    .token-block {
      background-color: #f0f4f8;
      border: 1px solid #d0d7de;
      border-radius: 6px;
      padding: 16px;
      margin: 24px 0;
      text-align: center;
    }
    .token-block code {
      font-family: 'SF Mono', 'Fira Code', 'Fira Mono', 'Roboto Mono', monospace;
      font-size: 13px;
      color: #1a1a2e;
      word-break: break-all;
      line-height: 1.8;
    }
    .login-button {
      display: inline-block;
      background-color: #1a1a2e;
      color: #ffffff !important;
      text-decoration: none;
      padding: 12px 32px;
      border-radius: 6px;
      font-size: 16px;
      font-weight: 600;
      margin: 16px 0;
    }
    .login-button:hover {
      background-color: #2d2d4e;
    }
    .center {
      text-align: center;
    }
    .info {
      font-size: 14px;
      color: #555555;
      margin: 16px 0;
    }
    .validity {
      font-size: 14px;
      color: #666666;
      background-color: #fff8e1;
      border-radius: 4px;
      padding: 8px 12px;
      display: inline-block;
    }
    .footer {
      margin-top: 32px;
      padding-top: 16px;
      border-top: 1px solid #e8e8e8;
      font-size: 12px;
      color: #999999;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>${params.constellationName}</h1>
      <p>Digital Twin Access Token</p>
    </div>

    <p class="info">
      Welcome! Your monthly access token for <strong>${params.constellationName}</strong> is ready.
      Click the button below to log in to your Digital Twin.
    </p>

    <div class="center">
      <a href="${params.loginUrl}?token=${encodeURIComponent(params.token)}" class="login-button">Log In to Your Twin</a>
    </div>

    <div class="center" style="margin-top: 16px;">
      <span class="validity">Valid through <strong>${params.validThrough}</strong></span>
    </div>

    <p class="info" style="margin-top: 24px; font-size: 13px;">
      <strong>Tip:</strong> Bookmark the link above for quick access all month.
      On ${params.validThrough.split(',')[0].replace(/\d+/, '1')}, you'll receive a new link automatically.
    </p>

    <div style="margin-top: 24px; background-color: #f0f4f8; border-radius: 6px; padding: 20px; border: 1px solid #d0d7de;">
      <p style="font-size: 15px; font-weight: 600; color: #1a1a2e; margin: 0 0 12px 0;">📱 First Time? Set Up Your Authenticator</p>
      <ol style="font-size: 13px; color: #555555; margin: 0; padding-left: 20px; line-height: 1.8;">
        <li>Install <strong>Google Authenticator</strong> (or Authy, Microsoft Authenticator)</li>
        <li>Click the login link above</li>
        <li>You'll be prompted to scan a QR code or enter a secret key</li>
        <li>Enter the 6-digit code from your app</li>
      </ol>
      <p style="font-size: 12px; color: #888888; margin: 12px 0 0 0;">
        You only need to do this once. After setup, just enter your 6-digit code each time you log in.
      </p>
    </div>

    <details style="margin-top: 16px; font-size: 12px; color: #888;">
      <summary style="cursor: pointer;">Or paste your token manually</summary>
      <div class="token-block" style="margin-top: 8px;">
        <code>${params.token}</code>
      </div>
      <p>Copy the token above and paste it at <a href="${params.loginUrl}">${params.loginUrl}</a></p>
    </details>

    <div class="footer">
      <p>
        This is an automated message from ${params.constellationName}. Do not reply.
      </p>
    </div>
  </div>
</body>
</html>`;

  return { subject, html };
}

/**
 * Send an access token to a user via AWS SES.
 *
 * // Why: SES is the simplest, most reliable way to send transactional email
 * // from Lambda. No SMTP servers to manage, no credentials to rotate manually.
 * // The SDK handles retries and connection pooling.
 *
 * @param params - Email delivery parameters.
 * @throws If SES fails to send (caller should handle and return appropriate error).
 */
/**
 * Send a rejection email to a user whose domain is not authorized.
 *
 * // Why: Rather than just showing an error on screen, send a helpful email
 * // explaining that their domain isn't authorized and directing them to
 * // a deployment-specific support address for manual vetting. This is
 * // better UX than a bare error screen and provides an audit trail of
 * // access requests.
 *
 * // The support mailbox is passed in via `params.supportEmail` (operators
 * // configure it per deployment, typically via `BANGAUTH_SUPPORT_EMAIL`).
 */
export async function sendRejectionEmail(params: SendRejectionEmailParams): Promise<void> {
  const subject = `${params.constellationName} — Access Request`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${subject}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      line-height: 1.6;
      color: #333333;
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
      background-color: #f5f5f5;
    }
    .container {
      background-color: #ffffff;
      border-radius: 8px;
      padding: 32px;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
    .header {
      text-align: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 2px solid #e8e8e8;
    }
    .header h1 {
      font-size: 20px;
      color: #1a1a2e;
      margin: 0;
    }
    .info {
      font-size: 14px;
      color: #555555;
      margin: 16px 0;
    }
    .contact-block {
      background-color: #f0f4f8;
      border: 1px solid #d0d7de;
      border-radius: 6px;
      padding: 16px;
      margin: 24px 0;
      text-align: center;
    }
    .contact-block a {
      font-size: 16px;
      font-weight: 600;
      color: #1a5fb4;
    }
    .footer {
      margin-top: 32px;
      padding-top: 16px;
      border-top: 1px solid #e8e8e8;
      font-size: 12px;
      color: #999999;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>${params.constellationName}</h1>
    </div>

    <p class="info">
      We received your request for access to <strong>${params.constellationName}</strong>,
      but your email domain is not currently authorized for automatic access.
    </p>

    <p class="info">
      If you believe you should have access, please contact our support team
      and we'll get you set up:
    </p>

    <div class="contact-block">
      <a href="mailto:${params.supportEmail}">${params.supportEmail}</a>
    </div>

    <p class="info" style="font-size: 13px;">
      Please include your name, organization, and the reason you need access.
      We typically respond within one business day.
    </p>

    <div class="footer">
      <p>This is an automated message from ${params.constellationName}. Do not reply.</p>
    </div>
  </div>
</body>
</html>`;

  await ses.send(
    new SendEmailCommand({
      FromEmailAddress: `${params.fromName} <${params.fromAddress}>`,
      Destination: {
        ToAddresses: [params.to],
      },
      Content: {
        Simple: {
          Subject: { Data: subject, Charset: 'UTF-8' },
          Body: {
            Html: { Data: html, Charset: 'UTF-8' },
          },
        },
      },
    }),
  );
}

/**
 * Send an MFA reset email with a time-limited reset link.
 *
 * // Why: When a user loses their authenticator device and has no recovery codes,
 * // they need an admin-independent way to reset MFA. We send an HMAC-signed
 * // reset link to their verified email — proving email ownership is sufficient
 * // to reset MFA since email IS the identity anchor in our system.
 *
 * @param params - Reset email parameters including the signed reset URL.
 */
export async function sendMfaResetEmail(params: SendResetEmailParams): Promise<void> {
  const subject = `${params.constellationName} — MFA Reset Request`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${subject}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      line-height: 1.6;
      color: #333333;
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
      background-color: #f5f5f5;
    }
    .container {
      background-color: #ffffff;
      border-radius: 8px;
      padding: 32px;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
    .header {
      text-align: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 2px solid #e8e8e8;
    }
    .header h1 {
      font-size: 20px;
      color: #1a1a2e;
      margin: 0;
    }
    .info {
      font-size: 14px;
      color: #555555;
      margin: 16px 0;
    }
    .center {
      text-align: center;
    }
    .reset-button {
      display: inline-block;
      background-color: #c0392b;
      color: #ffffff !important;
      text-decoration: none;
      padding: 12px 32px;
      border-radius: 6px;
      font-size: 16px;
      font-weight: 600;
      margin: 16px 0;
    }
    .warning {
      font-size: 13px;
      color: #c0392b;
      background-color: #fdf2f2;
      border-radius: 4px;
      padding: 8px 12px;
      display: inline-block;
    }
    .footer {
      margin-top: 32px;
      padding-top: 16px;
      border-top: 1px solid #e8e8e8;
      font-size: 12px;
      color: #999999;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>${params.constellationName}</h1>
    </div>

    <p class="info">
      We received a request to reset your multi-factor authentication (MFA) for
      <strong>${params.constellationName}</strong>.
    </p>

    <p class="info">
      Click the button below to reset your MFA. You will need to re-enroll your
      authenticator app after the reset.
    </p>

    <div class="center">
      <a href="${params.resetUrl}" class="reset-button">Reset My MFA</a>
    </div>

    <div class="center" style="margin-top: 16px;">
      <span class="warning">⚠️ This link expires in <strong>15 minutes</strong></span>
    </div>

    <p class="info" style="margin-top: 24px; font-size: 13px;">
      If you did not request this reset, you can safely ignore this email.
      Your MFA settings will remain unchanged.
    </p>

    <div class="footer">
      <p>This is an automated message from ${params.constellationName}. Do not reply.</p>
    </div>
  </div>
</body>
</html>`;

  await ses.send(
    new SendEmailCommand({
      FromEmailAddress: `${params.fromName} <${params.fromAddress}>`,
      Destination: {
        ToAddresses: [params.to],
      },
      Content: {
        Simple: {
          Subject: { Data: subject, Charset: 'UTF-8' },
          Body: {
            Html: { Data: html, Charset: 'UTF-8' },
          },
        },
      },
    }),
  );
}

export async function sendTokenEmail(params: SendTokenEmailParams): Promise<void> {
  const { subject, html } = buildTokenEmail(params);

  await ses.send(
    new SendEmailCommand({
      FromEmailAddress: `${params.fromName} <${params.fromAddress}>`,
      Destination: {
        ToAddresses: [params.to],
      },
      Content: {
        Simple: {
          Subject: { Data: subject, Charset: 'UTF-8' },
          Body: {
            Html: { Data: html, Charset: 'UTF-8' },
          },
        },
      },
    }),
  );
}
