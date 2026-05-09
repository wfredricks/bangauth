/**
 * BangAuth — Login Page HTML
 *
 * Self-contained HTML login page with inline CSS and JavaScript. No build step,
 * no React, no bundler — just clean, minimal HTML that posts to the API.
 *
 * // Why: For a standalone service, we want zero build complexity. This is
 * // pure HTML that loads instantly, works everywhere, and has no dependencies.
 *
 * @module login-page
 */

/**
 * Generate the login page HTML.
 *
 * // Why: The HTML is generated dynamically so we can inject the API base URL
 * // and app name from config. This lets the same code work in dev and prod.
 */
export function buildLoginPage(appName: string, apiBaseUrl: string, redirectUrl: string = '/'): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${appName} — Sign In</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      line-height: 1.6;
      color: #1a1a2e;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }

    .container {
      background: white;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      max-width: 400px;
      width: 100%;
      padding: 40px;
    }

    h1 {
      font-size: 28px;
      font-weight: 700;
      text-align: center;
      margin-bottom: 8px;
      color: #1a1a2e;
    }

    .subtitle {
      text-align: center;
      color: #666;
      font-size: 14px;
      margin-bottom: 32px;
    }

    .form-group {
      margin-bottom: 20px;
    }

    label {
      display: block;
      font-size: 14px;
      font-weight: 600;
      margin-bottom: 8px;
      color: #333;
    }

    input {
      width: 100%;
      padding: 12px 16px;
      font-size: 16px;
      border: 2px solid #e0e0e0;
      border-radius: 8px;
      transition: border-color 0.2s;
    }

    input:focus {
      outline: none;
      border-color: #667eea;
    }

    button {
      width: 100%;
      padding: 14px;
      font-size: 16px;
      font-weight: 600;
      color: white;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      border: none;
      border-radius: 8px;
      cursor: pointer;
      transition: transform 0.1s, box-shadow 0.2s;
    }

    button:hover:not(:disabled) {
      transform: translateY(-2px);
      box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
    }

    button:active:not(:disabled) {
      transform: translateY(0);
    }

    button:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }

    .message {
      margin-top: 16px;
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 14px;
      display: none;
    }

    .message.error {
      background: #fee;
      color: #c33;
      border: 1px solid #fcc;
    }

    .message.success {
      background: #efe;
      color: #3c3;
      border: 1px solid #cfc;
    }

    .message.info {
      background: #eef;
      color: #33c;
      border: 1px solid #ccf;
    }

    .hidden {
      display: none !important;
    }

    .step {
      display: none;
    }

    .step.active {
      display: block;
    }

    .back-link {
      text-align: center;
      margin-top: 16px;
      font-size: 14px;
    }

    .back-link a {
      color: #667eea;
      text-decoration: none;
      font-weight: 600;
    }

    .back-link a:hover {
      text-decoration: underline;
    }

    .loader {
      display: inline-block;
      width: 14px;
      height: 14px;
      border: 2px solid rgba(255, 255, 255, 0.3);
      border-top-color: white;
      border-radius: 50%;
      animation: spin 0.6s linear infinite;
      margin-right: 8px;
      vertical-align: middle;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>${appName}</h1>
    <p class="subtitle">Passwordless authentication</p>

    <!-- Step 1: Enter email -->
    <div class="step active" id="step-email">
      <form id="email-form">
        <div class="form-group">
          <label for="email">Email Address</label>
          <input
            type="email"
            id="email"
            name="email"
            placeholder="you@example.com"
            required
            autocomplete="email"
          />
        </div>
        <button type="submit" id="email-btn">
          Continue
        </button>
      </form>
    </div>

    <!-- Step 2: Enter code -->
    <div class="step" id="step-code">
      <form id="code-form">
        <div class="form-group">
          <label for="code">Access Code</label>
          <input
            type="text"
            id="code"
            name="code"
            placeholder="Enter 6-digit code"
            required
            maxlength="6"
            pattern="[0-9]{6}"
            autocomplete="one-time-code"
          />
        </div>
        <button type="submit" id="code-btn">
          Verify
        </button>
      </form>
      <div class="back-link">
        <a href="#" id="back-to-email">Use a different email</a>
      </div>
    </div>

    <!-- Step 3: Enter MFA (if required) -->
    <div class="step" id="step-mfa">
      <form id="mfa-form">
        <div class="form-group">
          <label for="mfa-code">Authenticator Code</label>
          <input
            type="text"
            id="mfa-code"
            name="mfa-code"
            placeholder="Enter 6-digit code"
            required
            maxlength="6"
            pattern="[0-9]{6}"
            autocomplete="one-time-code"
          />
        </div>
        <button type="submit" id="mfa-btn">
          Verify
        </button>
      </form>
      <div class="back-link">
        <a href="#" id="back-from-mfa">Go back</a>
      </div>
    </div>

    <div class="message" id="message"></div>
  </div>

  <script>
    const API_BASE = '${apiBaseUrl}';
    const REDIRECT_URL = '${redirectUrl}';
    let currentEmail = '';
    let mfaSessionToken = '';

    // DOM elements
    const steps = {
      email: document.getElementById('step-email'),
      code: document.getElementById('step-code'),
      mfa: document.getElementById('step-mfa'),
    };

    const forms = {
      email: document.getElementById('email-form'),
      code: document.getElementById('code-form'),
      mfa: document.getElementById('mfa-form'),
    };

    const inputs = {
      email: document.getElementById('email'),
      code: document.getElementById('code'),
      mfaCode: document.getElementById('mfa-code'),
    };

    const message = document.getElementById('message');

    // Utility: Show a specific step
    function showStep(step) {
      Object.values(steps).forEach(s => s.classList.remove('active'));
      steps[step].classList.add('active');
      hideMessage();
    }

    // Utility: Show a message
    function showMessage(text, type = 'info') {
      message.textContent = text;
      message.className = \`message \${type}\`;
      message.style.display = 'block';
    }

    // Utility: Hide message
    function hideMessage() {
      message.style.display = 'none';
    }

    // Utility: Set button loading state
    function setButtonLoading(button, loading) {
      if (loading) {
        button.disabled = true;
        button.innerHTML = '<span class="loader"></span>Loading...';
      } else {
        button.disabled = false;
        button.innerHTML = button.dataset.originalText || 'Submit';
      }
    }

    // Step 1: Request access code
    forms.email.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('email-btn');
      btn.dataset.originalText = btn.innerHTML;
      setButtonLoading(btn, true);
      hideMessage();

      currentEmail = inputs.email.value.trim();

      try {
        const res = await fetch(\`\${API_BASE}/auth/request-code\`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: currentEmail }),
        });

        const data = await res.json();

        if (res.ok) {
          showMessage(\`Access code sent to \${currentEmail}. Check your email (or console in dev mode).\`, 'success');
          setTimeout(() => showStep('code'), 1500);
        } else {
          showMessage(data.error || 'Failed to send code', 'error');
        }
      } catch (err) {
        showMessage('Network error. Please try again.', 'error');
      } finally {
        setButtonLoading(btn, false);
      }
    });

    // Step 2: Verify access code
    forms.code.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('code-btn');
      btn.dataset.originalText = btn.innerHTML;
      setButtonLoading(btn, true);
      hideMessage();

      const code = inputs.code.value.trim();

      try {
        const res = await fetch(\`\${API_BASE}/auth/verify-code\`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: currentEmail, code }),
        });

        const data = await res.json();

        if (res.ok && data.authenticated) {
          if (data.mfaRequired) {
            // MFA is required — move to MFA step
            mfaSessionToken = data.mfaSessionToken;
            showMessage('MFA required. Enter your authenticator code.', 'info');
            setTimeout(() => showStep('mfa'), 1500);
          } else {
            // Success — no MFA needed
            showMessage(\`Welcome, \${data.email}! Redirecting...\`, 'success');
            // Redirect to Twin UI with JWT + user info in URL params
            // The UI will pick these up and store in its own localStorage
            setTimeout(() => {
              const redirectUrl = REDIRECT_URL || '/';
              const params = new URLSearchParams({
                jwt: data.jwt || '',
                email: data.email || '',
                twinId: data.twinId || '',
              });
              window.location.href = \`\${redirectUrl}?\${params.toString()}\`;
            }, 1000);
          }
        } else {
          showMessage(data.error || 'Invalid or expired code', 'error');
        }
      } catch (err) {
        showMessage('Network error. Please try again.', 'error');
      } finally {
        setButtonLoading(btn, false);
      }
    });

    // Step 3: Verify MFA
    forms.mfa.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('mfa-btn');
      btn.dataset.originalText = btn.innerHTML;
      setButtonLoading(btn, true);
      hideMessage();

      const mfaCode = inputs.mfaCode.value.trim();

      try {
        const res = await fetch(\`\${API_BASE}/auth/mfa/verify\`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mfaSessionToken, code: mfaCode }),
        });

        const data = await res.json();

        if (res.ok && data.mfaVerified) {
          showMessage(\`Welcome, \${data.email}!\`, 'success');
          // In production, redirect to the app or set a cookie
          setTimeout(() => {
            window.location.href = '/';
          }, 2000);
        } else {
          showMessage(data.reason || 'Invalid MFA code', 'error');
          if (data.mfaSessionToken) {
            // Update session token for retry
            mfaSessionToken = data.mfaSessionToken;
          }
        }
      } catch (err) {
        showMessage('Network error. Please try again.', 'error');
      } finally {
        setButtonLoading(btn, false);
      }
    });

    // Back links
    document.getElementById('back-to-email').addEventListener('click', (e) => {
      e.preventDefault();
      inputs.code.value = '';
      showStep('email');
    });

    document.getElementById('back-from-mfa').addEventListener('click', (e) => {
      e.preventDefault();
      inputs.mfaCode.value = '';
      showStep('code');
    });
  </script>
</body>
</html>`;
}
