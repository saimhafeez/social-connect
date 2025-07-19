const express = require('express');
const { google } = require('googleapis');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const axios = require('axios');

const app = express();

// Configuration - replace these with your actual values
const CONFIG = {
  CLIENT_ID: '231297576692-0d52jql98elho2q7m08h9qr3csq8k7n2.apps.googleusercontent.com',
  CLIENT_SECRET: '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',
  JWT_SECRET: '4c5b76e5-9c68-415f-90c9-e315456026f7', // Generate a strong random string
  TOKEN_EXPIRY: '5m', // Token expiry time
  COOKIE_NAME: 'google_auth_state',
  COMPANION_DOMAIN: 'https://social-connect-f02m.onrender.com', // Your render.com app URL
  ALLOWED_REDIRECT_PATHS: ['/'], // Paths allowed for redirect
};

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(cookieParser());
app.use(express.json());

// Initialize Google OAuth2 client
const oauth2Client = new google.auth.OAuth2(
  CONFIG.CLIENT_ID,
  CONFIG.CLIENT_SECRET,
  `${CONFIG.COMPANION_DOMAIN}/login/google/callback`
);

google.options({ auth: oauth2Client });

/**
 * Generate a secure state token with origin validation
 */
function generateStateToken(origin) {
  return jwt.sign({ origin }, CONFIG.JWT_SECRET, { expiresIn: CONFIG.TOKEN_EXPIRY });
}

/**
 * Verify state token and return the origin if valid
 */
function verifyStateToken(token) {
  try {
    const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
    return decoded.origin;
  } catch (err) {
    console.error('Invalid state token:', err);
    return null;
  }
}

/**
 * Validate the redirect URL against allowed patterns
 */
function isValidRedirect(origin, path) {
  try {
    const url = new URL(path, origin);
    return (
      url.origin === origin && 
      CONFIG.ALLOWED_REDIRECT_PATHS.some(allowedPath => url.pathname.startsWith(allowedPath))
    );
  } catch (e) {
    return false;
  }
}

/**
 * Main login endpoint - initiates Google OAuth flow
 */
app.get('/login/google', (req, res) => {
  const { origin } = req.query;
  
  if (!origin) {
    return res.status(400).json({ error: 'Origin parameter is required' });
  }

  // Generate state token with origin
  const stateToken = generateStateToken(origin);
  
  // Set state token as HTTP-only cookie
  res.cookie(CONFIG.COOKIE_NAME, stateToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 300000 // 5 minutes
  });

  // Generate Google OAuth URL
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: [
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile'
    ],
    prompt: 'select_account',
  });

  // Redirect to Google OAuth
  res.redirect(url);
});

/**
 * Google OAuth callback handler
 */
app.get('/login/google/callback', async (req, res) => {
  const { code, state } = req.query;
  const stateToken = req.cookies[CONFIG.COOKIE_NAME];

  if (!stateToken) {
    return res.status(400).send('Missing state token');
  }

  // Verify state token
  const origin = verifyStateToken(stateToken);
  if (!origin) {
    return res.status(400).send('Invalid state token');
  }

  // Clear the cookie
  res.clearCookie(CONFIG.COOKIE_NAME);

  try {
    // Exchange code for tokens
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // Get user info
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data } = await oauth2.userinfo.get();

    if (!data.email) {
      throw new Error('Email not found in user data');
    }

    // Create a short-lived token to pass back to the client
    const loginToken = jwt.sign({
      email: data.email,
      name: data.name,
      picture: data.picture,
    }, CONFIG.JWT_SECRET, { expiresIn: '1m' });

    // Improved postMessage handling with retry logic
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Google Authentication</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 20px; }
          .spinner { margin: 20px auto; width: 50px; height: 50px; border: 5px solid #f3f3f3; border-top: 5px solid #3498db; border-radius: 50%; animation: spin 1s linear infinite; }
          @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        </style>
        <script>
          function sendMessage() {
            try {
              const token = '${loginToken}';
              if (window.opener && !window.opener.closed) {
                window.opener.postMessage({
                  source: 'companion-google-login',
                  loginToken: token,
                  status: 'success'
                }, '${origin}');
                
                // Close after short delay to ensure message is delivered
                setTimeout(() => window.close(), 300);
              } else {
                // Retry for a few seconds if opener isn't available immediately
                if (retryCount < 10) {
                  retryCount++;
                  setTimeout(sendMessage, 300);
                } else {
                  document.getElementById('status').innerHTML = 
                    '<p style="color:red">Could not communicate with the main window. Please return to the app.</p>';
                }
              }
            } catch (e) {
              console.error('Message sending error:', e);
            }
          }
          
          let retryCount = 0;
          window.addEventListener('load', sendMessage);
        </script>
      </head>
      <body>
        <div class="spinner"></div>
        <div id="status">Completing authentication...</div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Google auth error:', error);
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authentication Error</title>
        <script>
          window.addEventListener('load', function() {
            window.opener.postMessage({
              source: 'companion-google-login',
              status: 'error',
              error: 'Authentication failed: ${error.message.replace(/'/g, "\\'")}'
            }, '${origin}');
            window.close();
          });
        </script>
      </head>
      <body>
        <p>Authentication failed. You can close this window.</p>
      </body>
      </html>
    `);
  }
});

/**
 * Endpoint to verify login tokens
 */
app.get('/login/tokeninfo', (req, res) => {
  const { token } = req.query;
  
  if (!token) {
    return res.status(400).json({ error: 'Token is required' });
  }

  try {
    const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
    res.json({
      email: decoded.email,
      name: decoded.name,
      picture: decoded.picture,
    });
  } catch (err) {
    console.error('Token verification failed:', err);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
});

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
