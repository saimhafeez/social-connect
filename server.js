const express = require('express');
const { google } = require('googleapis');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const axios = require('axios');

const app = express();

// Configuration - replace these with your actual values
const CONFIG = {
  CLIENT_ID: 'YOUR_GOOGLE_CLIENT_ID',
  CLIENT_SECRET: 'YOUR_GOOGLE_CLIENT_SECRET',
  JWT_SECRET: 'YOUR_SECURE_JWT_SECRET', // Generate a strong random string
  TOKEN_EXPIRY: '5m', // Token expiry time
  COOKIE_NAME: 'google_auth_state',
  COMPANION_DOMAIN: 'https://your-render-app.onrender.com', // Your render.com app URL
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

    // Redirect back to the client with the token
    const redirectUrl = new URL(origin);
    redirectUrl.searchParams.set('loginToken', loginToken);
    
    // Render a page that will postMessage back to the parent
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Google Authentication</title>
        <script>
          window.addEventListener('load', function() {
            const token = '${loginToken}';
            window.opener.postMessage({
              source: 'companion-google-login',
              loginToken: token
            }, '${CONFIG.COMPANION_DOMAIN}');
            
            window.close();
          });
        </script>
      </head>
      <body>
        <p>Authentication successful. You can close this window.</p>
      </body>
      </html>
    `);

  } catch (error) {
    console.error('Google auth error:', error);
    
    // Redirect back with error
    const redirectUrl = new URL(origin);
    redirectUrl.searchParams.set('error', 'Authentication failed');
    res.redirect(redirectUrl.toString());
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
