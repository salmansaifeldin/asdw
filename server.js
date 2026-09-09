'use strict';

require('dotenv').config();

const crypto = require('crypto');
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');

const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI = 'http://localhost:3000/auth/google/callback',
  PORT = 3000,
  NODE_ENV = 'development',
} = process.env;

if (!GOOGLE_CLIENT_ID) {
  console.error(
    'Missing GOOGLE_CLIENT_ID.\n' +
      'Copy .env.example to .env and fill in the client ID from Google Cloud Console.'
  );
  process.exit(1);
}

// The browser token flow (POST /auth/google/token) needs the client ID only.
// The redirect / authorization-code flow additionally needs the secret.
const codeFlowEnabled = Boolean(GOOGLE_CLIENT_SECRET);
if (!codeFlowEnabled) {
  console.warn('No GOOGLE_CLIENT_SECRET set — the redirect code flow is disabled.');
}

const AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const USERINFO_ENDPOINT = 'https://www.googleapis.com/oauth2/v3/userinfo';
const REVOKE_ENDPOINT = 'https://oauth2.googleapis.com/revoke';
const TOKENINFO_ENDPOINT = 'https://oauth2.googleapis.com/tokeninfo';

const SCOPES = ['openid', 'email', 'profile'];

// In-memory stores. A real deployment would use Redis / a database.
const pendingLogins = new Map(); // state -> { codeVerifier, createdAt }
const sessions = new Map(); // sessionId -> { profile, accessToken, expiresAt, refreshToken }

const TEN_MINUTES = 10 * 60 * 1000;

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function newCodeVerifier() {
  return base64url(crypto.randomBytes(32));
}

function codeChallengeFor(verifier) {
  return base64url(crypto.createHash('sha256').update(verifier).digest());
}

function sweepPendingLogins() {
  const cutoff = Date.now() - TEN_MINUTES;
  for (const [state, entry] of pendingLogins) {
    if (entry.createdAt < cutoff) pendingLogins.delete(state);
  }
}

const app = express();
app.use(cookieParser());
app.use(express.json({ limit: '8kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const cookieOptions = {
  httpOnly: true,
  sameSite: 'lax',
  secure: NODE_ENV === 'production',
  path: '/',
};

function currentSession(req) {
  const id = req.cookies.sid;
  if (!id) return null;
  return sessions.get(id) || null;
}

// Step 1: send the user to Google's consent screen.
app.get('/auth/google', (req, res) => {
  if (!codeFlowEnabled) return res.status(501).send('Redirect flow disabled: no GOOGLE_CLIENT_SECRET.');
  sweepPendingLogins();

  const state = base64url(crypto.randomBytes(24));
  const codeVerifier = newCodeVerifier();
  pendingLogins.set(state, { codeVerifier, createdAt: Date.now() });

  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: SCOPES.join(' '),
    state,
    code_challenge: codeChallengeFor(codeVerifier),
    code_challenge_method: 'S256',
    access_type: 'offline',
    prompt: 'select_account',
  });

  res.redirect(`${AUTH_ENDPOINT}?${params.toString()}`);
});

// Step 2: Google redirects back with ?code=...&state=...
app.get('/auth/google/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) return res.status(400).send(`Google returned an error: ${error}`);
  if (!code || !state) return res.status(400).send('Missing code or state.');

  const pending = pendingLogins.get(state);
  pendingLogins.delete(state);
  if (!pending) return res.status(400).send('Invalid or expired state. Start the login again.');

  try {
    // Step 3: exchange the authorization code for an OAuth 2.0 access token.
    const tokenRes = await fetch(TOKEN_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code',
        code_verifier: pending.codeVerifier,
      }),
    });

    const tokens = await tokenRes.json();
    if (!tokenRes.ok) {
      console.error('Token exchange failed:', tokens);
      return res.status(502).send('Token exchange with Google failed.');
    }

    // Step 4: use the access token (Bearer) to call a Google API for the profile.
    const userinfoRes = await fetch(USERINFO_ENDPOINT, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });

    const profile = await userinfoRes.json();
    if (!userinfoRes.ok) {
      console.error('Userinfo request failed:', profile);
      return res.status(502).send('Could not read the profile from Google.');
    }

    const sessionId = base64url(crypto.randomBytes(32));
    sessions.set(sessionId, {
      profile,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || null,
      scope: tokens.scope,
      expiresAt: Date.now() + (tokens.expires_in || 3600) * 1000,
    });

    res.cookie('sid', sessionId, { ...cookieOptions, maxAge: 24 * 60 * 60 * 1000 });
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.status(500).send('Unexpected error during the OAuth exchange.');
  }
});

// The client ID the browser needs to start the Google token flow.
app.get('/api/config', (req, res) => {
  res.json({ clientId: GOOGLE_CLIENT_ID, scopes: SCOPES });
});

// SSO login as a POST: the browser sends the Google access token (ya29....) in the body.
//
//   POST /auth/google/token
//   Content-Type: application/json
//   { "access_token": "ya29.a0AfH6SM..." }
//
// The token is NOT trusted as-is. It is validated at Google's tokeninfo endpoint and the
// audience must be this app's own client ID — otherwise any site could take a token its
// own users granted it and replay it here to log in as them.
app.post('/auth/google/token', async (req, res) => {
  const accessToken = req.body?.access_token;

  if (typeof accessToken !== 'string' || !accessToken) {
    return res.status(400).json({ error: 'missing_access_token' });
  }
  if (!accessToken.startsWith('ya29.')) {
    // Google OAuth 2.0 access tokens carry this prefix; an id_token (JWT, "eyJ...")
    // sent here by mistake would fail validation below anyway.
    return res.status(400).json({ error: 'not_a_google_access_token' });
  }

  try {
    const infoRes = await fetch(
      `${TOKENINFO_ENDPOINT}?access_token=${encodeURIComponent(accessToken)}`
    );
    const info = await infoRes.json();

    if (!infoRes.ok) {
      return res.status(401).json({ error: 'invalid_token', details: info.error_description });
    }
    if (info.aud !== GOOGLE_CLIENT_ID) {
      // Token was minted for a different application — reject it.
      console.warn('Rejected access token issued to another audience:', info.aud);
      return res.status(401).json({ error: 'audience_mismatch' });
    }
    if (info.expires_in !== undefined && Number(info.expires_in) <= 0) {
      return res.status(401).json({ error: 'expired_token' });
    }

    const userinfoRes = await fetch(USERINFO_ENDPOINT, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const profile = await userinfoRes.json();
    if (!userinfoRes.ok) {
      return res.status(502).json({ error: 'userinfo_failed' });
    }

    const sessionId = base64url(crypto.randomBytes(32));
    sessions.set(sessionId, {
      profile,
      accessToken,
      refreshToken: null,
      scope: info.scope,
      expiresAt: Date.now() + Number(info.expires_in || 3600) * 1000,
    });

    res.cookie('sid', sessionId, { ...cookieOptions, maxAge: 24 * 60 * 60 * 1000 });
    res.status(200).json({ authenticated: true, profile: { sub: profile.sub, email: profile.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'token_validation_failed' });
  }
});

// Who is signed in, for the front-end.
app.get('/api/me', (req, res) => {
  const session = currentSession(req);
  if (!session) return res.status(401).json({ authenticated: false });

  const { profile, expiresAt, scope, accessToken } = session;
  res.json({
    authenticated: true,
    profile,
    token: {
      // Only a prefix — the full access token stays on the server.
      preview: `${accessToken.slice(0, 12)}…`,
      scope,
      expiresAt: new Date(expiresAt).toISOString(),
      expiresInSeconds: Math.max(0, Math.round((expiresAt - Date.now()) / 1000)),
    },
  });
});

// Proof the access token itself works: call Google with it, live.
app.get('/api/google/userinfo', async (req, res) => {
  const session = currentSession(req);
  if (!session) return res.status(401).json({ error: 'not authenticated' });

  const r = await fetch(USERINFO_ENDPOINT, {
    headers: { Authorization: `Bearer ${session.accessToken}` },
  });
  res.status(r.status).json(await r.json());
});

app.post('/logout', async (req, res) => {
  const id = req.cookies.sid;
  const session = id ? sessions.get(id) : null;

  if (session) {
    sessions.delete(id);
    try {
      await fetch(REVOKE_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: session.accessToken }),
      });
    } catch (err) {
      console.error('Token revocation failed:', err);
    }
  }

  res.clearCookie('sid', cookieOptions);
  res.status(204).end();
});

app.listen(PORT, () => {
  console.log(`Google SSO POC listening on http://localhost:${PORT}`);
  console.log(`Redirect URI in use: ${GOOGLE_REDIRECT_URI}`);
});
