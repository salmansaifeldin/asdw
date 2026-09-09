# Google SSO POC

A deliberately blank page with a single **Sign in with Google** button, backed by a real
Google OAuth 2.0 Authorization Code flow (with PKCE). After sign-in the server holds a
genuine Google **access token** and uses it as a `Bearer` credential against the Google
userinfo API.

## Flow

1. `GET /auth/google` — generates `state` + PKCE verifier, redirects to Google's consent screen.
2. Google redirects back to `GET /auth/google/callback?code=...&state=...`.
3. The server POSTs the code to `https://oauth2.googleapis.com/token` and receives an
   `access_token` (plus `id_token` and, on first consent, a `refresh_token`).
4. The server calls `https://www.googleapis.com/oauth2/v3/userinfo` with
   `Authorization: Bearer <access_token>` to read the profile.
5. A server-side session is created; only an httpOnly `sid` cookie reaches the browser.
   The access token never leaves the server.

`POST /logout` drops the session and revokes the token at Google's revoke endpoint.

## Setting up the Google Cloud app

1. Go to <https://console.cloud.google.com/> and create (or pick) a project.
2. **APIs & Services → OAuth consent screen**: choose *External*, fill in app name and
   support email, and add the scopes `openid`, `.../auth/userinfo.email`,
   `.../auth/userinfo.profile`. While the app is in *Testing*, add every account you
   intend to sign in with under **Test users**.
3. **APIs & Services → Credentials → Create credentials → OAuth client ID**, type
   **Web application**.
4. Under **Authorized redirect URIs** add exactly:
   `http://localhost:3000/auth/google/callback`
   (it must match `GOOGLE_REDIRECT_URI` character for character, or Google returns
   `redirect_uri_mismatch`).
5. Copy the generated Client ID and Client secret.

## Running it

```bash
npm install
cp .env.example .env      # then paste your Client ID / secret into .env
npm start
```

Open <http://localhost:3000>.

## Endpoints

| Method | Path                     | Purpose                                              |
| ------ | ------------------------ | ---------------------------------------------------- |
| GET    | `/`                      | The blank page with the sign-in button                |
| GET    | `/auth/google`           | Starts the OAuth flow                                 |
| GET    | `/auth/google/callback`  | Handles the redirect, exchanges the code for a token  |
| GET    | `/api/me`                | Current session (profile + token metadata)            |
| GET    | `/api/google/userinfo`   | Live call to Google using the stored access token     |
| POST   | `/logout`                | Clears the session and revokes the token              |

## POC limits

Sessions and pending-login state live in a process-local `Map`, so they are lost on
restart and do not survive more than one instance — use Redis or a database for anything
real. Cookies are only marked `Secure` when `NODE_ENV=production`, so serve over HTTPS
there. The refresh token is stored but not yet used to renew an expired access token.
