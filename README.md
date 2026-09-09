# Google SSO POC

A deliberately blank page with a single **Sign in with Google** button. Two flows are
implemented; both end with the server holding a genuine Google **access token** and using
it as a `Bearer` credential against the Google userinfo API.

## Flow A — token flow (default): SSO login is a POST

1. The page fetches its client ID from `GET /api/config` and starts Google Identity
   Services (`google.accounts.oauth2.initTokenClient`).
2. The user picks an account; Google hands the **browser** an access token that starts
   with `ya29.`.
3. The browser sends the SSO login request to this app:

   ```http
   POST /auth/google/token
   Content-Type: application/json

   { "access_token": "ya29.a0AfH6SM..." }
   ```

4. The server does **not** trust that token as-is. It calls
   `https://oauth2.googleapis.com/tokeninfo?access_token=...` and rejects the login unless
   `aud` equals this app's own client ID — without that check any site could replay a
   token its own users granted it and sign in here as them. Expiry is checked too.
5. The profile is read from the userinfo endpoint, a server-side session is created, and
   an httpOnly `sid` cookie is set. `200` with the profile comes back to the browser.

This flow needs **no client secret**. Configure the page's origin under
**Authorized JavaScript origins** (e.g. `http://localhost:3000`) on the OAuth client.

## Flow B — redirect / authorization-code flow (with PKCE)

Kept for reference at `GET /auth/google`; it requires `GOOGLE_CLIENT_SECRET` and returns
`501` when the secret is not set.

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
4. Under **Authorized JavaScript origins** add `http://localhost:3000` — this is what the
   token flow (Flow A) needs.
5. Only for Flow B: under **Authorized redirect URIs** add exactly
   `http://localhost:3000/auth/google/callback` (it must match `GOOGLE_REDIRECT_URI`
   character for character, or Google returns `redirect_uri_mismatch`).
6. Copy the generated Client ID. The Client secret is needed for Flow B only — treat it
   as a password: never commit it, never paste it into a chat or an issue. If it is ever
   exposed, reset it from the same screen.

## Running it

```bash
npm install
cp .env.example .env      # then paste your Client ID into .env (secret only for Flow B)
npm start
```

Open <http://localhost:3000>.

## Endpoints

| Method | Path                     | Purpose                                              |
| ------ | ------------------------ | ---------------------------------------------------- |
| GET    | `/`                      | The blank page with the sign-in button                |
| GET    | `/api/config`            | Client ID + scopes for the browser token flow         |
| POST   | `/auth/google/token`     | **SSO login** — body carries the `ya29.` access token |
| GET    | `/auth/google`           | Starts the redirect code flow (needs the secret)      |
| GET    | `/auth/google/callback`  | Handles the redirect, exchanges the code for a token  |
| GET    | `/api/me`                | Current session (profile + token metadata)            |
| GET    | `/api/google/userinfo`   | Live call to Google using the stored access token     |
| POST   | `/logout`                | Clears the session and revokes the token              |

## POC limits

Sessions and pending-login state live in a process-local `Map`, so they are lost on
restart and do not survive more than one instance — use Redis or a database for anything
real. Cookies are only marked `Secure` when `NODE_ENV=production`, so serve over HTTPS
there. The refresh token is stored but not yet used to renew an expired access token.
