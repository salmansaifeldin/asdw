import { createHmac, timingSafeEqual } from "node:crypto";
import { Router, type IRouter } from "express";

const router: IRouter = Router();
const SESSION_COOKIE = "proteqon_google_session";
const ONE_HOUR_MS = 60 * 60 * 1000;
const DEFAULT_POST_LOGIN_REDIRECT = "http://192.168.1.4:8000";

type GoogleTokenInfo = {
  aud?: string;
  sub?: string;
  email?: string;
  email_verified?: string | boolean;
  expires_in?: string | number;
};

type GoogleUserInfo = {
  sub?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  locale?: string;
};

function requiredEnv(name: string) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function sign(value: string) {
  return createHmac("sha256", requiredEnv("SESSION_SECRET"))
    .update(value)
    .digest("base64url");
}

function makeSignedValue(value: string) {
  return `${value}.${sign(value)}`;
}

function verifySignedValue(signedValue: string | undefined) {
  if (!signedValue) return null;
  const separator = signedValue.lastIndexOf(".");
  if (separator < 1) return null;

  const value = signedValue.slice(0, separator);
  const providedSignature = signedValue.slice(separator + 1);
  const expectedSignature = sign(value);
  const provided = Buffer.from(providedSignature);
  const expected = Buffer.from(expectedSignature);

  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    return null;
  }

  return value;
}

// The access token is passed in the query string, so it can end up in browser
// history, proxy logs and Referer headers. Keep the target on a trusted host.
function postLoginRedirectUrl(accessToken: string) {
  const target = new URL(
    process.env.POST_LOGIN_REDIRECT_URL ?? DEFAULT_POST_LOGIN_REDIRECT,
  );
  target.searchParams.set("accesstoken", accessToken);
  return target.toString();
}

function cookieOptions(maxAge: number) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    maxAge,
    path: "/",
  };
}

router.get("/auth/google/config", (_req, res) => {
  res.json({ clientId: requiredEnv("GOOGLE_CLIENT_ID") });
});

router.post("/auth/google/login", async (req, res) => {
  const token =
    typeof req.body?.token === "string" ? req.body.token.trim() : "";
  if (!token) {
    res.status(400).json({ authenticated: false, error: "Google token is required" });
    return;
  }

  try {
    const tokenInfoUrl = new URL("https://oauth2.googleapis.com/tokeninfo");
    tokenInfoUrl.searchParams.set("access_token", token);
    const tokenInfoResponse = await fetch(tokenInfoUrl);

    if (!tokenInfoResponse.ok) {
      req.log.warn(
        { statusCode: tokenInfoResponse.status },
        "Google access token validation failed",
      );
      res.status(401).json({ authenticated: false, error: "Invalid Google token" });
      return;
    }

    const tokenInfo = (await tokenInfoResponse.json()) as GoogleTokenInfo;
    const expiresIn = Number(tokenInfo.expires_in);
    const emailVerified =
      tokenInfo.email_verified === true || tokenInfo.email_verified === "true";

    if (tokenInfo.aud !== requiredEnv("GOOGLE_CLIENT_ID")) {
      req.log.warn("Google access token audience did not match");
      res.status(401).json({ authenticated: false, error: "Invalid token audience" });
      return;
    }

    if (!Number.isFinite(expiresIn) || expiresIn <= 0) {
      req.log.warn("Google access token was expired");
      res.status(401).json({ authenticated: false, error: "Google token has expired" });
      return;
    }

    if (!emailVerified) {
      req.log.warn("Google account email was not verified");
      res.status(403).json({ authenticated: false, error: "Google email is not verified" });
      return;
    }

    if (!tokenInfo.sub || !tokenInfo.email) {
      req.log.warn("Google token info response was incomplete");
      res.status(401).json({ authenticated: false, error: "Incomplete Google identity" });
      return;
    }

    const userInfoResponse = await fetch(
      "https://openidconnect.googleapis.com/v1/userinfo",
      { headers: { Authorization: `Bearer ${token}` } },
    );
    if (!userInfoResponse.ok) {
      req.log.warn(
        { statusCode: userInfoResponse.status },
        "Google user info request failed",
      );
      res.status(502).json({ authenticated: false, error: "Could not load Google user" });
      return;
    }
    const userInfo = (await userInfoResponse.json()) as GoogleUserInfo;

    if (userInfo.sub !== tokenInfo.sub || userInfo.email !== tokenInfo.email) {
      req.log.warn("Google user info did not match token identity");
      res.status(401).json({ authenticated: false, error: "Google identity mismatch" });
      return;
    }

    const sessionLifetimeMs = Math.min(
      ONE_HOUR_MS,
      Math.max(1, expiresIn) * 1000,
    );

    const sessionPayload = Buffer.from(
      JSON.stringify({
        sub: tokenInfo.sub,
        email: tokenInfo.email,
        expiresAt: Date.now() + sessionLifetimeMs,
      }),
    ).toString("base64url");

    res.cookie(
      SESSION_COOKIE,
      makeSignedValue(sessionPayload),
      cookieOptions(sessionLifetimeMs),
    );

    req.log.info(
      {
        event: "google_sign_in",
        user: {
          id: userInfo.sub,
          email: userInfo.email,
          emailVerified: userInfo.email_verified === true,
          name: userInfo.name ?? null,
          givenName: userInfo.given_name ?? null,
          familyName: userInfo.family_name ?? null,
          locale: userInfo.locale ?? null,
        },
      },
      "Google user signed in",
    );

    // Always send the user to our app server with the access token in the URL:
    // http://192.168.1.4:8000?accesstoken=ya29...
    res.redirect(303, postLoginRedirectUrl(token));
  } catch (error) {
    req.log.error({ err: error }, "Google token login failed");
    res.status(500).json({ authenticated: false, error: "Google login failed" });
  }
});

router.get("/auth/google/session", (req, res) => {
  const sessionPayload = verifySignedValue(req.cookies?.[SESSION_COOKIE]);
  if (!sessionPayload) {
    res.json({ authenticated: false });
    return;
  }

  try {
    const session = JSON.parse(
      Buffer.from(sessionPayload, "base64url").toString("utf8"),
    ) as { expiresAt?: number };

    if (!session.expiresAt || session.expiresAt <= Date.now()) {
      res.clearCookie(SESSION_COOKIE, { path: "/" });
      res.json({ authenticated: false });
      return;
    }

    res.json({ authenticated: true });
  } catch {
    res.clearCookie(SESSION_COOKIE, { path: "/" });
    res.json({ authenticated: false });
  }
});

export default router;