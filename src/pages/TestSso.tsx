import { useEffect, useState } from 'react';

type GoogleTokenResponse = {
  access_token?: string;
  error?: string;
};

type GoogleTokenClient = {
  requestAccessToken: (options?: { prompt?: string }) => void;
};

declare global {
  interface Window {
    google?: {
      accounts: {
        oauth2: {
          initTokenClient: (config: {
            client_id: string;
            scope: string;
            callback: (response: GoogleTokenResponse) => void;
          }) => GoogleTokenClient;
        };
      };
    };
  }
}

export default function TestSso() {
  const [authenticated, setAuthenticated] = useState(false);
  const [tokenClient, setTokenClient] = useState<GoogleTokenClient | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    document.title = 'Google Sign In';

    let robots = document.querySelector<HTMLMetaElement>('meta[name="robots"]');
    const createdRobotsTag = !robots;
    const previousContent = robots?.content;

    if (!robots) {
      robots = document.createElement('meta');
      robots.name = 'robots';
      document.head.appendChild(robots);
    }
    robots.content = 'noindex, nofollow, noarchive';

    fetch('/api/auth/google/session', { credentials: 'include' })
      .then((response) => response.json())
      .then((data: { authenticated?: boolean }) => {
        setAuthenticated(data.authenticated === true);
      })
      .catch(() => setAuthenticated(false));

    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    script.onload = async () => {
      try {
        const configResponse = await fetch('/api/auth/google/config');
        if (!configResponse.ok) throw new Error('Google configuration failed');
        const { clientId } = (await configResponse.json()) as { clientId: string };
        const client = window.google?.accounts.oauth2.initTokenClient({
          client_id: clientId,
          scope: 'openid email profile',
          callback: async (googleResponse) => {
            if (!googleResponse.access_token) {
              setLoading(false);
              return;
            }
            const loginResponse = await fetch('/api/auth/google/login', {
              method: 'POST',
              credentials: 'include',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ token: googleResponse.access_token }),
            });
            const result = (await loginResponse.json()) as {
              authenticated?: boolean;
              redirectUrl?: string;
            };

            if (loginResponse.ok && result.authenticated === true) {
              setAuthenticated(true);
              // The server hands back the app URL with the access token in it
              // (http://192.168.1.4:8000?accesstoken=ya29...). A top-level
              // navigation to it works even from this HTTPS page, unlike the
              // blocked fetch/redirect. Fall back to the token if needed.
              const target =
                result.redirectUrl ??
                `http://192.168.1.4:8000?accesstoken=${encodeURIComponent(
                  googleResponse.access_token,
                )}`;
              window.location.href = target;
              return;
            }

            setAuthenticated(false);
            setLoading(false);
          },
        });
        setTokenClient(client ?? null);
      } finally {
        setLoading(false);
      }
    };
    script.onerror = () => setLoading(false);
    document.head.appendChild(script);

    return () => {
      script.remove();
      if (createdRobotsTag) {
        robots?.remove();
      } else if (robots && previousContent !== undefined) {
        robots.content = previousContent;
      }
    };
  }, []);

  return (
    <main className="min-h-screen bg-white flex items-center justify-center p-6">
      <button
        type="button"
        onClick={() => {
          setLoading(true);
          tokenClient?.requestAccessToken({ prompt: 'select_account' });
        }}
        disabled={!tokenClient || loading}
        aria-label="Login with Google"
        className="inline-flex h-12 min-w-64 items-center justify-center gap-3 rounded border border-[#dadce0] bg-white px-6 font-sans text-sm font-medium text-[#3c4043] shadow-sm transition hover:bg-[#f8faff] hover:shadow-md focus:outline-none focus:ring-2 focus:ring-[#1a73e8] focus:ring-offset-2 disabled:cursor-wait disabled:opacity-60"
      >
        <svg aria-hidden="true" width="20" height="20" viewBox="0 0 18 18">
          <path fill="#4285F4" d="M17.64 9.205c0-.638-.057-1.252-.164-1.841H9v3.482h4.844a4.14 4.14 0 0 1-1.797 2.716v2.258h2.909c1.703-1.568 2.684-3.88 2.684-6.615Z" />
          <path fill="#34A853" d="M9 18c2.43 0 4.468-.806 5.956-2.18l-2.909-2.258c-.806.54-1.835.859-3.047.859-2.344 0-4.328-1.585-5.037-3.714H.956v2.332A9 9 0 0 0 9 18Z" />
          <path fill="#FBBC05" d="M3.963 10.707A5.42 5.42 0 0 1 3.681 9c0-.593.102-1.169.282-1.707V4.961H.956A9 9 0 0 0 0 9c0 1.452.347 2.827.956 4.039l3.007-2.332Z" />
          <path fill="#EA4335" d="M9 3.579c1.321 0 2.507.454 3.44 1.345l2.581-2.581C13.464.891 11.426 0 9 0A9 9 0 0 0 .956 4.961l3.007 2.332C4.672 5.164 6.656 3.579 9 3.579Z" />
        </svg>
        {authenticated ? 'Signed in with Google' : loading ? 'Loading…' : 'Login with Google'}
      </button>
    </main>
  );
}
