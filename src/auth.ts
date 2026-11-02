// Who is making this request? Answered from the shared poietic session
// cookie, verified against auth.poietic.tech's public key. This Worker holds
// no auth secret and can't mint tokens; see @poietic-tech/auth.

import {
  AUD_PUBLIC,
  ISSUER,
  JWKS_URL,
  SESSION_COOKIE,
  parseCookies,
  verifyIdentityToken,
} from "@poietic-tech/auth";

export interface Caller {
  sub: string;
  name: string;
}

interface AuthEnv {
  /** Local development only: see isDevBypass. Never set in production. */
  DEV_AUTH_BYPASS?: string;
}

// The .poietic.tech cookie can't exist on localhost, so local dev needs a way
// to create rooms. Requiring BOTH the var and a localhost hostname means a
// stray production var can't open the gate on the real domain.
function isDevBypass(request: Request, env: AuthEnv): boolean {
  const host = new URL(request.url).hostname;
  return env.DEV_AUTH_BYPASS === "1" && (host === "localhost" || host === "127.0.0.1");
}

export async function authenticate(
  request: Request,
  env: AuthEnv,
  fetchImpl?: typeof fetch,
): Promise<Caller | null> {
  if (isDevBypass(request, env)) return { sub: "dev", name: "Local dev" };
  const token = parseCookies(request.headers.get("cookie"))[SESSION_COOKIE];
  if (!token) return null;
  const claims = await verifyIdentityToken(token, JWKS_URL, {
    issuer: ISSUER,
    audience: AUD_PUBLIC,
    fetchImpl,
  });
  return claims ? { sub: claims.sub, name: claims.name } : null;
}
