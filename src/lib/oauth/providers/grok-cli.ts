/**
 * Grok Build OAuth Provider — Browser PKCE Flow + Import Token Flow
 *
 * Two ways to connect, merged under one provider entry (#7013):
 *   - Browser login: PKCE authorization-code flow against auth.x.ai, reusing
 *     the same public client id as the sibling xai-oauth provider (see
 *     grok-cli-oauth.ts / GROK_BUILD_OAUTH_CONFIG). Recommended, one click.
 *   - Import token: user pastes the entire auth.json from ~/.grok/auth.json
 *     or just the JWT access token string. Kept as a fallback for headless /
 *     remote installs where a loopback callback can't be reached.
 * Both paths converge on mapTokens() below and support automatic refresh
 * using the refresh_token (open-sse token-refresh reads config.tokenUrl
 * generically, independent of which flow acquired the tokens).
 */

import { GROK_BUILD_OAUTH_CONFIG } from "../constants/oauth";
import {
  buildGrokBuildAuthUrl,
  exchangeGrokBuildToken,
  isGrokBuildBrowserTokens,
  mapGrokBuildBrowserTokens,
} from "./grok-cli-oauth";

interface GrokCliAuthInfo {
  user_id: string;
  email: string;
  team_id: string;
  tier: number;
  principal_type: string;
}

function parseJwtPayload(token: string): {
  email: string | null;
  authInfo: GrokCliAuthInfo | null;
  exp: number | null;
} {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return { email: null, authInfo: null, exp: null };

    let base64 = parts[1];
    switch (base64.length % 4) {
      case 2:
        base64 += "==";
        break;
      case 3:
        base64 += "=";
        break;
    }
    base64 = base64.replace(/-/g, "+").replace(/_/g, "/");

    const payload = JSON.parse(Buffer.from(base64, "base64").toString("utf-8"));
    return {
      email: payload.email || null,
      authInfo: {
        user_id: payload.sub || "",
        email: payload.email || "",
        team_id: payload.team_id || "",
        tier: payload.tier || 1,
        principal_type: payload.principal_type || "User",
      },
      exp: typeof payload.exp === "number" ? payload.exp : null,
    };
  } catch {
    return { email: null, authInfo: null, exp: null };
  }
}

/**
 * Extract the JWT access token and refresh_token from user input.
 * Accepts either:
 *   - Raw JWT string (no refresh_token available)
 *   - The entire auth.json object: { "https://auth.x.ai::...": { "key": "eyJ...", "refresh_token": "..." } }
 */
function extractTokenAndRefresh(input: unknown): {
  accessToken: string;
  refreshToken: string | null;
  rawAuthJson: Record<string, unknown> | null;
  expiresAt: string | null;
} {
  // Direct JWT string
  if (typeof input === "string")
    return { accessToken: input, refreshToken: null, rawAuthJson: null, expiresAt: null };

  if (input && typeof input === "object") {
    const obj = input as Record<string, unknown>;

    // The route handler wraps the token: { accessToken: <token> }.
    // Unwrap once before checking the inner value.
    const inner =
      typeof obj.accessToken === "object" && obj.accessToken !== null
        ? (obj.accessToken as Record<string, unknown>)
        : obj;

    // auth.json format: { "https://auth.x.ai::...": { key: "eyJ...", refresh_token: "..." } }
    if (inner && typeof inner === "object") {
      const innerKeys = Object.keys(inner);
      for (const k of innerKeys) {
        const entry = inner[k];
        if (entry && typeof entry === "object" && "key" in entry) {
          const e = entry as Record<string, unknown>;
          if (typeof e.key === "string" && e.key.startsWith("eyJ")) {
            return {
              accessToken: e.key,
              refreshToken: typeof e.refresh_token === "string" ? e.refresh_token : null,
              rawAuthJson: inner as Record<string, unknown>,
              expiresAt: typeof e.expires_at === "string" ? e.expires_at : null,
            };
          }
        }
      }
    }

    // Raw JWT passed as { accessToken: "eyJ..." }
    if (typeof obj.accessToken === "string" && obj.accessToken.length > 0) {
      return {
        accessToken: obj.accessToken,
        refreshToken: typeof obj.refreshToken === "string" ? obj.refreshToken : null,
        rawAuthJson: null,
        expiresAt: null,
      };
    }
  }

  return { accessToken: "", refreshToken: null, rawAuthJson: null, expiresAt: null };
}

/** The pre-existing paste-token mapping — unchanged (#5775 clamp included). */
function mapImportedToken(token: unknown) {
  const { accessToken, refreshToken, rawAuthJson, expiresAt } = extractTokenAndRefresh(token);
  const { email, authInfo, exp } = parseJwtPayload(accessToken);

  const currentSec = Math.floor(Date.now() / 1000);
  let expiresIn = 21600;

  if (expiresAt) {
    const parsed = Date.parse(expiresAt);
    if (!isNaN(parsed)) {
      expiresIn = Math.floor(parsed / 1000) - currentSec;
    }
  } else if (typeof exp === "number" && exp > 0) {
    expiresIn = exp - currentSec;
  }

  // #5775 follow-up: guard against an already-expired token yielding a negative
  // expiresIn. A negative value is truthy downstream (import-token route) and maps
  // to a PAST expiresAt, which AutoCombo reads as "already expired" and excludes the
  // connection instead of refreshing it. Clamp to a tiny positive TTL so the token is
  // treated as due-for-refresh.
  expiresIn = Math.max(1, expiresIn);

  return {
    accessToken,
    refreshToken,
    expiresIn,
    email,
    providerSpecificData: {
      userId: authInfo?.user_id || null,
      teamId: authInfo?.team_id || null,
      tier: authInfo?.tier || 1,
      principalType: authInfo?.principal_type || "User",
      rawAuthJson: rawAuthJson || undefined,
    },
  };
}

export const grokCli = {
  config: GROK_BUILD_OAUTH_CONFIG,
  flowType: "authorization_code_pkce" as const,
  fixedPort: GROK_BUILD_OAUTH_CONFIG.loopbackPort,
  callbackPath: GROK_BUILD_OAUTH_CONFIG.callbackPath,
  callbackHost: GROK_BUILD_OAUTH_CONFIG.callbackHost,
  // The xAI flow uses a 96-byte random verifier (128 base64url chars), same as xai-oauth.
  pkceVerifierBytes: 96,
  buildAuthUrl: buildGrokBuildAuthUrl,
  exchangeToken: exchangeGrokBuildToken,
  /**
   * Unified token mapper serving BOTH flows under this single provider entry:
   * the browser PKCE exchange (tokens shaped like the OAuth token-endpoint
   * response — `access_token`/`refresh_token`/`id_token`/`expires_in`) and
   * the paste-token import (`{ accessToken: <JWT string or auth.json blob> }`,
   * see extractTokenAndRefresh above). Both converge on the same persisted
   * connection shape, so refresh keeps working unmodified either way.
   */
  mapTokens: (token: unknown) =>
    isGrokBuildBrowserTokens(token) ? mapGrokBuildBrowserTokens(token) : mapImportedToken(token),
};
