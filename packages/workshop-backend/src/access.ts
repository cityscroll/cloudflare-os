import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

/** Cloudflare Access settings required to verify an assertion. */
export type CfAccessEnv = Readonly<{
  CF_ACCESS_AUD?: string;
  CF_ACCESS_ISS?: string;
}>;

type AccessTokenVerifier = (token: string, env: CfAccessEnv) => Promise<JWTPayload>;

/** A caller derived exclusively from a verified Access assertion. */
export type CfAccessPrincipal =
  | { type: "human"; userId: string }
  | { type: "service"; userId: string; clientId: string };

/** Deployment-owned authorization settings; neither list is writable through the admin API. */
export type AccessAdminEnv = {
  ADMINS?: unknown;
  CF_ACCESS_SERVICE_ADMINS?: unknown;
};

function inAllowlist(value: string, configured: unknown): boolean {
  if (typeof configured === "string") {
    try { configured = JSON.parse(configured); } catch { return false; }
  }
  return Array.isArray(configured) && configured.every((entry) => typeof entry === "string") &&
      configured.includes(value);
}

/** Resolve signed claims, refusing ambiguous identities and unconfigured service principals. */
export function resolveCfAccessPrincipal(
    payload: JWTPayload, env: AccessAdminEnv): CfAccessPrincipal | null {
  if (payload.common_name !== undefined) {
    if (payload.email !== undefined || typeof payload.common_name !== "string" ||
        !/^[a-zA-Z0-9_-]+\.access$/.test(payload.common_name) ||
        !inAllowlist(payload.common_name, env.CF_ACCESS_SERVICE_ADMINS)) return null;
    return { type: "service", clientId: payload.common_name,
      userId: `cf-access-service:${payload.common_name}` };
  }
  if (typeof payload.email !== "string" || !/^[^\s@]+@[^\s@]+$/.test(payload.email)) return null;
  return { type: "human", userId: payload.email };
}

/** The common admin decision used by both the RPC capability and the caller-only probe. */
export function isWorkshopAdmin(
    userId: string | undefined, env: AccessAdminEnv, principal?: CfAccessPrincipal): boolean {
  if (!userId) return false;
  if (principal?.type === "service") {
    return userId === principal.userId && inAllowlist(principal.clientId, env.CF_ACCESS_SERVICE_ADMINS);
  }
  // Service account names can never gain authority through human/password authentication.
  if (userId.startsWith("cf-access-service:")) return false;
  return inAllowlist(userId, env.ADMINS);
}

const remoteJwkSets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

async function verifyToken(token: string, env: CfAccessEnv): Promise<JWTPayload> {
  if (!env.CF_ACCESS_AUD || !env.CF_ACCESS_ISS) {
    throw new Error("Cloudflare Access issuer and audience must both be configured.");
  }
  let jwks = remoteJwkSets.get(env.CF_ACCESS_ISS);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${env.CF_ACCESS_ISS}/cdn-cgi/access/certs`));
    remoteJwkSets.set(env.CF_ACCESS_ISS, jwks);
  }
  return (await jwtVerify(token, jwks, {
    issuer: env.CF_ACCESS_ISS,
    audience: env.CF_ACCESS_AUD,
  })).payload;
}

/** Returns verified Cloudflare Access claims, or null when the assertion cannot be trusted. */
export async function verifyCfAccessJwt(
    request: Request,
    env: CfAccessEnv,
    verifier: AccessTokenVerifier = verifyToken): Promise<JWTPayload | null> {
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) return null;
  try {
    return await verifier(token, env);
  } catch {
    return null;
  }
}

/** Returns a privacy-preserving limiter key derived only from verified Access claims. */
export async function accessRateLimitKey(payload: JWTPayload): Promise<string | null> {
  if (payload.sub) return `access-sub:${payload.sub}`;
  if (typeof payload.email !== "string" || payload.email.length === 0) return null;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload.email));
  return `access-email:${new Uint8Array(digest).toHex()}`;
}
