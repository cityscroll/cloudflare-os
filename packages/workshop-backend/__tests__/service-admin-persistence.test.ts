import { createExecutionContext, waitOnExecutionContext, runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { generateKeyPair, exportJWK, SignJWT, type JWK } from "jose";
import { newWebSocketRpcSession } from "capnweb";
import type { PublicApi } from "@gadgets/workshop-shared/api";
import { expect, it, vi } from "vitest";
import server from "../src/server.js";

// Substitute only the provider's key distribution. Signature/issuer/audience verification
// runs through the real jose implementation; no live Access credentials are needed.
const keys = vi.hoisted(() => ({ jwks: { keys: [] as JWK[] } }));
vi.mock("jose", async (original) => {
  const jose = await original<typeof import("jose")>();
  return { ...jose, createRemoteJWKSet: () => jose.createLocalJWKSet(keys.jwks) };
});

it("authenticates a signed service and persists an admin RPC mutation with public signups closed", async () => {
  const pair = await generateKeyPair("RS256");
  keys.jwks.keys = [await exportJWK(pair.publicKey)];
  const origin = "https://workshop.example";
  const issuer = "https://team.cloudflareaccess.com";
  const clientId = "persistence-service.access";
  const settings = { ...env, CF_ACCESS_AUD: "workshop-audience", CF_ACCESS_ISS: issuer,
    CF_ACCESS_SERVICE_ADMINS: [clientId], ADMINS: ["admin@example.com"] };
  const ctx = createExecutionContext();
  const durableAdmin = exports.AdminSettings.getByName("");
  await durableAdmin.updateAdminConfig({ signupsEnabled: false, siteName: "Before service operation" });
  const sign = (claims: object, aud = settings.CF_ACCESS_AUD, iss = issuer, key = pair.privateKey) =>
    new SignJWT(claims).setProtectedHeader({ alg: "RS256" }).setIssuer(iss).setAudience(aud)
      .setExpirationTime("5m").sign(key);
  const request = (token: string, path = "/api/admin-auth", method = "GET") => new Request(origin + path, {
    method, headers: { Origin: origin, "cf-access-jwt-assertion": token,
      ...(path === "/api" ? { Upgrade: "websocket" } : {}) },
  });
  const token = await sign({ common_name: clientId });
  const before = await durableAdmin.getAdminConfig();
  const probe = await server.fetch(request(token, "/api/admin-auth?client_id=other.access"), settings, ctx);
  const body = await probe.json();
  expect(probe.status).toBe(200);
  expect(body).toEqual({ schema: "workshop-admin-auth.v1", authenticated: true, admin: true,
    principal_type: "service", client_id: clientId });
  expect(await durableAdmin.getAdminConfig()).toEqual(before);
  const existingAccount = await runInDurableObject(
    exports.UserDurableObject.getByName(`cf-access-service:${clientId}`), async (user) => {
      try {
        await user.authenticateFromCfAccess(`cf-access-service:${clientId}`, false);
        return true;
      } catch (error) {
        if (!(error instanceof Error) || !error.message.includes("New sign-ups")) throw error;
        return false;
      }
    });
  expect(existingAccount).toBe(false);
  const humanProbe = await server.fetch(request(await sign({ email: "admin@example.com" })), settings, ctx);
  expect(await humanProbe.json()).toEqual({ schema: "workshop-admin-auth.v1", authenticated: true,
    admin: true, principal_type: "human" });
  const foreignKey = (await generateKeyPair("RS256")).privateKey;
  for (const invalid of [await sign({ common_name: clientId }, "wrong-audience"),
    await sign({ common_name: clientId }, settings.CF_ACCESS_AUD, "https://wrong.example"),
    await sign({ common_name: clientId }, settings.CF_ACCESS_AUD, issuer, foreignKey)]) {
    for (const path of ["/api", "/api/admin-auth"])
      expect((await server.fetch(request(invalid, path), settings, ctx)).status).toBe(403);
  }
  expect((await server.fetch(request(token, "/api/admin-auth", "POST"), settings, ctx)).status).toBe(405);
  const response = await server.fetch(request(token, "/api"), settings, ctx);
  expect(response.status).toBe(101);
  const socket = response.webSocket!;
  socket.accept();
  using api = newWebSocketRpcSession<PublicApi>(socket);
  using authenticated = await api.authenticateFromCfAccess();
  expect(await authenticated.amIAdmin()).toBe(true);
  using admin = await authenticated.getAdminApi();
  expect(admin).not.toBeNull();
  await admin!.setSiteName("Managed by service administrator");
  const after = await durableAdmin.getAdminConfig();
  expect(after.siteName).toBe("Managed by service administrator");
  expect(after.signupsEnabled).toBe(false);
  expect((await server.fetch(request(token), { ...settings, CF_ACCESS_SERVICE_ADMINS: [] }, ctx)).status).toBe(403);
  console.log("SERVICE_ADMIN_EVIDENCE " + JSON.stringify({
    environment: "local workerd; real JWT cryptography, Capn Web and Durable Object storage; local provider key fixture",
    probe: { status: probe.status, body },
    rpc: { authenticatedAs: `cf-access-service:${clientId}`, amIAdmin: true,
      operation: 'setSiteName("Managed by service administrator")' },
    persisted: { before: before.siteName, after: after.siteName, signupsEnabled: after.signupsEnabled },
    rejectionStatus: { wrongIssuer: 403, wrongAudience: 403, foreignSignature: 403, removedGrant: 403, postProbe: 405 },
  }));
  await waitOnExecutionContext(ctx);
}, 60_000);
