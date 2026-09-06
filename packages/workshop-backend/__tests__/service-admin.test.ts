import { afterEach, describe, expect, it, vi } from "vitest";
import { newWebSocketRpcSession } from "capnweb";
import type { PublicApi } from "@gadgets/workshop-shared/api";
import { isWorkshopAdmin, resolveCfAccessPrincipal } from "../src/access.js";
import server from "../src/server.js";

const signed = vi.hoisted(() => ({ verify: vi.fn() }));
vi.mock("jose", () => ({
  createRemoteJWKSet: vi.fn(),
  jwtVerify: signed.verify,
}));

const clientId = "dedicated-service.access";
const origin = "https://workshop.example";
const settings = {
  CF_ACCESS_AUD: "workshop-audience",
  CF_ACCESS_ISS: "https://team.cloudflareaccess.com",
  CF_ACCESS_SERVICE_ADMINS: [clientId],
  ADMINS: ["admin@example.com"],
};

function fixture() {
  const authenticate = vi.fn().mockResolvedValue(false);
  const setMode = vi.fn().mockResolvedValue(undefined);
  const idFromName = vi.fn((name: string) => ({ name, toString: () => "opaque-user-id" }));
  const admin = {
    ensureFormatBlueprintsInstalled: vi.fn().mockResolvedValue(true),
    setGatekeeperMode: setMode,
  };
  const ctx = {
    waitUntil: (_promise: Promise<unknown>) => {},
    exports: {
      UserDurableObject: { idFromName, get: () => ({ authenticateFromCfAccess: authenticate }) },
      AdminSettings: { getByName: () => admin },
      OverseerDurableObject: {},
    },
  } as ExecutionContext;
  const env = { ...settings, BLUEPRINTS: { get: vi.fn().mockResolvedValue({ signupsEnabled: false }) } } as Parameters<typeof server.fetch>[1];
  return { ctx, env, authenticate, setMode, idFromName };
}

function request(path = "/api/admin-auth", headers: Record<string, string> = {}) {
  return new Request(origin + path, { headers: {
    Origin: origin, "cf-access-jwt-assertion": "signed-assertion", ...headers,
  } });
}

afterEach(() => vi.clearAllMocks());

describe("service administrator identity", () => {
  it("keeps service and human namespaces separate, even if a human allowlist contains a service ID", () => {
    const principal = resolveCfAccessPrincipal({ common_name: clientId }, settings)!;
    expect(principal).toEqual({ type: "service", clientId, userId: `cf-access-service:${clientId}` });
    expect(isWorkshopAdmin(principal.userId, settings, principal)).toBe(true);
    expect(isWorkshopAdmin(principal.userId, { ADMINS: [principal.userId] })).toBe(false);
    expect(resolveCfAccessPrincipal({ common_name: clientId }, { ADMINS: [clientId] })).toBeNull();
    expect(resolveCfAccessPrincipal({ email: "admin@example.com", common_name: clientId }, settings)).toBeNull();
    expect(resolveCfAccessPrincipal({ email: principal.userId }, settings)).toBeNull();
    expect(isWorkshopAdmin("someone-else", settings, principal)).toBe(false);
  });

  it("fails closed for absent, malformed and removed service grants", () => {
    for (const configured of [undefined, [], "not-json", {}, [clientId, 42], ["other.access"]]) {
      expect(resolveCfAccessPrincipal({ common_name: clientId }, { CF_ACCESS_SERVICE_ADMINS: configured })).toBeNull();
    }
    expect(resolveCfAccessPrincipal({ common_name: clientId }, {
      CF_ACCESS_SERVICE_ADMINS: JSON.stringify([clientId]),
    })?.type).toBe("service");
    for (const common_name of [true, "", "admin@example.com", " padded.access"])
      expect(resolveCfAccessPrincipal({ common_name }, settings)).toBeNull();
  });

  it("preserves human administrators without granting ordinary humans administrator access", () => {
    for (const email of ["admin@example.com", "reader@example.com"]) {
      const principal = resolveCfAccessPrincipal({ email }, settings)!;
      expect(principal).toEqual({ type: "human", userId: email });
      expect(isWorkshopAdmin(email, settings, principal)).toBe(email === "admin@example.com");
    }
  });
});

describe("authenticated caller probe and Workshop RPC", () => {
  it("reports only the verified caller, never a queried identity, with no account mutation", async () => {
    signed.verify.mockResolvedValue({ payload: { common_name: clientId } });
    const { env, ctx, authenticate } = fixture();
    const response = await server.fetch(request("/api/admin-auth?client_id=other.access"), env, ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(await response.json()).toEqual({ schema: "workshop-admin-auth.v1", authenticated: true,
      admin: true, principal_type: "service", client_id: clientId });
    expect(authenticate).not.toHaveBeenCalled();
    expect(signed.verify).toHaveBeenCalledWith("signed-assertion", undefined,
      { issuer: settings.CF_ACCESS_ISS, audience: settings.CF_ACCESS_AUD });
  });

  it("refuses unsigned, invalid, cross-origin and unallowlisted requests on both surfaces", async () => {
    const { env, ctx } = fixture();
    for (const path of ["/api", "/api/admin-auth"]) {
      signed.verify.mockResolvedValue({ payload: { common_name: clientId } });
      expect((await server.fetch(new Request(origin + path), env, ctx)).status).toBe(403);
      expect((await server.fetch(request(path, { Origin: "https://other.example" }), env, ctx)).status).toBe(403);
      signed.verify.mockRejectedValue(new Error("invalid signature"));
      expect((await server.fetch(request(path), env, ctx)).status).toBe(403);
      signed.verify.mockResolvedValue({ payload: { common_name: "other.access" } });
      expect((await server.fetch(request(path), env, ctx)).status).toBe(403);
    }
    signed.verify.mockResolvedValue({ payload: { email: "reader@example.com" } });
    expect((await server.fetch(request(), env, ctx)).status).toBe(403);
    expect((await server.fetch(request(), { ...env, CF_ACCESS_AUD: undefined }, ctx)).status).toBe(403);
  });

  it("uses the service identity for a real admin capability over Cap'n Web even with signups closed", async () => {
    signed.verify.mockResolvedValue({ payload: { common_name: clientId } });
    const { env, ctx, authenticate, setMode, idFromName } = fixture();
    const response = await server.fetch(request("/api", { Upgrade: "websocket" }), env, ctx);
    expect(response.status).toBe(101);
    const socket = response.webSocket!;
    socket.accept();
    using api = newWebSocketRpcSession<PublicApi>(socket);
    using authenticated = await api.authenticateFromCfAccess();
    expect(await authenticated.amIAdmin()).toBe(true);
    using admin = await authenticated.getAdminApi();
    expect(admin).not.toBeNull();
    await admin!.setGatekeeperMode("cityscroll", "optional");
    expect(setMode).toHaveBeenCalledWith("cityscroll", "optional");
    expect(idFromName).toHaveBeenCalledWith(`cf-access-service:${clientId}`);
    expect(authenticate).toHaveBeenCalledWith(`cf-access-service:${clientId}`, true);
  });
});
