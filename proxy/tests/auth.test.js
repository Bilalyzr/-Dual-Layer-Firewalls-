/**
 * WebAuthn step-up route tests (Tier 2 · EPIC B).
 *
 * The @simplewebauthn/server crypto is mocked so we can exercise the route logic
 * (session guard, challenge handling, credential persistence, step-up clear) with
 * deterministic verified/failed assertions, offline.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import express from "express";
import request from "supertest";

vi.mock("@simplewebauthn/server", () => ({
  generateRegistrationOptions: vi.fn(async () => ({ challenge: "reg-challenge", rp: { id: "localhost" } })),
  verifyRegistrationResponse: vi.fn(),
  generateAuthenticationOptions: vi.fn(async () => ({ challenge: "auth-challenge" })),
  verifyAuthenticationResponse: vi.fn(),
}));

import {
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { createSession, requireStepUp, getSessionFromToken, sessionMiddleware } from "../auth/session.js";
import authRouter from "../routes/auth.js";

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use(sessionMiddleware);
  app.use("/api/auth", authRouter);
  return app;
}

beforeEach(() => {
  vi.clearAllMocks();
  process.env.SESSION_SECRET = "test-secret-abcdefghijklmnop";
  process.env.WEBAUTHN_RP_ID = "localhost";
  process.env.WEBAUTHN_ORIGIN = "http://localhost:5174";
});

async function newSession(app, userId) {
  const s = await createSession({ userId });
  return { token: s.token, sessionId: s.sessionId, auth: { Authorization: `Bearer ${s.token}` } };
}

describe("WebAuthn endpoints require a session", () => {
  it("401s registration options without a session", async () => {
    const res = await request(buildApp()).post("/api/auth/webauthn/register/options").send({});
    expect(res.status).toBe(401);
  });
});

describe("registration", () => {
  it("persists a credential on a verified registration", async () => {
    const app = buildApp();
    const { auth } = await newSession(app, "u-reg");
    const opts = await request(app).post("/api/auth/webauthn/register/options").set(auth).send({});
    expect(opts.body.challenge).toBe("reg-challenge");

    verifyRegistrationResponse.mockResolvedValue({
      verified: true,
      registrationInfo: {
        credential: { id: "cred-1", publicKey: new Uint8Array([1, 2, 3]), counter: 0, transports: ["internal"] },
      },
    });
    const verify = await request(app)
      .post("/api/auth/webauthn/register/verify")
      .set(auth)
      .send({ response: { id: "cred-1" } });
    expect(verify.body.verified).toBe(true);
    expect(verify.body.credentialID).toBe("cred-1");
  });
});

describe("authentication clears step-up", () => {
  it("verified assertion clears stepUpRequired", async () => {
    const app = buildApp();
    const { auth, sessionId } = await newSession(app, "u-auth");

    // Register a credential first.
    verifyRegistrationResponse.mockResolvedValue({
      verified: true,
      registrationInfo: { credential: { id: "cred-A", publicKey: new Uint8Array([9]), counter: 3, transports: [] } },
    });
    await request(app).post("/api/auth/webauthn/register/options").set(auth).send({});
    await request(app).post("/api/auth/webauthn/register/verify").set(auth).send({ response: { id: "cred-A" } });

    // Session collapses → step-up required.
    await requireStepUp(sessionId, "test");
    expect((await getSessionFromToken(auth.Authorization.slice(7))).trustState.stepUpRequired).toBe(true);

    // Get an authentication challenge, then verify a good assertion.
    await request(app).post("/api/auth/webauthn/authenticate/options").set(auth).send({});
    verifyAuthenticationResponse.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 4 },
    });
    const verify = await request(app)
      .post("/api/auth/webauthn/authenticate/verify")
      .set(auth)
      .send({ response: { id: "cred-A" } });
    expect(verify.body.verified).toBe(true);
    expect(verify.body.trustState.stepUpRequired).toBe(false);
  });

  it("failed assertion keeps step-up in place", async () => {
    const app = buildApp();
    const { auth, sessionId } = await newSession(app, "u-fail");
    verifyRegistrationResponse.mockResolvedValue({
      verified: true,
      registrationInfo: { credential: { id: "cred-B", publicKey: new Uint8Array([7]), counter: 0, transports: [] } },
    });
    await request(app).post("/api/auth/webauthn/register/options").set(auth).send({});
    await request(app).post("/api/auth/webauthn/register/verify").set(auth).send({ response: { id: "cred-B" } });
    await requireStepUp(sessionId, "test");

    await request(app).post("/api/auth/webauthn/authenticate/options").set(auth).send({});
    verifyAuthenticationResponse.mockResolvedValue({ verified: false });
    const verify = await request(app)
      .post("/api/auth/webauthn/authenticate/verify")
      .set(auth)
      .send({ response: { id: "cred-B" } });
    expect(verify.status).toBe(401);
    expect((await getSessionFromToken(auth.Authorization.slice(7))).trustState.stepUpRequired).toBe(true);
  });
});
