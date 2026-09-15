// Copyright (c) 2026 D-o-M-Pl. All Rights Reserved.

import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createStore } from "./store.js";
import { bearer, json, readJson, tenant } from "./http.js";
import { passwordHash, validatePassword } from "./security.js";
import { AuthAnomalyDetector, clientIp } from "./anomaly.js";

const store = await createStore();
const detector = new AuthAnomalyDetector();

async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const method = req.method ?? "GET";
  const url = new URL(req.url ?? "/", "http://localhost");

  if (method === "GET" && url.pathname === "/health/live") {
    json(res, 200, { status: "ok" });
    return;
  }

  if (method === "GET" && url.pathname === "/health/ready") {
    const ready = await store.ready();
    json(res, ready ? 200 : 503, {
      status: ready ? "ready" : "not-ready",
      databaseMode: process.env.DATABASE_MODE ?? "prisma"
    });
    return;
  }

  if (method === "GET" && url.pathname === "/metrics") {
    res.statusCode = 200;
    res.setHeader("content-type", "text/plain; version=0.0.4");
    res.end(
      [
        "# TYPE char_code_audit_events gauge",
        `char_code_audit_events ${await store.auditCount()}`,
        "# TYPE char_code_outbox_pending gauge",
        `char_code_outbox_pending ${await store.pendingOutboxCount()}`,
        ""
      ].join("\n")
    );
    return;
  }

  if (method === "POST" && url.pathname === "/api/auth/login") {
    const { body, correlationId } = await readJson<{ email?: string; password?: string }>(req);
    if (!body.email || !body.password) {
      json(res, 400, { error: "EMAIL_AND_PASSWORD_REQUIRED" });
      return;
    }

    const ip = clientIp(req.headers, req.socket.remoteAddress);
    const decision = detector.check(body.email, ip);

    if (!decision.allowed) {
      await store.audit("auth.login.throttled", correlationId);
      res.setHeader("retry-after", String(decision.retryAfterSeconds));
      json(res, 429, { error: "TOO_MANY_ATTEMPTS", retryAfterSeconds: decision.retryAfterSeconds });
      return;
    }

    const session = await store.authenticate(body.email, body.password);

    if (!session) {
      const signals = detector.record(body.email, ip, false);
      await store.audit("auth.login.failed", correlationId);

      // Audyt rejestruje ka¿dy sygna³; powiadamiamy tylko o nowych,
      // aby trwaj¹cy atak nie zala³ administratora alertami.
      for (const signal of signals) {
        await store.audit(`security.anomaly.${signal}`, correlationId);
      }

      for (const signal of detector.alertable(signals, body.email, ip)) {
        await store.enqueue("SecurityAnomalyDetected", {
          signal,
          correlationId,
          email: body.email,
          detectedAt: new Date().toISOString()
        });
      }

      json(res, 401, { error: "INVALID_CREDENTIALS" });
      return;
    }

    detector.record(body.email, ip, true);
    await store.audit("auth.login", correlationId, session.userId);
    json(res, 200, { accessToken: session.token, expiresInSeconds: 900 });
    return;
  }

  if (method === "POST" && url.pathname === "/api/account/password/forgot") {
    const { body, correlationId } = await readJson<{ email?: string }>(req);
    const ip = clientIp(req.headers, req.socket.remoteAddress);

    // Ten sam limit co logowanie — ogranicza enumeracjê kont i zalew e-maili.
    if (!detector.check(body.email ?? "unknown", ip).allowed) {
      await store.audit("account.password.forgot.throttled", correlationId);
      json(res, 202, { accepted: true });
      return;
    }

    detector.record(body.email ?? "unknown", ip, false);

    if (body.email) {
      const token = await store.requestPasswordReset(body.email);
      if (token) await store.enqueue("PasswordResetRequested", { email: body.email, token });
    }

    json(res, 202, { accepted: true });
    return;
  }

  if (method === "POST" && url.pathname === "/api/account/password/reset") {
    const { body } = await readJson<{ token?: string; password?: string }>(req);
    if (!body.token || !body.password) {
      json(res, 400, { error: "TOKEN_AND_PASSWORD_REQUIRED" });
      return;
    }

    const error = validatePassword(body.password);
    if (error) {
      json(res, 400, { error });
      return;
    }

    const ok = await store.resetPassword(body.token, passwordHash(body.password));
    json(res, ok ? 200 : 400, ok ? { reset: true } : { error: "INVALID_OR_EXPIRED_TOKEN" });
    return;
  }

  if (method === "POST" && url.pathname === "/api/account/mfa/recovery-codes") {
    const tokenValue = bearer(req);
    const user = tokenValue ? await store.resolveSession(tokenValue) : null;
    if (!user) {
      json(res, 401, { error: "UNAUTHORIZED" });
      return;
    }

    json(res, 200, { codes: await store.createRecoveryCodes(user.id) });
    return;
  }

  if (method === "POST" && url.pathname === "/api/account/mfa/recover") {
    const { body, correlationId } = await readJson<{ code?: string }>(req);
    const ip = clientIp(req.headers, req.socket.remoteAddress);

    // Kody odzyskiwania omijaj¹ MFA — limitowane per IP.
    if (!detector.check(`mfa-recover:${ip}`, ip).allowed) {
      await store.audit("account.mfa.recover.throttled", correlationId);
      json(res, 429, { error: "TOO_MANY_ATTEMPTS" });
      return;
    }

    const ok = body.code ? await store.recoverMfa(body.code) : false;
    detector.record(`mfa-recover:${ip}`, ip, ok);
    await store.audit(ok ? "account.mfa.recovered" : "account.mfa.recover.failed", correlationId);
    json(res, ok ? 200 : 400, ok ? { recovered: true } : { error: "INVALID_RECOVERY_CODE" });
    return;
  }

  if (method === "GET" && url.pathname === "/api/tenant/tasks") {
    const tokenValue = bearer(req);
    const user = tokenValue ? await store.resolveSession(tokenValue) : null;
    const organizationId = tenant(req);

    if (!user) {
      json(res, 401, { error: "UNAUTHORIZED" });
      return;
    }

    if (!organizationId) {
      json(res, 400, { error: "TENANT_REQUIRED" });
      return;
    }

    const tasks = await store.tenantTasks(user, organizationId);
    if (!tasks) {
      json(res, 403, { error: "TENANT_ACCESS_DENIED" });
      return;
    }

    json(res, 200, { organizationId, tasks });
    return;
  }

  json(res, 404, { error: "NOT_FOUND" });
}

const port = Number(process.env.PORT ?? "3001");
const host = process.env.HOST ?? "127.0.0.1";
const server = createServer(async (req, res) => {
  try {
    await route(req, res);
  } catch (error) {
    console.error("Unhandled request error", error);
    json(res, 500, {
      error: "INTERNAL_ERROR"
    });
  }
});

server.listen(port, host, () => {
  console.log(`Char-code API listening on http://${host}:${port}`);
});