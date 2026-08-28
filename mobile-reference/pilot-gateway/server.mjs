#!/usr/bin/env node
import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { TextDecoder } from "node:util";
import { randomBytes } from "node:crypto";
import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";
import { AlphaStateError, AlphaStore } from "./alpha-store.mjs";
import {
  CommandSecurityError,
  createCommandSecurity,
} from "./command-security.mjs";
import {
  PairingSessionError,
  createPairingSession,
  readDesktopJson,
  readTrustedIngressTokenFromFd,
  validateDesktopSecurityRead,
  validateDesktopApprove,
  validateDesktopCancel,
  validateDesktopCreate,
  validateDesktopRevoke,
  validateDesktopReset,
  validateDesktopStatus,
  validateDesktopUninstall,
  validateJoinId,
} from "./pairing-session.mjs";
import {
  ProductHostClient,
  ProductHostClientError,
  readCommandKeyFromFd,
} from "./product-host-client.mjs";
import { RelayClient } from "./relay-client.mjs";
import {
  ALPHA_SCHEMA,
  MAX_PROJECTION_BYTES,
  ProjectionValidationError,
} from "./view.mjs";

const FRAME_ID = /^[0-9a-f]{16}$/;
const HEX_PAYLOAD = /^(?:[0-9a-fA-F]{2})+$/;
const MAX_RELAY_FRAMES = 100;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });
const execFile = promisify(execFileCallback);

export function createGateway(options) {
  const mode = options.mode ?? "foundation-readonly";
  if (!["foundation-readonly", "official-agent-local"].includes(mode))
    throw new Error("Unsupported Gateway mode");
  const routeTable = options.routeTable ?? "legacy";
  if (!["legacy", "desktop", "join"].includes(routeTable))
    throw new Error("Unsupported Gateway route table");
  if (routeTable !== "legacy" && mode !== "official-agent-local")
    throw new Error("Pairing route tables require official-agent-local mode");
  const commandKey =
    mode === "official-agent-local" && !options.productHostClient
      ? (options.commandKey ?? readCommandKeyFromFd(options.commandKeyFd))
      : options.commandKey;
  const productHost =
    mode === "official-agent-local"
      ? (options.productHostClient ??
        new ProductHostClient(options.productHostSocket, {
          expectedIdentity: options.productHostSocketIdentity,
          commandKey,
        }))
      : null;
  const relay =
    mode === "foundation-readonly"
      ? (options.relayClient ??
        new RelayClient(options.relayUrl, options.relayToken))
      : null;
  const store =
    routeTable === "join"
      ? null
      : (options.store ?? new AlphaStore(options.stateDb));
  const distDir = options.distDir;
  const commandSecurity =
    mode === "official-agent-local"
      ? (options.commandSecurity ??
        (options.port === undefined
          ? null
          : createCommandSecurity(
              options.host ?? "127.0.0.1",
              Number(options.port),
            )))
      : null;
  const desktopOrigin =
    routeTable === "desktop"
      ? exactDesktopOrigin(options.host ?? "127.0.0.1", options.port)
      : null;
  const desktopCsrf =
    routeTable === "desktop"
      ? (options.desktopCsrfToken ?? randomBytes(32).toString("base64url"))
      : null;
  const desktopPublicOrigin =
    routeTable === "desktop" && options.publicOrigin
      ? exactHttpsPublicOrigin(options.publicOrigin)
      : null;
  const pairingSession =
    routeTable === "join"
      ? (options.pairingSession ??
        createPairingSession({
          publicOrigin: options.publicOrigin,
          trustedIngressToken: options.trustedIngressToken,
        }))
      : null;
  const lifecycleBridge =
    routeTable === "desktop"
      ? (options.lifecycleBridge ??
        createLifecycleBridge(options.lifecycleBridgeOptions ?? {}))
      : null;
  let ingestFlight = null;

  function ingestSingleFlight() {
    if (ingestFlight) return ingestFlight;
    const flight = (
      productHost
        ? ingestProductHost(productHost, store)
        : ingestFrames(relay, store)
    ).finally(() => {
      if (ingestFlight === flight) ingestFlight = null;
    });
    ingestFlight = flight;
    return flight;
  }

  return async (request, response) => {
    setHeaders(response);
    let pairingRoute = routeTable === "join";
    try {
      const url = new URL(request.url, "http://gateway.local");
      if (routeTable === "desktop") {
        if (
          url.pathname.startsWith("/j/") ||
          url.pathname === "/api/pairing" ||
          url.pathname.startsWith("/api/pairing/")
        )
          return json(response, 404, { error: "NOT_FOUND" });
        pairingRoute = url.pathname.startsWith("/api/desktop/");
        if (
          await handleDesktopRoute(
            request,
            response,
            url,
            productHost,
            lifecycleBridge,
            desktopOrigin,
            desktopCsrf,
            desktopPublicOrigin,
          )
        )
          return;
      }
      if (routeTable === "join")
        return await handleJoinRoute(
          request,
          response,
          url,
          productHost,
          pairingSession,
          distDir,
        );
      if (
        url.pathname === "/api/pilot" ||
        url.pathname.startsWith("/api/pilot/")
      ) {
        return json(response, 403, { error: "READ_ONLY_ALPHA" });
      }

      if (url.pathname === "/api/commands/capability") {
        if (mode !== "official-agent-local")
          return json(response, 404, { error: "NOT_FOUND" });
        if (!commandSecurity)
          throw new CommandSecurityError("COMMAND_GATEWAY_UNAVAILABLE", 503);
        if (request.method !== "GET")
          return json(response, 405, { error: "METHOD_NOT_ALLOWED" });
        commandSecurity.validateRead(request);
        let capability;
        let hostEnvelope;
        let displayProjection;
        try {
          hostEnvelope = store.productEnvelope();
          displayProjection = store.productCurrent();
          if (!hostEnvelope || !displayProjection)
            throw new Error("NO_CURRENT_PRODUCT_HOST_SNAPSHOT");
          capability = await productHost.getCommandCapability();
          if (
            capability.snapshot_seq !== hostEnvelope.snapshot_seq ||
            capability.snapshot_digest !== hostEnvelope.digest
          ) {
            throw new Error("COMMAND_CAPABILITY_SNAPSHOT_MISMATCH");
          }
        } catch {
          return json(response, 503, {
            error: "COMMAND_CAPABILITY_UNAVAILABLE",
          });
        }
        return json(response, 200, {
          schema: "nomad.gateway.command-capability.v1",
          csrf_token: commandSecurity.csrfToken,
          capability,
          display_snapshot_seq: displayProjection.last_applied_seq,
          display_snapshot_digest: displayProjection.digest,
        });
      }
      if (url.pathname === "/api/commands") {
        if (mode !== "official-agent-local")
          return json(response, 404, { error: "NOT_FOUND" });
        if (!commandSecurity)
          throw new CommandSecurityError("COMMAND_GATEWAY_UNAVAILABLE", 503);
        if (request.method !== "POST")
          return json(response, 405, { error: "METHOD_NOT_ALLOWED" });
        const command = await commandSecurity.readCommand(request);
        let receipt;
        try {
          receipt = await productHost.postCommand(command);
        } catch {
          return json(response, 503, { error: "COMMAND_OUTCOME_UNAVAILABLE" });
        }
        return json(response, 200, {
          ...receipt,
          schema: "nomad.gateway.command-receipt.v1",
        });
      }

      const alphaMatch = url.pathname.match(
        /^\/api\/alpha\/session(?:\/([A-Za-z0-9_.:-]{1,64}))?$/,
      );
      if (alphaMatch) {
        if (request.method !== "GET")
          return json(response, 405, { error: "METHOD_NOT_ALLOWED" });
        const projection = await ingestSingleFlight();
        if (!projection)
          return json(
            response,
            503,
            unavailable(
              "unavailable",
              productHost ? "local-host-direct" : "local-alpha-gateway",
            ),
          );
        if (alphaMatch[1] && projection.session.session_id !== alphaMatch[1]) {
          return json(
            response,
            503,
            unavailable(
              "unavailable",
              productHost ? "local-host-direct" : "local-alpha-gateway",
            ),
          );
        }
        return json(response, 200, projection);
      }

      if (url.pathname.startsWith("/api/"))
        return json(response, 404, { error: "NOT_FOUND" });
      return serveStatic(distDir, url.pathname, response);
    } catch (error) {
      // Do not log request bodies, Relay tokens, projections, or raw frames.
      if (
        error instanceof CommandSecurityError ||
        error instanceof PairingSessionError
      )
        return json(response, error.statusCode, { error: error.code });
      if (error instanceof ProductHostClientError && pairingRoute)
        return json(response, pairingHostStatus(error), {
          error: safePairingHostCode(error),
        });
      if (pairingRoute)
        return json(response, 503, { error: "PAIRING_UNAVAILABLE" });
      if (
        error instanceof ProjectionValidationError ||
        error instanceof AlphaStateError ||
        error instanceof SyntaxError
      ) {
        return json(
          response,
          503,
          unavailable(
            "unknown",
            productHost ? "local-host-direct" : "local-alpha-gateway",
          ),
        );
      }
      return json(
        response,
        503,
        unavailable(
          "unavailable",
          productHost ? "local-host-direct" : "local-alpha-gateway",
        ),
      );
    }
  };
}

async function handleDesktopRoute(
  request,
  response,
  url,
  productHost,
  lifecycleBridge,
  origin,
  csrf,
  publicOrigin,
) {
  if (!url.pathname.startsWith("/api/desktop/")) return false;
  if (url.search !== "") {
    json(response, 404, { error: "NOT_FOUND" });
    return true;
  }
  const postRoutes = new Map([
    [
      "/api/desktop/pairing/approve",
      [validateDesktopApprove, "approvePairing"],
    ],
    ["/api/desktop/pairing/cancel", [validateDesktopCancel, "cancelPairing"]],
    [
      "/api/desktop/pairing/status",
      [validateDesktopStatus, "getPairingStatus"],
    ],
    ["/api/desktop/devices/revoke", [validateDesktopRevoke, "revokeDevice"]],
  ]);
  if (url.pathname === "/api/desktop/remote-access/reset") {
    if (request.method !== "POST") {
      json(response, 405, { error: "METHOD_NOT_ALLOWED" });
      return true;
    }
    const body = validateDesktopReset(
      await readDesktopJson(request, origin, csrf),
    );
    void body;
    if (!lifecycleBridge)
      throw new PairingSessionError("PAIRING_UNAVAILABLE", 503);
    json(response, 200, await lifecycleBridge.resetRemoteAccess());
    return true;
  }
  if (url.pathname === "/api/desktop/install/uninstall") {
    if (request.method !== "POST") {
      json(response, 405, { error: "METHOD_NOT_ALLOWED" });
      return true;
    }
    const body = validateDesktopUninstall(
      await readDesktopJson(request, origin, csrf),
    );
    void body;
    if (!lifecycleBridge)
      throw new PairingSessionError("PAIRING_UNAVAILABLE", 503);
    json(response, 200, await lifecycleBridge.uninstall());
    return true;
  }
  if (url.pathname === "/api/desktop/security") {
    if (request.method !== "GET") {
      json(response, 405, { error: "METHOD_NOT_ALLOWED" });
      return true;
    }
    validateDesktopSecurityRead(request, origin);
    response.setHeader("Cache-Control", "no-store");
    json(response, 200, {
      schema: "nomad.gateway.desktop-security.v1",
      csrf_token: csrf,
    });
    return true;
  }
  if (url.pathname === "/api/desktop/pairing/create") {
    if (request.method !== "POST") {
      json(response, 405, { error: "METHOD_NOT_ALLOWED" });
      return true;
    }
    const body = validateDesktopCreate(
      await readDesktopJson(request, origin, csrf),
    );
    if (!publicOrigin)
      throw new PairingSessionError("PAIRING_PUBLIC_ORIGIN_REQUIRED", 503);
    const created = await productHost.createPairing(body);
    const secret = Buffer.from(created.join_secret, "utf8");
    delete created.join_secret;
    try {
      const joinUrl = `${publicOrigin}/j/${created.join_id}#${secret.toString("utf8")}`;
      json(response, 200, {
        schema: "nomad.m3e.pairing.desktop-created.v1",
        join_id: created.join_id,
        join_url: joinUrl,
        expires_at: created.expires_at,
      });
      return true;
    } finally {
      secret.fill(0);
    }
  }
  if (url.pathname === "/api/desktop/devices/current") {
    if (request.method !== "POST") {
      json(response, 405, { error: "METHOD_NOT_ALLOWED" });
      return true;
    }
    const body = await readDesktopJson(request, origin, csrf);
    if (
      !body ||
      typeof body !== "object" ||
      Array.isArray(body) ||
      Object.keys(body).length !== 0
    )
      throw new PairingSessionError("PAIRING_REQUEST_INVALID", 400);
    json(response, 200, await productHost.getCurrentDevice());
    return true;
  }
  const route = postRoutes.get(url.pathname);
  if (route) {
    if (request.method !== "POST") {
      json(response, 405, { error: "METHOD_NOT_ALLOWED" });
      return true;
    }
    const body = route[0](await readDesktopJson(request, origin, csrf));
    const result = await productHost[route[1]](body);
    if (result === undefined) empty(response, 204);
    else json(response, 200, result);
    return true;
  }
  json(response, 404, { error: "NOT_FOUND" });
  return true;
}

async function handleJoinRoute(
  request,
  response,
  url,
  productHost,
  session,
  distDir,
) {
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'",
  );
  if (url.search !== "") return json(response, 404, { error: "NOT_FOUND" });
  const shell = url.pathname.match(/^\/j\/(join-[0-9a-f]{32})$/);
  if (shell) {
    if (request.method !== "GET")
      return json(response, 405, { error: "METHOD_NOT_ALLOWED" });
    validateJoinId(shell[1]);
    session.validateShellRequest(request);
    return serveJoinShell(distDir, response);
  }
  if (url.pathname.startsWith("/assets/")) {
    if (request.method !== "GET")
      return json(response, 405, { error: "METHOD_NOT_ALLOWED" });
    session.validateAssetRequest(request);
    return serveJoinAsset(distDir, url.pathname, response);
  }
  if (url.pathname === "/api/pairing/join/start") {
    if (request.method !== "POST")
      return json(response, 405, { error: "METHOD_NOT_ALLOWED" });
    const started = await productHost.startPairing(
      await session.readStart(request),
    );
    const capability = Buffer.from(started.join_cookie_capability, "utf8");
    const browserStart = started.browser_start;
    const cookieMaxAge = started.join_cookie_max_age_seconds;
    delete started.join_cookie_capability;
    try {
      response.setHeader(
        "Set-Cookie",
        session.cookieFor(capability.toString("utf8"), cookieMaxAge),
      );
      return json(response, 200, browserStart);
    } finally {
      capability.fill(0);
    }
  }
  if (url.pathname === "/api/pairing/join/confirm") {
    if (request.method !== "POST")
      return json(response, 405, { error: "METHOD_NOT_ALLOWED" });
    const { capability, body } = await session.readConfirm(request);
    return json(
      response,
      200,
      await productHost.confirmPairing(capability, body),
    );
  }
  if (url.pathname === "/api/pairing/join/complete") {
    if (request.method !== "POST")
      return json(response, 405, { error: "METHOD_NOT_ALLOWED" });
    const { capability, body } = await session.readComplete(request);
    const result = await productHost.completePairing(capability, body);
    response.setHeader("Set-Cookie", session.clearCookie());
    return json(response, 200, result);
  }
  if (url.pathname === "/api/pairing/join/abort") {
    if (request.method !== "POST")
      return json(response, 405, { error: "METHOD_NOT_ALLOWED" });
    const { capability, body } = await session.readAbort(request);
    await productHost.abortPairing(capability, body);
    response.setHeader("Set-Cookie", session.clearCookie());
    return empty(response, 204);
  }
  return json(response, 404, { error: "NOT_FOUND" });
}

function exactDesktopOrigin(host, port) {
  if (
    host !== "127.0.0.1" ||
    !Number.isInteger(Number(port)) ||
    Number(port) < 1 ||
    Number(port) > 65535
  )
    throw new Error("Desktop Gateway requires an exact loopback origin");
  return `http://127.0.0.1:${port}`;
}

function exactHttpsPublicOrigin(value) {
  let origin;
  try {
    origin = new URL(value);
  } catch {
    throw new Error("Invalid HTTPS public origin");
  }
  if (
    origin.protocol !== "https:" ||
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash
  )
    throw new Error("Invalid HTTPS public origin");
  return origin.origin;
}

async function ingestProductHost(client, store) {
  const last = store.productEnvelope();
  try {
    if (!last) return acceptProductCurrent(await client.getCurrent(), store);
    let next;
    try {
      next = await client.getStream(last.snapshot_seq);
    } catch (error) {
      if (
        error instanceof ProductHostClientError &&
        error.code === "PRODUCT_HOST_RESTARTED"
      ) {
        return acceptProductCurrent(await retryCurrent(client), store);
      }
      throw error;
    }
    // A 204 means only that the cursor did not advance. Probe current on the
    // same private capability to distinguish healthy idle from lost source.
    if (next === null)
      return acceptProductCurrent(await retryCurrent(client), store);
    try {
      const result = store.persistProduct(next);
      return store.productCurrent(
        result.wasDisconnected
          ? { hostConnectivity: "Online", clientFreshness: "Reconnecting" }
          : undefined,
      );
    } catch (error) {
      if (
        error instanceof AlphaStateError &&
        ["HOST_INSTANCE_SWITCH", "SEQ_GAP", "STALE_SEQ"].includes(error.code)
      ) {
        return acceptProductCurrent(await retryCurrent(client), store);
      }
      throw error;
    }
  } catch {
    // Preserve the durable last-good Agent facts. Connectivity is Gateway
    // observation only and never rewrites the Agent's turn_state.
    return store.productDisconnected();
  }
}

async function retryCurrent(client) {
  let failure;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return await client.getCurrent();
    } catch (error) {
      failure = error;
    }
    if (attempt < 2)
      await new Promise((resolvePromise) =>
        setTimeout(
          resolvePromise,
          25 * 2 ** attempt + Math.floor(Math.random() * 25),
        ),
      );
  }
  throw failure;
}

function acceptProductCurrent(envelope, store) {
  const result = store.persistProduct(envelope, { source: "current" });
  const reconnecting = result.wasDisconnected || result.result === "restarted";
  return store.productCurrent(
    reconnecting
      ? { hostConnectivity: "Online", clientFreshness: "Reconnecting" }
      : undefined,
  );
}

async function ingestFrames(relay, store) {
  const frames = await relay.listFrames();
  if (!Array.isArray(frames) || frames.length > MAX_RELAY_FRAMES)
    throw new ProjectionValidationError("INVALID_RELAY_RESPONSE");
  for (const frame of frames) {
    const projection = decodeFrame(frame);
    store.persist(projection);
    // persist() returns only after the FULL-synchronous SQLite transaction
    // commits. Never move this ACK above the durable commit.
    const ack = await relay.ackFrames([frame.frame_id]);
    if (!ack || ack.verified !== true || ack.acked !== 1)
      throw new Error("Relay ACK was not verified");
  }
  return store.current();
}

function decodeFrame(frame) {
  if (!frame || typeof frame !== "object" || Array.isArray(frame))
    throw new ProjectionValidationError("INVALID_FRAME");
  const keys = Object.keys(frame).sort();
  const expected = ["created", "expires", "flags", "frame_id", "payload"];
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index])
  )
    throw new ProjectionValidationError("INVALID_FRAME");
  if (typeof frame.frame_id !== "string" || !FRAME_ID.test(frame.frame_id))
    throw new ProjectionValidationError("INVALID_FRAME_ID");
  if (
    typeof frame.payload !== "string" ||
    !HEX_PAYLOAD.test(frame.payload) ||
    frame.payload.length > MAX_PROJECTION_BYTES * 2
  ) {
    throw new ProjectionValidationError("INVALID_PAYLOAD_HEX");
  }
  if (frame.flags !== 1)
    throw new ProjectionValidationError("INVALID_FRAME_FLAGS");
  if (
    !Number.isSafeInteger(frame.created) ||
    !Number.isSafeInteger(frame.expires) ||
    frame.created < 0 ||
    frame.expires < frame.created
  ) {
    throw new ProjectionValidationError("INVALID_FRAME_TIME");
  }
  const raw = Buffer.from(frame.payload, "hex");
  let parsed;
  try {
    parsed = JSON.parse(utf8Decoder.decode(raw));
  } catch {
    throw new ProjectionValidationError("INVALID_PAYLOAD_JSON");
  }
  return parsed;
}

function unavailable(status, source = "local-alpha-gateway") {
  return {
    schema: ALPHA_SCHEMA,
    status,
    session: null,
    last_applied_seq: null,
    digest: null,
    events: [],
    changes: { status: "unavailable", files: [] },
    provenance: {
      source,
      relay_ingress_verified: false,
      gateway_schema_verified: false,
    },
  };
}

function setHeaders(response) {
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'",
  );
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Cache-Control", "no-store");
}

function json(response, status, body) {
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json");
  response.end(JSON.stringify(body));
}

function empty(response, status) {
  response.statusCode = status;
  response.setHeader("Content-Length", "0");
  response.end();
}

function pairingHostStatus(error) {
  if (
    error.statusCode === 400 ||
    error.statusCode === 401 ||
    error.statusCode === 404 ||
    error.statusCode === 409 ||
    error.statusCode === 410 ||
    error.statusCode === 503
  )
    return error.statusCode;
  if (
    error.code === "PAIRING_DESKTOP_APPROVAL_REQUIRED" ||
    error.code === "PAIRING_CONFLICT" ||
    error.code === "PAIRING_REPLAY"
  )
    return 409;
  if (error.code === "PAIRING_EXPIRED") return 410;
  if (error.code === "PAIRING_NOT_FOUND") return 404;
  return 503;
}

function safePairingHostCode(error) {
  return typeof error.code === "string" &&
    /^(?:PAIRING_[A-Z_]+|INVALID_REQUEST|UNAUTHORIZED|COMMAND_UNAVAILABLE)$/.test(
      error.code,
    )
    ? error.code
    : "PAIRING_UNAVAILABLE";
}

function createLifecycleBridge(options = {}) {
  return {
    async resetRemoteAccess() {
      return invokeLifecycleCommand("reset-remote-access", options);
    },
    async uninstall() {
      return invokeLifecycleCommand("uninstall", options);
    },
  };
}

async function invokeLifecycleCommand(command, options) {
  const python =
    options.pythonBin ??
    process.env.NOMAD_DESKTOP_LIFECYCLE_PYTHON ??
    "python3";
  const repoRoot =
    options.repoRoot ??
    process.env.NOMAD_DESKTOP_LIFECYCLE_REPO_ROOT ??
    fileURLToPath(new URL("../../..", import.meta.url));
  const env = {
    ...process.env,
    ...(options.env ?? {}),
  };
  try {
    const { stdout } = await execFile(
      python,
      ["-m", "tools.nomad_web.cli", "--json", command],
      {
        cwd: repoRoot,
        env,
        timeout: 30_000,
        maxBuffer: 128 * 1024,
      },
    );
    const parsed = JSON.parse(stdout);
    if (command === "reset-remote-access") return decodeLifecycleReset(parsed);
    return decodeLifecycleUninstall(parsed);
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      "stdout" in error &&
      typeof error.stdout === "string"
    ) {
      try {
        const parsed = JSON.parse(error.stdout);
        const code =
          typeof parsed.error === "string"
            ? parsed.error
            : "PAIRING_UNAVAILABLE";
        throw new PairingSessionError(code, 409);
      } catch (decodeError) {
        if (decodeError instanceof PairingSessionError) throw decodeError;
      }
    }
    throw new PairingSessionError("PAIRING_UNAVAILABLE", 503);
  }
}

function decodeLifecycleReset(value) {
  const raw = exactObject(value, [
    "schema",
    "state",
    "mode",
    "remote_access",
    "install_state",
    "host_identity_disposition",
    "production_ready",
  ]);
  if (
    raw.schema !== "nomad.web-companion.remote-access-reset.v1" ||
    raw.state !== "STOPPED" ||
    raw.mode !== "foundation-readonly" ||
    raw.remote_access !== "CLEARED" ||
    raw.install_state !== "PRESERVED" ||
    raw.host_identity_disposition !== "retained" ||
    raw.production_ready !== false
  )
    throw new PairingSessionError("PAIRING_UNAVAILABLE", 503);
  return {
    schema: "nomad.desktop.remote-access-reset.v1",
    state: raw.state,
    remote_access: "cleared",
    install_state: "preserved",
    host_identity_disposition: "retained",
  };
}

function decodeLifecycleUninstall(value) {
  const raw = exactObject(value, [
    "schema",
    "state",
    "mode",
    "remote_access",
    "install_state",
    "host_identity_disposition",
    "production_ready",
  ]);
  if (
    raw.schema !== "nomad.web-companion.uninstall-result.v1" ||
    raw.state !== "UNINSTALLED" ||
    raw.mode !== "foundation-readonly" ||
    raw.remote_access !== "CLEARED" ||
    raw.install_state !== "REMOVED" ||
    raw.host_identity_disposition !== "retained" ||
    raw.production_ready !== false
  )
    throw new PairingSessionError("PAIRING_UNAVAILABLE", 503);
  return {
    schema: "nomad.desktop.uninstall-result.v1",
    state: raw.state,
    remote_access: "cleared",
    install_state: "removed",
    host_identity_disposition: "retained",
  };
}

function exactObject(value, expectedKeys) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new PairingSessionError("PAIRING_UNAVAILABLE", 503);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new PairingSessionError("PAIRING_UNAVAILABLE", 503);
  }
  return value;
}

function serveStatic(distDir, pathname, response) {
  const requested =
    pathname === "/"
      ? "index.html"
      : normalize(pathname)
          .replace(/^([.][.]\/)+/, "")
          .replace(/^\//, "");
  let file = join(distDir, requested);
  if (!existsSync(file) || !statSync(file).isFile())
    file = join(distDir, "index.html");
  if (!existsSync(file))
    return json(response, 503, { error: "MOBILE_BUILD_MISSING" });
  const types = {
    ".html": "text/html",
    ".js": "text/javascript",
    ".css": "text/css",
    ".svg": "image/svg+xml",
    ".png": "image/png",
  };
  response.statusCode = 200;
  response.setHeader(
    "Content-Type",
    types[extname(file)] ?? "application/octet-stream",
  );
  createReadStream(file).pipe(response);
}

function serveJoinShell(distDir, response) {
  const file = join(distDir, "index.html");
  if (!existsSync(file) || !statSync(file).isFile())
    return json(response, 503, { error: "MOBILE_BUILD_MISSING" });
  response.statusCode = 200;
  response.setHeader("Content-Type", "text/html");
  createReadStream(file).pipe(response);
}

function serveJoinAsset(distDir, pathname, response) {
  const requested = normalize(pathname)
    .replace(/^([.][.]\/)+/, "")
    .replace(/^\//, "");
  if (!requested.startsWith("assets/"))
    return json(response, 404, { error: "NOT_FOUND" });
  const file = join(distDir, requested);
  if (!existsSync(file) || !statSync(file).isFile())
    return json(response, 404, { error: "NOT_FOUND" });
  const types = {
    ".js": "text/javascript",
    ".css": "text/css",
    ".svg": "image/svg+xml",
    ".png": "image/png",
  };
  response.statusCode = 200;
  response.setHeader(
    "Content-Type",
    types[extname(file)] ?? "application/octet-stream",
  );
  createReadStream(file).pipe(response);
}

export function startGateway(config) {
  if (!isLoopbackHost(config.host))
    throw new Error("Alpha Gateway requires a loopback host");
  const routeTable = config.routeTable ?? "legacy";
  const store =
    routeTable === "join"
      ? null
      : (config.store ?? new AlphaStore(config.stateDb));
  const trustedIngressToken =
    routeTable === "join" && !config.trustedIngressToken
      ? readTrustedIngressTokenFromFd(config.trustedIngressFd)
      : config.trustedIngressToken;
  const handler = createGateway({ ...config, trustedIngressToken, store });
  const server = createHttpServer(handler);
  server.on("close", () => {
    if (routeTable !== "join" && !config.store) store.close();
  });
  return server.listen(config.port, config.host);
}

function isLoopbackHost(host) {
  if (host === "localhost" || host === "::1") return true;
  const parts = host?.split(".").map(Number);
  return (
    parts?.length === 4 &&
    parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) &&
    parts[0] === 127
  );
}

export function parseArgs(args, env = process.env) {
  const out = {
    mode: "foundation-readonly",
    host: "127.0.0.1",
    port: 4173,
    distDir: fileURLToPath(new URL("../dist", import.meta.url)),
    relayUrl: "http://127.0.0.1:8089",
    relayToken: undefined,
    productHostSocket: undefined,
    productHostSocketIdentity: undefined,
    commandKeyFd: undefined,
    routeTable: "legacy",
    publicOrigin: undefined,
    trustedIngressFd: undefined,
  };
  const allowed = new Set([
    "mode",
    "route-table",
    "host",
    "port",
    "dist-dir",
    "relay-url",
    "state-db",
    "product-host-socket",
    "product-host-socket-parent-dev",
    "product-host-socket-parent-ino",
    "product-host-socket-dev",
    "product-host-socket-ino",
    "command-key-fd",
    "public-origin",
    "trusted-ingress-fd",
  ]);
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index]?.replace(/^--/, "");
    if (!allowed.has(name) || args[index + 1] === undefined)
      throw new Error(`Unsupported or incomplete option: ${args[index] ?? ""}`);
    out[name.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] =
      args[index + 1];
  }
  out.port = Number(out.port);
  if (!Number.isInteger(out.port) || out.port < 0 || out.port > 65535)
    throw new Error("Invalid --port");
  if (!["foundation-readonly", "official-agent-local"].includes(out.mode))
    throw new Error("Invalid --mode");
  if (!["legacy", "desktop", "join"].includes(out.routeTable))
    throw new Error("Invalid --route-table");
  if (out.mode === "official-agent-local") {
    if (!out.productHostSocket)
      throw new Error("Missing --product-host-socket");
    const identity = {};
    for (const [option, field] of [
      ["productHostSocketParentDev", "parentDev"],
      ["productHostSocketParentIno", "parentIno"],
      ["productHostSocketDev", "socketDev"],
      ["productHostSocketIno", "socketIno"],
    ]) {
      if (typeof out[option] !== "string" || !/^[1-9][0-9]*$/.test(out[option]))
        throw new Error("Missing or invalid product Host socket identity");
      identity[field] = out[option];
      delete out[option];
    }
    out.productHostSocketIdentity = identity;
    if (out.commandKeyFd !== "11")
      throw new Error("Missing or invalid --command-key-fd");
    out.commandKeyFd = 11;
    if (out.routeTable === "join") {
      if (out.trustedIngressFd !== "12")
        throw new Error("Missing or invalid --trusted-ingress-fd");
      out.trustedIngressFd = 12;
      if (!out.publicOrigin) throw new Error("Missing --public-origin");
    } else if (out.routeTable === "desktop") {
      if (!out.publicOrigin) throw new Error("Missing --public-origin");
      if (out.trustedIngressFd !== undefined)
        throw new Error("Trusted ingress capability requires join route table");
    } else if (out.publicOrigin || out.trustedIngressFd !== undefined)
      throw new Error(
        "Pairing public origin requires desktop or join route table",
      );
    if (
      out.routeTable !== "join" &&
      out.routeTable !== "legacy" &&
      out.commandKeyFd !== 11
    )
      throw new Error(
        "Pairing Gateway requires authenticated Product Host transport",
      );
  } else {
    if (out.productHostSocket || out.commandKeyFd !== undefined)
      throw new Error(
        "Product Host capability requires official-agent-local mode",
      );
    out.relayToken = env.NOMAD_ALPHA_RELAY_TOKEN;
    if (!out.relayToken) throw new Error("Missing NOMAD_ALPHA_RELAY_TOKEN");
  }
  if (out.routeTable !== "join" && (!out.stateDb || out.stateDb === ":memory:"))
    throw new Error(
      "Desktop Gateway requires an explicit file-backed --state-db",
    );
  if (out.routeTable === "join" && out.stateDb)
    throw new Error("Join Gateway must not use --state-db");
  return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const config = parseArgs(process.argv.slice(2));
  startGateway(config);
  console.log(
    JSON.stringify({
      ready: true,
      protocol: "http",
      host: config.host,
      port: config.port,
    }),
  );
}
