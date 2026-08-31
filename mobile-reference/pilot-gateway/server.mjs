#!/usr/bin/env node
import { createReadStream, existsSync, fstatSync, statSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { Socket } from "node:net";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { TextDecoder } from "node:util";
import { randomBytes } from "node:crypto";
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
  validateDesktopRead,
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
  canonicalJson,
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
const MAX_LIFECYCLE_FRAME_BYTES = 4096;
const LIFECYCLE_BOOTSTRAP_SCHEMA =
  "nomad.web-companion.lifecycle-bootstrap.v1";
const LIFECYCLE_REQUEST_SCHEMA =
  "nomad.web-companion.lifecycle-request.v1";
const LIFECYCLE_COMMIT_SCHEMA =
  "nomad.web-companion.lifecycle-commit.v1";
const LIFECYCLE_RESPONSE_SCHEMA =
  "nomad.web-companion.lifecycle-response.v1";
const HEX64 = /^[0-9a-f]{64}$/;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

export function createGateway(options) {
  const mode = options.mode ?? "foundation-readonly";
  if (!["foundation-readonly", "official-agent-local"].includes(mode))
    throw new Error("Unsupported Gateway mode");
  const routeTable = options.routeTable ?? "legacy";
  if (!["legacy", "desktop", "join"].includes(routeTable))
    throw new Error("Unsupported Gateway route table");
  if (routeTable !== "legacy" && mode !== "official-agent-local")
    throw new Error("Pairing route tables require official-agent-local mode");
  const diagnosticLoopback = options.diagnosticLoopback === true;
  if (
    diagnosticLoopback &&
    (mode !== "official-agent-local" ||
      routeTable !== "desktop" ||
      options.host !== "127.0.0.1")
  )
    throw new Error(
      "Diagnostic loopback requires official-agent-local desktop on 127.0.0.1",
    );
  if (
    diagnosticLoopback &&
    (options.lifecycleChannelFd !== undefined ||
      options.lifecycleBridge !== undefined ||
      options.lifecycleBridgeOptions !== undefined)
  )
    throw new Error(
      "Diagnostic loopback must not receive lifecycle capabilities",
    );
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
    routeTable === "desktop" && !diagnosticLoopback
      ? lazyLifecycleBridge(options)
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
            diagnosticLoopback,
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
        if (diagnosticLoopback)
          return json(response, 404, { error: "DIAGNOSTIC_UNAVAILABLE" });
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
        if (diagnosticLoopback)
          return json(response, 404, { error: "DIAGNOSTIC_UNAVAILABLE" });
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
  diagnosticLoopback,
) {
  if (!url.pathname.startsWith("/api/desktop/")) return false;
  if (url.search !== "") {
    json(response, 404, { error: "NOT_FOUND" });
    return true;
  }
  if (
    diagnosticLoopback &&
    (url.pathname.startsWith("/api/desktop/remote-access/") ||
      url.pathname === "/api/desktop/install/uninstall" ||
      url.pathname === "/api/desktop/lifecycle/status")
  ) {
    json(response, 404, { error: "DIAGNOSTIC_UNAVAILABLE" });
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
    const accepted = await lifecycleBridge.begin("reset_remote_access", body.request_id);
    response.once("finish", () => void lifecycleBridge.commit());
    json(response, 202, accepted);
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
    const accepted = await lifecycleBridge.begin("uninstall", body.request_id);
    response.once("finish", () => void lifecycleBridge.commit());
    json(response, 202, accepted);
    return true;
  }
  if (url.pathname === "/api/desktop/lifecycle/status") {
    if (request.method !== "GET") {
      json(response, 405, { error: "METHOD_NOT_ALLOWED" });
      return true;
    }
    validateDesktopRead(request, origin, csrf);
    const projection = lifecycleBridge?.status();
    if (!projection) {
      json(response, 404, { error: "LIFECYCLE_OPERATION_NOT_FOUND" });
      return true;
    }
    json(response, 200, projection);
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

export function createLifecycleBridge(options = {}) {
  const transport = options.transport ?? lifecycleTransport(options.channelFd);
  const ready = transport.receive().then(validateLifecycleBootstrap);
  let current = null;
  let beginning = false;
  let commitFlight = null;
  return {
    async begin(operation, requestId) {
      if (!new Set(["reset_remote_access", "uninstall"]).has(operation))
        throw new PairingSessionError("LIFECYCLE_UNAVAILABLE", 503);
      if (beginning || current !== null)
        throw new PairingSessionError("LIFECYCLE_OPERATION_IN_PROGRESS", 409);
      if (typeof requestId !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(requestId))
        throw new PairingSessionError("LIFECYCLE_REQUEST_INVALID", 400);
      beginning = true;
      try {
        const binding = await ready;
        const request = {
          schema: LIFECYCLE_REQUEST_SCHEMA,
          operation,
          confirm: true,
          request_id: requestId,
          run_id: binding.run_id,
          bundle_digest: binding.bundle_digest,
          install_sequence: binding.install_sequence,
          gateway_identity: binding.gateway_identity,
          coordinator_identity: binding.coordinator_identity,
        };
        current = {
          request, challenge: null, publicState: "outcome_unknown",
          error: "LIFECYCLE_OUTCOME_UNKNOWN",
        };
        transport.send(request);
        const accepted = validateLifecycleResponse(
          await transport.receive(), request, "ACCEPTED",
        );
        current.challenge = accepted.commit_challenge;
        current.publicState = "accepted";
        current.error = null;
        return lifecycleAccepted(request.request_id);
      } finally {
        beginning = false;
      }
    },
    commit() {
      if (commitFlight) return commitFlight;
      if (current === null) return Promise.resolve();
      current.publicState = "closing";
      const commit = {
        ...current.request,
        schema: LIFECYCLE_COMMIT_SCHEMA,
        commit_challenge: current.challenge,
      };
      commitFlight = (async () => {
        transport.send(commit);
        const completed = validateLifecycleResponse(
          await transport.receive(),
          current.request,
        );
        current.publicState =
          completed.state === "COMPLETED"
            ? "completed"
            : completed.state === "OUTCOME_UNKNOWN"
              ? "outcome_unknown"
              : "failed";
        current.error = completed.error;
        current.challenge = null;
      })().catch(() => {
        // Closing the Gateway is part of both operations. A lost channel is
        // therefore not evidence of success or failure; retain closing.
      });
      return commitFlight;
    },
    status() {
      if (current === null) return null;
      return {
        schema: "nomad.desktop.lifecycle-status.v1",
        operation_id: current.request.request_id,
        operation: current.request.operation,
        state: current.publicState,
        terminal: new Set(["completed", "failed", "outcome_unknown"]).has(
          current.publicState,
        ),
        error: current.error,
        recovery: lifecycleRecovery(current.publicState),
      };
    },
  };
}

function lifecycleRecovery(state) {
  if (state === "failed") return "RUN_DIAGNOSTICS";
  if (state === "outcome_unknown") return "RUN_OPERATION_STATUS";
  return null;
}

function lazyLifecycleBridge(options) {
  if (options.lifecycleBridge) return options.lifecycleBridge;
  let bridge = null;
  const get = () => {
    bridge ??= createLifecycleBridge({
      channelFd: options.lifecycleChannelFd,
      ...(options.lifecycleBridgeOptions ?? {}),
    });
    return bridge;
  };
  return {
    begin(operation, requestId) { return get().begin(operation, requestId); },
    commit() { return get().commit(); },
    status() { return get().status(); },
  };
}

function lifecycleAccepted(operationId) {
  return {
    schema: "nomad.desktop.lifecycle-accepted.v1",
    state: "accepted",
    operation_id: operationId,
  };
}

function lifecycleTransport(fd) {
  if (!Number.isInteger(fd) || fd !== 12)
    throw new PairingSessionError("LIFECYCLE_UNAVAILABLE", 503);
  let info;
  try {
    info = fstatSync(fd);
  } catch {
    throw new PairingSessionError("LIFECYCLE_UNAVAILABLE", 503);
  }
  if (!info.isSocket())
    throw new PairingSessionError("LIFECYCLE_UNAVAILABLE", 503);
  const channel = new Socket({ fd, readable: true, writable: true });
  let buffered = Buffer.alloc(0);
  const frames = [];
  const waiters = [];
  let failure = null;
  const rejectAll = (error) => {
    if (failure) return;
    failure = error;
    while (waiters.length) waiters.shift().reject(error);
  };
  channel.on("data", (chunk) => {
    buffered = Buffer.concat([buffered, chunk]);
    while (buffered.length >= 4) {
      const length = buffered.readUInt32BE(0);
      if (length < 1 || length > MAX_LIFECYCLE_FRAME_BYTES) {
        rejectAll(new Error("LIFECYCLE_FRAME_INVALID"));
        channel.destroy();
        return;
      }
      if (buffered.length < length + 4) return;
      const raw = buffered.subarray(4, length + 4);
      buffered = buffered.subarray(length + 4);
      let value;
      try {
        const text = utf8Decoder.decode(raw);
        value = strictLifecycleJson(text);
        if (canonicalJson(value) !== text) throw new Error("noncanonical");
      } catch {
        rejectAll(new Error("LIFECYCLE_FRAME_INVALID"));
        channel.destroy();
        return;
      }
      if (waiters.length) waiters.shift().resolve(value);
      else frames.push(value);
    }
  });
  channel.on("error", rejectAll);
  channel.on("close", () => rejectAll(new Error("LIFECYCLE_CHANNEL_CLOSED")));
  return {
    send(value) {
      if (failure) throw failure;
      const raw = Buffer.from(canonicalJson(value), "utf8");
      if (raw.length < 1 || raw.length > MAX_LIFECYCLE_FRAME_BYTES)
        throw new Error("LIFECYCLE_FRAME_INVALID");
      const frame = Buffer.allocUnsafe(raw.length + 4);
      frame.writeUInt32BE(raw.length, 0);
      raw.copy(frame, 4);
      channel.write(frame);
    },
    receive() {
      if (frames.length) return Promise.resolve(frames.shift());
      if (failure) return Promise.reject(failure);
      return new Promise((resolve, reject) => waiters.push({ resolve, reject }));
    },
  };
}

function validateLifecycleBootstrap(value) {
  const raw = exactObject(value, [
    "schema", "run_id", "bundle_digest", "install_sequence",
    "gateway_identity", "coordinator_identity",
  ]);
  if (
    raw.schema !== LIFECYCLE_BOOTSTRAP_SCHEMA ||
    !HEX64.test(raw.run_id ?? "") ||
    !HEX64.test(raw.bundle_digest ?? "") ||
    !Number.isSafeInteger(raw.install_sequence) ||
    raw.install_sequence < 1 ||
    !HEX64.test(raw.gateway_identity ?? "") ||
    !HEX64.test(raw.coordinator_identity ?? "")
  )
    throw new PairingSessionError("LIFECYCLE_UNAVAILABLE", 503);
  return raw;
}

function validateLifecycleResponse(value, request, requiredState = null) {
  const raw = exactObject(value, [
    "schema", "request_id", "operation", "state", "result",
    "error", "commit_challenge",
  ]);
  const states = new Set(["ACCEPTED", "COMPLETED", "FAILED", "OUTCOME_UNKNOWN"]);
  if (
    raw.schema !== LIFECYCLE_RESPONSE_SCHEMA ||
    raw.request_id !== request.request_id ||
    raw.operation !== request.operation ||
    !states.has(raw.state) ||
    (requiredState !== null && raw.state !== requiredState)
  )
    throw new PairingSessionError("LIFECYCLE_UNAVAILABLE", 503);
  if (raw.state === "ACCEPTED") {
    if (!HEX64.test(raw.commit_challenge ?? "") || raw.result !== null || raw.error !== null)
      throw new PairingSessionError("LIFECYCLE_UNAVAILABLE", 503);
  } else if (raw.commit_challenge !== null) {
    throw new PairingSessionError("LIFECYCLE_UNAVAILABLE", 503);
  }
  return raw;
}

function strictLifecycleJson(raw) {
  let index = 0; let nodes = 0;
  const ws = () => { while (" \t\r\n".includes(raw[index] ?? "!")) index += 1; };
  const value = (depth) => { ws(); if (++nodes > 2048 || depth > 12) throw new Error("budget"); const char = raw[index]; if (char === "{") return objectValue(depth + 1); if (char === "[") return arrayValue(depth + 1); if (char === '"') return stringValue(); for (const pair of [["true", true], ["false", false], ["null", null]]) if (raw.startsWith(pair[0], index)) { index += pair[0].length; return pair[1]; } const match = raw.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/); if (!match) throw new Error("value"); index += match[0].length; const number = Number(match[0]); if (!Number.isFinite(number)) throw new Error("number"); return number; };
  const stringValue = () => { const start = index++; while (index < raw.length) { const code = raw.charCodeAt(index++); if (code === 34) return JSON.parse(raw.slice(start, index)); if (code < 32) throw new Error("string"); if (code === 92) { const escaped = raw[index++]; if (escaped === "u") { if (!/^[0-9a-fA-F]{4}$/.test(raw.slice(index, index + 4))) throw new Error("escape"); index += 4; } else if (!'"\\/bfnrt'.includes(escaped ?? "")) throw new Error("escape"); } } throw new Error("string"); };
  const objectValue = (depth) => { index += 1; ws(); const result = {}; const keys = new Set(); if (raw[index] === "}") { index += 1; return result; } while (true) { ws(); if (raw[index] !== '"') throw new Error("key"); const key = stringValue(); if (keys.has(key)) throw new Error("duplicate"); keys.add(key); ws(); if (raw[index++] !== ":") throw new Error("colon"); result[key] = value(depth); ws(); const delimiter = raw[index++]; if (delimiter === "}") return result; if (delimiter !== ",") throw new Error("delimiter"); } };
  const arrayValue = (depth) => { index += 1; ws(); const result = []; if (raw[index] === "]") { index += 1; return result; } while (true) { result.push(value(depth)); ws(); const delimiter = raw[index++]; if (delimiter === "]") return result; if (delimiter !== ",") throw new Error("delimiter"); } };
  const parsed = value(0); ws(); if (index !== raw.length) throw new Error("trailing"); return parsed;
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
    lifecycleChannelFd: undefined,
    diagnosticLoopback: false,
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
    "lifecycle-channel-fd",
  ]);
  for (let index = 0; index < args.length; ) {
    if (args[index] === "--diagnostic-loopback") {
      if (out.diagnosticLoopback)
        throw new Error("Duplicate --diagnostic-loopback");
      out.diagnosticLoopback = true;
      index += 1;
      continue;
    }
    const name = args[index]?.replace(/^--/, "");
    if (!allowed.has(name) || args[index + 1] === undefined)
      throw new Error(`Unsupported or incomplete option: ${args[index] ?? ""}`);
    out[name.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] =
      args[index + 1];
    index += 2;
  }
  out.port = Number(out.port);
  if (!Number.isInteger(out.port) || out.port < 0 || out.port > 65535)
    throw new Error("Invalid --port");
  if (!["foundation-readonly", "official-agent-local"].includes(out.mode))
    throw new Error("Invalid --mode");
  if (!["legacy", "desktop", "join"].includes(out.routeTable))
    throw new Error("Invalid --route-table");
  if (
    out.diagnosticLoopback &&
    (out.mode !== "official-agent-local" ||
      out.routeTable !== "desktop" ||
      out.host !== "127.0.0.1")
  )
    throw new Error(
      "--diagnostic-loopback requires official-agent-local desktop on 127.0.0.1",
    );
  if (out.diagnosticLoopback && out.lifecycleChannelFd !== undefined)
    throw new Error(
      "--diagnostic-loopback must not use --lifecycle-channel-fd",
    );
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
      if (!out.diagnosticLoopback && out.lifecycleChannelFd !== "12")
        throw new Error("Missing or invalid --lifecycle-channel-fd");
      if (!out.diagnosticLoopback) out.lifecycleChannelFd = 12;
      if (out.trustedIngressFd !== undefined)
        throw new Error("Trusted ingress capability requires join route table");
    } else if (out.publicOrigin || out.trustedIngressFd !== undefined || out.lifecycleChannelFd !== undefined)
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
