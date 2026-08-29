import { timingSafeEqual } from "node:crypto";
import { closeSync, fstatSync, readSync } from "node:fs";
import { TextDecoder } from "node:util";

export const JOIN_COOKIE_NAME = "__Host-nomad-join";
export const MAX_JOIN_COOKIE_AGE_SECONDS = 120;
export const MAX_PAIRING_REQUEST_BYTES = 4 * 1024;

const JOIN_ID = /^join-[0-9a-f]{32}$/;
const CHALLENGE_ID = /^challenge-[A-Za-z0-9_-]{8,128}$/;
const DEVICE_ALIAS = /^device-[A-Za-z0-9_-]{8,128}$/;
const LIFECYCLE_REQUEST_ID = /^[A-Za-z0-9_-]{16,128}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const COMPARISON_CODE = /^[0-9]{6}$/;
const TRUST_HEADER = "x-nomad-trusted-ingress";
const utf8 = new TextDecoder("utf-8", { fatal: true });

export class PairingSessionError extends Error {
  constructor(code, statusCode = 403) {
    super(code);
    this.name = "PairingSessionError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

export function readTrustedIngressTokenFromFd(fd) {
  if (!Number.isInteger(fd) || fd < 3)
    reject("INVALID_TRUSTED_INGRESS_FD", 500);
  const source = Buffer.alloc(33);
  let offset = 0;
  try {
    const info = fstatSync(fd);
    if (!info.isFIFO() && !info.isSocket())
      reject("INVALID_TRUSTED_INGRESS_FD", 500);
    while (offset < source.length) {
      const count = readSync(fd, source, offset, source.length - offset, null);
      if (count === 0) break;
      offset += count;
    }
    if (offset !== 32) reject("INVALID_TRUSTED_INGRESS_TOKEN", 500);
    return source.subarray(0, 32).toString("base64url");
  } catch (error) {
    if (error instanceof PairingSessionError) throw error;
    reject("INVALID_TRUSTED_INGRESS_FD", 500);
  } finally {
    source.fill(0);
    try {
      closeSync(fd);
    } catch {}
  }
}

/**
 * The join listener receives cleartext HTTP only from a reviewed local ingress.
 * The ingress contract is explicit: loopback peer, an unguessable marker that
 * the ingress strips/replaces, and exact forwarded HTTPS authority. Merely
 * setting Origin or X-Forwarded-Proto on ordinary HTTP is never sufficient.
 */
export function createPairingSession(options) {
  const publicOrigin = parseHttpsOrigin(options?.publicOrigin);
  const trustedIngressToken = validateCapability(
    options?.trustedIngressToken,
    "INVALID_TRUSTED_INGRESS",
  );
  return {
    publicOrigin: publicOrigin.origin,
    validateShellRequest(request) {
      requireTrustedIngress(request, publicOrigin, trustedIngressToken);
      exactHeader(request, "sec-fetch-mode", "navigate");
      exactHeader(request, "sec-fetch-dest", "document");
      const site = oneHeader(request, "sec-fetch-site");
      if (!["none", "same-origin", "cross-site"].includes(site))
        reject("FETCH_METADATA_REJECTED");
    },
    validateAssetRequest(request) {
      requireTrustedIngress(request, publicOrigin, trustedIngressToken);
      optionalExactHeader(request, "origin", publicOrigin.origin);
      exactHeader(request, "sec-fetch-site", "same-origin");
      const mode = oneHeader(request, "sec-fetch-mode");
      const destination = oneHeader(request, "sec-fetch-dest");
      const valid =
        (mode === "cors" && ["script", "font"].includes(destination)) ||
        (mode === "no-cors" &&
          ["script", "style", "image", "font"].includes(destination));
      if (!valid) reject("FETCH_METADATA_REJECTED");
    },
    async readStart(request) {
      const value = await readPairingJson(
        request,
        publicOrigin,
        trustedIngressToken,
      );
      exactObject(value, [
        "join_id",
        "join_secret",
        "device_signing_public_key_sec1",
        "device_agreement_public_key_sec1",
      ]);
      if (
        !JOIN_ID.test(value.join_id ?? "") ||
        !base64urlBytes(value.join_secret, 32) ||
        !sec1PublicKey(value.device_signing_public_key_sec1) ||
        !sec1PublicKey(value.device_agreement_public_key_sec1) ||
        value.device_signing_public_key_sec1 ===
          value.device_agreement_public_key_sec1
      ) {
        reject("PAIRING_REQUEST_INVALID", 400);
      }
      return value;
    },
    async readConfirm(request) {
      const capability = requireJoinCookie(request);
      const value = await readPairingJson(
        request,
        publicOrigin,
        trustedIngressToken,
      );
      exactObject(value, [
        "challenge_id",
        "expected_epoch",
        "device_signing_signature_p1363",
        "device_agreement_mac",
      ]);
      if (
        !CHALLENGE_ID.test(value.challenge_id ?? "") ||
        !positive(value.expected_epoch) ||
        !base64urlBytes(value.device_signing_signature_p1363, 64) ||
        !base64urlBytes(value.device_agreement_mac, 32)
      )
        reject("PAIRING_REQUEST_INVALID", 400);
      return { capability, body: value };
    },
    async readComplete(request) {
      const capability = requireJoinCookie(request);
      const value = await readPairingJson(
        request,
        publicOrigin,
        trustedIngressToken,
      );
      exactObject(value, [
        "schema",
        "challenge_id",
        "expected_epoch",
        "device_vault_signature_p1363",
      ]);
      if (
        value.schema !== "nomad.m3e.pairing.vault-commit.v1" ||
        !CHALLENGE_ID.test(value.challenge_id ?? "") ||
        !positive(value.expected_epoch) ||
        !base64urlBytes(value.device_vault_signature_p1363, 64)
      )
        reject("PAIRING_REQUEST_INVALID", 400);
      return { capability, body: value };
    },
    async readAbort(request) {
      const capability = requireJoinCookie(request);
      const value = await readPairingJson(
        request,
        publicOrigin,
        trustedIngressToken,
      );
      exactObject(value, ["schema", "challenge_id", "expected_epoch"]);
      if (
        value.schema !== "nomad.m3e.pairing.abort.v1" ||
        !CHALLENGE_ID.test(value.challenge_id ?? "") ||
        !positive(value.expected_epoch)
      )
        reject("PAIRING_REQUEST_INVALID", 400);
      return { capability, body: value };
    },
    cookieFor(capability, maxAgeSeconds) {
      validateCapability(capability, "PAIRING_CAPABILITY_INVALID");
      if (
        !Number.isSafeInteger(maxAgeSeconds) ||
        maxAgeSeconds < 1 ||
        maxAgeSeconds > MAX_JOIN_COOKIE_AGE_SECONDS
      )
        reject("PAIRING_SESSION_EXPIRED", 410);
      return serializeCookie(capability, maxAgeSeconds);
    },
    clearCookie() {
      return serializeCookie("", 0);
    },
  };
}

export function validateJoinId(value) {
  if (!JOIN_ID.test(value ?? "")) reject("JOIN_NOT_FOUND", 404);
  return value;
}

export function validateDesktopCreate(value) {
  exactObject(value, ["schema"]);
  if (value.schema !== "nomad.m3e.pairing.create.v1")
    reject("PAIRING_REQUEST_INVALID", 400);
  return value;
}

export function validateDesktopApprove(value) {
  exactObject(value, [
    "schema",
    "join_id",
    "challenge_id",
    "expected_epoch",
    "comparison_code",
  ]);
  if (
    value.schema !== "nomad.m3e.pairing.desktop-approve.v1" ||
    !JOIN_ID.test(value.join_id ?? "") ||
    !CHALLENGE_ID.test(value.challenge_id ?? "") ||
    !positive(value.expected_epoch) ||
    !COMPARISON_CODE.test(value.comparison_code ?? "")
  )
    reject("PAIRING_REQUEST_INVALID", 400);
  return value;
}

export function validateDesktopCancel(value) {
  exactObject(value, ["schema", "join_id"]);
  if (
    value.schema !== "nomad.m3e.pairing.cancel.v1" ||
    !JOIN_ID.test(value.join_id ?? "")
  )
    reject("PAIRING_REQUEST_INVALID", 400);
  return value;
}

export function validateDesktopStatus(value) {
  exactObject(value, ["schema", "join_id"]);
  if (
    value.schema !== "nomad.m3e.pairing.status.v1" ||
    !JOIN_ID.test(value.join_id ?? "")
  )
    reject("PAIRING_REQUEST_INVALID", 400);
  return value;
}

export function validateDesktopRevoke(value) {
  // Reuse the already-frozen Product Host request shape. Its response, not
  // its request, carries nomad.product-host.device-revoke.v1.
  exactObject(value, ["device_alias", "expected_epoch"]);
  if (
    !DEVICE_ALIAS.test(value.device_alias ?? "") ||
    !positive(value.expected_epoch)
  )
    reject("PAIRING_REQUEST_INVALID", 400);
  return value;
}

export function validateDesktopReset(value) {
  exactObject(value, ["schema", "request_id"]);
  if (value.schema !== "nomad.desktop.remote-access-reset.v1" || !LIFECYCLE_REQUEST_ID.test(value.request_id ?? ""))
    reject("PAIRING_REQUEST_INVALID", 400);
  return value;
}

export function validateDesktopUninstall(value) {
  exactObject(value, ["schema", "request_id"]);
  if (value.schema !== "nomad.desktop.uninstall.v1" || !LIFECYCLE_REQUEST_ID.test(value.request_id ?? ""))
    reject("PAIRING_REQUEST_INVALID", 400);
  return value;
}

export async function readDesktopJson(request, expectedOrigin, csrfToken) {
  const origin = parseLoopbackOrigin(expectedOrigin);
  requireHost(request, origin);
  exactHeader(request, "origin", origin.origin);
  exactHeader(request, "sec-fetch-site", "same-origin");
  exactHeader(request, "sec-fetch-mode", "cors");
  exactHeader(request, "sec-fetch-dest", "empty");
  exactSecretHeader(
    request,
    "x-nomad-csrf",
    validateCapability(csrfToken, "CSRF_REJECTED"),
    "CSRF_REJECTED",
  );
  return readStrictBody(request);
}

export function validateDesktopSecurityRead(request, expectedOrigin) {
  const origin = parseLoopbackOrigin(expectedOrigin);
  requireHost(request, origin);
  optionalExactHeader(request, "origin", origin.origin);
  exactHeader(request, "sec-fetch-site", "same-origin");
  exactHeader(request, "sec-fetch-mode", "cors");
  exactHeader(request, "sec-fetch-dest", "empty");
  validateEmptyRequest(request);
}

export function validateDesktopRead(request, expectedOrigin, csrfToken) {
  const origin = parseLoopbackOrigin(expectedOrigin);
  requireHost(request, origin);
  optionalExactHeader(request, "origin", origin.origin);
  exactHeader(request, "sec-fetch-site", "same-origin");
  exactHeader(request, "sec-fetch-mode", "cors");
  exactHeader(request, "sec-fetch-dest", "empty");
  exactSecretHeader(
    request,
    "x-nomad-csrf",
    validateCapability(csrfToken, "CSRF_REJECTED"),
    "CSRF_REJECTED",
  );
  validateEmptyRequest(request);
}

async function readPairingJson(request, origin, token) {
  requireTrustedIngress(request, origin, token);
  exactHeader(request, "origin", origin.origin);
  exactHeader(request, "sec-fetch-site", "same-origin");
  exactHeader(request, "sec-fetch-mode", "cors");
  exactHeader(request, "sec-fetch-dest", "empty");
  return readStrictBody(request);
}

async function readStrictBody(request) {
  exactHeader(request, "content-type", "application/json");
  if (
    rawHeaderValues(request, "content-encoding").length !== 0 ||
    rawHeaderValues(request, "transfer-encoding").length !== 0
  )
    reject("PAIRING_FRAMING_INVALID", 400);
  const lengths = rawHeaderValues(request, "content-length");
  if (lengths.length !== 1 || !/^[1-9][0-9]*$/.test(lengths[0]))
    reject("PAIRING_FRAMING_INVALID", 400);
  const declared = Number(lengths[0]);
  if (!Number.isSafeInteger(declared) || declared > MAX_PAIRING_REQUEST_BYTES)
    reject("PAIRING_FRAMING_INVALID", 400);
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > declared || size > MAX_PAIRING_REQUEST_BYTES) {
      request.destroy();
      reject("PAIRING_FRAMING_INVALID", 400);
    }
    chunks.push(chunk);
  }
  if (size !== declared) reject("PAIRING_FRAMING_INVALID", 400);
  try {
    return strictJson(utf8.decode(Buffer.concat(chunks)));
  } catch {
    reject("PAIRING_JSON_INVALID", 400);
  }
}

function requireTrustedIngress(request, origin, token) {
  if (!isLoopbackAddress(request.socket?.remoteAddress))
    reject("TRUSTED_INGRESS_REQUIRED");
  requireHost(request, origin);
  if (rawHeaderValues(request, "forwarded").length !== 0)
    reject("TRUSTED_INGRESS_REQUIRED");
  exactHeader(
    request,
    "x-forwarded-proto",
    "https",
    "TRUSTED_INGRESS_REQUIRED",
  );
  exactHeader(
    request,
    "x-forwarded-host",
    origin.host,
    "TRUSTED_INGRESS_REQUIRED",
  );
  exactSecretHeader(request, TRUST_HEADER, token, "TRUSTED_INGRESS_REQUIRED");
}

function validateEmptyRequest(request) {
  if (
    rawHeaderValues(request, "content-encoding").length !== 0 ||
    rawHeaderValues(request, "transfer-encoding").length !== 0
  )
    reject("PAIRING_FRAMING_INVALID", 400);
  const lengths = rawHeaderValues(request, "content-length");
  if (lengths.length > 1) reject("PAIRING_FRAMING_INVALID", 400);
  if (lengths.length === 1 && lengths[0] !== "0")
    reject("PAIRING_FRAMING_INVALID", 400);
}

function requireJoinCookie(request) {
  const headers = rawHeaderValues(request, "cookie");
  if (headers.length !== 1) reject("JOIN_COOKIE_REQUIRED", 401);
  let found = null;
  for (const part of headers[0].split(";")) {
    const item = part.trim();
    const equals = item.indexOf("=");
    if (equals < 1) reject("JOIN_COOKIE_INVALID", 401);
    const name = item.slice(0, equals);
    const value = item.slice(equals + 1);
    if (name === JOIN_COOKIE_NAME) {
      if (found !== null) reject("JOIN_COOKIE_INVALID", 401);
      found = validateCapability(value, "JOIN_COOKIE_INVALID");
    }
  }
  if (found === null) reject("JOIN_COOKIE_REQUIRED", 401);
  return found;
}

function serializeCookie(value, maxAge) {
  return `${JOIN_COOKIE_NAME}=${value}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

function parseHttpsOrigin(value) {
  let origin;
  try {
    origin = new URL(value);
  } catch {
    reject("INVALID_PUBLIC_ORIGIN", 500);
  }
  if (
    origin.protocol !== "https:" ||
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash
  )
    reject("INVALID_PUBLIC_ORIGIN", 500);
  return origin;
}

function parseLoopbackOrigin(value) {
  let origin;
  try {
    origin = new URL(value);
  } catch {
    reject("INVALID_DESKTOP_ORIGIN", 500);
  }
  if (
    origin.protocol !== "http:" ||
    origin.hostname !== "127.0.0.1" ||
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash ||
    !origin.port
  )
    reject("INVALID_DESKTOP_ORIGIN", 500);
  return origin;
}

function requireHost(request, origin) {
  exactHeader(request, "host", origin.host, "ORIGIN_REJECTED");
}
function exactHeader(
  request,
  name,
  expected,
  code = "FETCH_METADATA_REJECTED",
) {
  const values = rawHeaderValues(request, name);
  if (values.length !== 1 || values[0] !== expected) reject(code);
}
function optionalExactHeader(request, name, expected) {
  const values = rawHeaderValues(request, name);
  if (values.length > 1 || (values.length === 1 && values[0] !== expected))
    reject("ORIGIN_REJECTED");
}
function oneHeader(request, name) {
  const values = rawHeaderValues(request, name);
  if (values.length !== 1) reject("FETCH_METADATA_REJECTED");
  return values[0];
}
function exactSecretHeader(request, name, expected, code) {
  const values = rawHeaderValues(request, name);
  if (values.length !== 1) reject(code);
  const actual = Buffer.from(values[0]);
  const wanted = Buffer.from(expected);
  if (actual.length !== wanted.length || !timingSafeEqual(actual, wanted))
    reject(code);
}
function rawHeaderValues(request, name) {
  const values = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index].toLowerCase() === name)
      values.push(request.rawHeaders[index + 1]);
  }
  return values;
}
function isLoopbackAddress(value) {
  return (
    value === "127.0.0.1" || value === "::1" || value === "::ffff:127.0.0.1"
  );
}
function validateCapability(value, code) {
  if (!base64urlBytes(value, 32))
    reject(code, code.startsWith("INVALID_") ? 500 : 401);
  return value;
}
function sec1PublicKey(value) {
  if (!base64urlBytes(value, 65)) return false;
  return Buffer.from(value, "base64url")[0] === 4;
}
function base64urlBytes(value, bytes) {
  if (typeof value !== "string" || !BASE64URL.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length === bytes && decoded.toString("base64url") === value;
}
function positive(value) {
  return Number.isSafeInteger(value) && value > 0;
}
function exactObject(value, keys) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  )
    reject("PAIRING_REQUEST_INVALID", 400);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  )
    reject("PAIRING_REQUEST_INVALID", 400);
}
function strictJson(raw) {
  let index = 0;
  let nodes = 0;
  const ws = () => {
    while (" \t\r\n".includes(raw[index] ?? "!")) index += 1;
  };
  const value = (depth) => {
    ws();
    if (++nodes > 512 || depth > 8) throw new Error("budget");
    const char = raw[index];
    if (char === "{") return objectValue(depth + 1);
    if (char === "[") return arrayValue(depth + 1);
    if (char === '"') return stringValue();
    for (const pair of [
      ["true", true],
      ["false", false],
      ["null", null],
    ])
      if (raw.startsWith(pair[0], index)) {
        index += pair[0].length;
        return pair[1];
      }
    const match = raw
      .slice(index)
      .match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (!match) throw new Error("value");
    index += match[0].length;
    const number = Number(match[0]);
    if (!Number.isFinite(number)) throw new Error("number");
    return number;
  };
  const stringValue = () => {
    const start = index++;
    while (index < raw.length) {
      const code = raw.charCodeAt(index++);
      if (code === 34) return JSON.parse(raw.slice(start, index));
      if (code < 32) throw new Error("string");
      if (code === 92) {
        const escaped = raw[index++];
        if (escaped === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(raw.slice(index, index + 4)))
            throw new Error("escape");
          index += 4;
        } else if (!'"\\/bfnrt'.includes(escaped ?? ""))
          throw new Error("escape");
      }
    }
    throw new Error("string");
  };
  const objectValue = (depth) => {
    index += 1;
    ws();
    const result = {};
    const keys = new Set();
    if (raw[index] === "}") {
      index += 1;
      return result;
    }
    while (true) {
      ws();
      if (raw[index] !== '"') throw new Error("key");
      const key = stringValue();
      if (keys.has(key)) throw new Error("duplicate");
      keys.add(key);
      ws();
      if (raw[index++] !== ":") throw new Error("colon");
      result[key] = value(depth);
      ws();
      const delimiter = raw[index++];
      if (delimiter === "}") return result;
      if (delimiter !== ",") throw new Error("delimiter");
    }
  };
  const arrayValue = (depth) => {
    index += 1;
    ws();
    const result = [];
    if (raw[index] === "]") {
      index += 1;
      return result;
    }
    while (true) {
      result.push(value(depth));
      ws();
      const delimiter = raw[index++];
      if (delimiter === "]") return result;
      if (delimiter !== ",") throw new Error("delimiter");
    }
  };
  const parsed = value(0);
  ws();
  if (index !== raw.length) throw new Error("trailing");
  return parsed;
}
function reject(code, statusCode = 403) {
  throw new PairingSessionError(code, statusCode);
}
