import assert from 'node:assert/strict';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { createServer, request as httpRequest } from 'node:http';
import test from 'node:test';
import {
  JOIN_COOKIE_NAME, MAX_PAIRING_REQUEST_BYTES, PairingSessionError,
  createPairingSession, readDesktopJson, validateDesktopApprove,
  validateDesktopCancel, validateDesktopCreate, validateDesktopRead,
  readTrustedIngressTokenFromFd, validateDesktopRevoke, validateJoinId,
} from './pairing-session.mjs';

const PUBLIC_ORIGIN = 'https://opaque.pair.nomad.example';
const TRUST = Buffer.alloc(32, 7).toString('base64url');
const CSRF = Buffer.alloc(32, 8).toString('base64url');
const JOIN_ID = `join-${'1'.repeat(32)}`;
const CHALLENGE_ID = 'challenge-12345678';
const SECRET = Buffer.alloc(32, 1).toString('base64url');
const KEY_A = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 2)]).toString('base64url');
const KEY_B = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 3)]).toString('base64url');
const SIGNATURE = Buffer.alloc(64, 4).toString('base64url');
const MAC = Buffer.alloc(32, 5).toString('base64url');
const VAULT_SIGNATURE = Buffer.alloc(64, 6).toString('base64url');

function joinHeaders(extra = {}) {
  return {
    Host: new URL(PUBLIC_ORIGIN).host,
    Origin: PUBLIC_ORIGIN,
    'X-Forwarded-Proto': 'https',
    'X-Forwarded-Host': new URL(PUBLIC_ORIGIN).host,
    'X-Nomad-Trusted-Ingress': TRUST,
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
    'Content-Type': 'application/json',
    ...extra,
  };
}

function desktopHeaders(origin, extra = {}) {
  return {
    Host: new URL(origin).host, Origin: origin,
    'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty',
    'X-Nomad-CSRF': CSRF, 'Content-Type': 'application/json', ...extra,
  };
}

async function requestFixture(reader, body, headers = joinHeaders()) {
  let observed;
  const server = createServer(async (request, response) => {
    try { observed = await reader(request); response.statusCode = 204; }
    catch (error) { observed = error; response.statusCode = error.statusCode ?? 500; }
    response.end();
  }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;
  const resolvedHeaders = typeof headers === 'function' ? headers(origin) : headers;
  const result = await new Promise((resolve, reject) => {
    const request = httpRequest(origin, { method: 'POST', headers: { ...resolvedHeaders, 'Content-Length': String(Buffer.byteLength(body)) } }, resolve);
    request.on('error', reject); request.end(body);
  });
  result.resume(); await once(result, 'end');
  server.close(); await once(server, 'close');
  return { status: result.statusCode, observed };
}

test('requires an explicit HTTPS public origin and unguessable trusted-ingress contract', () => {
  assert.throws(() => createPairingSession({ publicOrigin: 'http://pair.example', trustedIngressToken: TRUST }), { code: 'INVALID_PUBLIC_ORIGIN' });
  assert.throws(() => createPairingSession({ publicOrigin: PUBLIC_ORIGIN, trustedIngressToken: 'guessable' }), { code: 'INVALID_TRUSTED_INGRESS' });
  assert.doesNotThrow(() => createPairingSession({ publicOrigin: PUBLIC_ORIGIN, trustedIngressToken: TRUST }));
});

test('start validates exact keys and exact P-256/base64url field sizes', async () => {
  const session = createPairingSession({ publicOrigin: PUBLIC_ORIGIN, trustedIngressToken: TRUST });
  const input = { join_id: JOIN_ID, join_secret: SECRET, device_signing_public_key_sec1: KEY_A, device_agreement_public_key_sec1: KEY_B };
  const accepted = await requestFixture((request) => session.readStart(request), JSON.stringify(input));
  assert.equal(accepted.status, 204); assert.deepEqual(accepted.observed, input);

  for (const invalid of [
    { ...input, extra: true },
    { ...input, join_secret: SECRET + '=' },
    { ...input, device_agreement_public_key_sec1: KEY_A },
    { ...input, device_signing_public_key_sec1: Buffer.alloc(65, 3).toString('base64url') },
  ]) {
    const rejected = await requestFixture((request) => session.readStart(request), JSON.stringify(invalid));
    assert.equal(rejected.status, 400); assert.equal(rejected.observed.code, 'PAIRING_REQUEST_INVALID');
  }
});

test('confirm, complete and abort require the one exact join cookie and exact schema keys', async () => {
  const session = createPairingSession({ publicOrigin: PUBLIC_ORIGIN, trustedIngressToken: TRUST });
  const cookie = `${JOIN_COOKIE_NAME}=${SECRET}`;
  const confirm = { challenge_id: CHALLENGE_ID, expected_epoch: 1, device_signing_signature_p1363: SIGNATURE, device_agreement_mac: MAC };
  const complete = { schema: 'nomad.m3e.pairing.vault-commit.v1', challenge_id: CHALLENGE_ID, expected_epoch: 1, device_vault_signature_p1363: VAULT_SIGNATURE };
  const abort = { schema: 'nomad.m3e.pairing.abort.v1', challenge_id: CHALLENGE_ID, expected_epoch: 1 };
  for (const [reader, body] of [[session.readConfirm, confirm], [session.readComplete, complete], [session.readAbort, abort]]) {
    const result = await requestFixture(reader, JSON.stringify(body), joinHeaders({ Cookie: cookie }));
    assert.equal(result.status, 204); assert.equal(result.observed.capability, SECRET); assert.deepEqual(result.observed.body, body);
  }
  const missing = await requestFixture(session.readConfirm, JSON.stringify(confirm));
  assert.equal(missing.status, 401); assert.equal(missing.observed.code, 'JOIN_COOKIE_REQUIRED');
  const duplicate = await requestFixture(session.readConfirm, JSON.stringify(confirm), joinHeaders({ Cookie: `${cookie}; ${cookie}` }));
  assert.equal(duplicate.status, 401); assert.equal(duplicate.observed.code, 'JOIN_COOKIE_INVALID');
  const wrongAbort = await requestFixture(session.readAbort, `{"schema":"nomad.m3e.pairing.abort.v1","challenge_id":"${CHALLENGE_ID}","expected_epoch":1,"extra":true}`, joinHeaders({ Cookie: cookie }));
  assert.equal(wrongAbort.status, 400);
});

test('cookie serialization is exact, bounded by Host expiry, and clearing uses Max-Age zero', () => {
  const session = createPairingSession({ publicOrigin: PUBLIC_ORIGIN, trustedIngressToken: TRUST });
  assert.equal(session.cookieFor(SECRET, 120), `${JOIN_COOKIE_NAME}=${SECRET}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=120`);
  assert.equal(session.cookieFor(SECRET, 45), `${JOIN_COOKIE_NAME}=${SECRET}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=45`);
  assert.equal(session.clearCookie(), `${JOIN_COOKIE_NAME}=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
  assert.throws(() => session.cookieFor(SECRET, 121), { code: 'PAIRING_SESSION_EXPIRED' });
});

test('ordinary public HTTP and spoofable forwarding headers are insufficient without the trusted ingress marker', async () => {
  const session = createPairingSession({ publicOrigin: PUBLIC_ORIGIN, trustedIngressToken: TRUST });
  const input = JSON.stringify({ join_id: JOIN_ID, join_secret: SECRET, device_signing_public_key_sec1: KEY_A, device_agreement_public_key_sec1: KEY_B });
  for (const headers of [
    { ...joinHeaders(), 'X-Nomad-Trusted-Ingress': undefined },
    { ...joinHeaders(), 'X-Nomad-Trusted-Ingress': Buffer.alloc(32, 9).toString('base64url') },
    { ...joinHeaders(), 'X-Forwarded-Proto': 'http' },
    { ...joinHeaders(), Origin: 'https://evil.example' },
    { ...joinHeaders(), 'Sec-Fetch-Site': 'cross-site' },
  ]) {
    for (const key of Object.keys(headers)) if (headers[key] === undefined) delete headers[key];
    const result = await requestFixture(session.readStart, input, headers);
    assert.equal(result.status, 403);
  }
});

test('strict bounded JSON rejects duplicate keys, unknown framing and oversized bodies', async () => {
  const session = createPairingSession({ publicOrigin: PUBLIC_ORIGIN, trustedIngressToken: TRUST });
  const duplicate = `{"join_id":"${JOIN_ID}","join_id":"${JOIN_ID}","join_secret":"${SECRET}","device_signing_public_key_sec1":"${KEY_A}","device_agreement_public_key_sec1":"${KEY_B}"}`;
  const rejected = await requestFixture(session.readStart, duplicate);
  assert.equal(rejected.status, 400); assert.equal(rejected.observed.code, 'PAIRING_JSON_INVALID');
  const encoded = await requestFixture(session.readStart, '{}', joinHeaders({ 'Content-Encoding': 'gzip' }));
  assert.equal(encoded.status, 400); assert.equal(encoded.observed.code, 'PAIRING_FRAMING_INVALID');
  const oversized = await requestFixture(session.readStart, JSON.stringify({ padding: 'x'.repeat(MAX_PAIRING_REQUEST_BYTES) }));
  assert.equal(oversized.status, 400); assert.equal(oversized.observed.code, 'PAIRING_FRAMING_INVALID');
});

test('desktop DTO schemas and exact key sets reuse the frozen Product Host revoke request shape', async () => {
  assert.deepEqual(validateDesktopCreate({ schema: 'nomad.m3e.pairing.create.v1' }), { schema: 'nomad.m3e.pairing.create.v1' });
  assert.deepEqual(validateDesktopApprove({ schema: 'nomad.m3e.pairing.desktop-approve.v1', join_id: JOIN_ID, challenge_id: CHALLENGE_ID, expected_epoch: 1, comparison_code: '042913' }), { schema: 'nomad.m3e.pairing.desktop-approve.v1', join_id: JOIN_ID, challenge_id: CHALLENGE_ID, expected_epoch: 1, comparison_code: '042913' });
  assert.deepEqual(validateDesktopCancel({ schema: 'nomad.m3e.pairing.cancel.v1', join_id: JOIN_ID }), { schema: 'nomad.m3e.pairing.cancel.v1', join_id: JOIN_ID });
  assert.deepEqual(validateDesktopRevoke({ device_alias: 'device-12345678', expected_epoch: 1 }), { device_alias: 'device-12345678', expected_epoch: 1 });
  assert.throws(() => validateDesktopRevoke({ schema: 'nomad.m3e.device.revoke.v1', device_alias: 'device-12345678', expected_epoch: 1 }), { code: 'PAIRING_REQUEST_INVALID' });
  assert.equal(validateJoinId(JOIN_ID), JOIN_ID);

  const server = createServer(async (request, response) => {
    try { validateDesktopRead(request, `http://127.0.0.1:${server.address().port}`, CSRF); response.statusCode = 204; }
    catch (error) { response.statusCode = error.statusCode; }
    response.end();
  }).listen(0, '127.0.0.1'); await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;
  const accepted = await fetch(origin, { headers: desktopHeaders(origin) }); assert.equal(accepted.status, 204);
  server.close(); await once(server, 'close');

  const read = await requestFixture((request) => readDesktopJson(request, request.headers.origin, CSRF), JSON.stringify({ schema: 'nomad.m3e.pairing.create.v1' }), (fixtureOrigin) => desktopHeaders(fixtureOrigin));
  assert.equal(read.status, 204);
});

test('public validators expose only stable safe error codes', () => {
  assert.throws(() => validateJoinId(`join-${'G'.repeat(32)}`), (error) => error instanceof PairingSessionError && error.code === 'JOIN_NOT_FOUND' && error.message === 'JOIN_NOT_FOUND');
});

test('trusted ingress token FD requires exactly 32 bytes and EOF and closes descriptor', async () => {
  const moduleUrl = new URL('./pairing-session.mjs', import.meta.url).href;
  for (const [size, expected] of [[31, 'INVALID_TRUSTED_INGRESS_TOKEN'], [32, 'ok'], [33, 'INVALID_TRUSTED_INGRESS_TOKEN']]) {
    const code = 'import { fstatSync } from "node:fs"; import { readTrustedIngressTokenFromFd } from ' + JSON.stringify(moduleUrl) + '; let result; try { const token=readTrustedIngressTokenFromFd(3); result={code:"ok",token}; } catch(error) { result={code:error.code}; } try { fstatSync(3); result.closed=false; } catch { result.closed=true; } process.stdout.write(JSON.stringify(result));';
    const child = spawn(process.execPath, ['--input-type=module', '-e', code], { stdio: ['ignore', 'pipe', 'pipe', 'pipe'] });
    child.stdio[3].end(Buffer.alloc(size, 9)); let stdout = ''; child.stdout.setEncoding('utf8'); child.stdout.on('data', (chunk) => { stdout += chunk; });
    const [exitCode] = await once(child, 'exit'); assert.equal(exitCode, 0); const result = JSON.parse(stdout); assert.equal(result.code, expected); assert.equal(result.closed, true); if (size === 32) assert.equal(result.token, Buffer.alloc(32, 9).toString('base64url'));
  }
  assert.equal(typeof readTrustedIngressTokenFromFd, 'function');
});
