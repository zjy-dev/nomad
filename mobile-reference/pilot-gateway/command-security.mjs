import { randomBytes, timingSafeEqual } from 'node:crypto';
import { TextDecoder } from 'node:util';

export const MAX_BROWSER_COMMAND_BYTES = 16 * 1024;
const utf8 = new TextDecoder('utf-8', { fatal: true });

export class CommandSecurityError extends Error {
  constructor(code, statusCode = 403) { super(code); this.name = 'CommandSecurityError'; this.code = code; this.statusCode = statusCode; }
}

export function createCommandSecurity(host, port) {
  const origin = expectedOrigin(host, port);
  const csrfToken = randomBytes(32).toString('base64url');
  return {
    csrfToken,
    validateRead(request) {
      requireHost(request, origin);
      optionalExactHeader(request, 'origin', origin);
      exactHeader(request, 'sec-fetch-site', 'same-origin');
      exactHeader(request, 'sec-fetch-mode', 'cors');
    },
    async readCommand(request) {
      requireHost(request, origin);
      exactHeader(request, 'origin', origin);
      exactHeader(request, 'sec-fetch-site', 'same-origin');
      exactHeader(request, 'sec-fetch-mode', 'cors');
      exactHeader(request, 'content-type', 'application/json');
      requireCsrf(request, csrfToken);
      if (rawHeaderValues(request, 'transfer-encoding').length !== 0) reject('INVALID_COMMAND_FRAMING', 400);
      const lengths = rawHeaderValues(request, 'content-length');
      if (lengths.length !== 1 || !/^[1-9][0-9]*$/.test(lengths[0])) reject('INVALID_COMMAND_FRAMING', 400);
      const declared = Number(lengths[0]);
      if (!Number.isSafeInteger(declared) || declared > MAX_BROWSER_COMMAND_BYTES) reject('INVALID_COMMAND_FRAMING', 400);
      const chunks = []; let size = 0;
      for await (const chunk of request) {
        size += chunk.length;
        if (size > declared || size > MAX_BROWSER_COMMAND_BYTES) { request.destroy(); reject('INVALID_COMMAND_FRAMING', 400); }
        chunks.push(chunk);
      }
      if (size !== declared) reject('INVALID_COMMAND_FRAMING', 400);
      let parsed;
      try { parsed = strictJson(utf8.decode(Buffer.concat(chunks))); } catch { reject('INVALID_COMMAND_JSON', 400); }
      return validateGatewayCommand(parsed);
    },
  };
}

export function validateGatewayCommand(value) {
  object(value); const common = ['schema', 'capability_id', 'request_id', 'nonce', 'command_seq', 'expected_snapshot_seq', 'expected_snapshot_digest', 'issued_at', 'expires_at', 'action'];
  const additions = value.action === 'reply' ? ['turn_alias', 'input_alias', 'content'] : value.action === 'deny' ? ['permission_alias', 'action_hash', 'permission_expires_at'] : value.action === 'stop' ? ['turn_alias'] : [];
  exact(value, [...common, ...additions]);
  if (value.schema !== 'nomad.gateway.command.v1' || !opaque(value.capability_id) || !opaque(value.request_id) || !opaque(value.nonce)) reject('INVALID_COMMAND', 400);
  if (!positive(value.command_seq) || !positive(value.expected_snapshot_seq) || !digest(value.expected_snapshot_digest) || !timestamp(value.issued_at) || !timestamp(value.expires_at)) reject('INVALID_COMMAND', 400);
  if (!['reply', 'deny', 'stop'].includes(value.action)) reject('INVALID_COMMAND', 400);
  if (value.action === 'reply' && (!alias(value.turn_alias, 'turn-') || !alias(value.input_alias, 'input-') || typeof value.content !== 'string' || value.content.trim().length === 0 || Buffer.byteLength(value.content) > 8 * 1024)) reject('INVALID_COMMAND', 400);
  if (value.action === 'deny' && (!alias(value.permission_alias, 'permission-') || !digest(value.action_hash) || !timestamp(value.permission_expires_at))) reject('INVALID_COMMAND', 400);
  if (value.action === 'stop' && !alias(value.turn_alias, 'turn-')) reject('INVALID_COMMAND', 400);
  return value;
}

function expectedOrigin(host, port) {
  if (host !== '127.0.0.1' || !Number.isInteger(port) || port < 1 || port > 65535) reject('INVALID_GATEWAY_ORIGIN', 500);
  return 'http://' + host + ':' + port;
}

function requireHost(request, origin) { exactHeader(request, 'host', new URL(origin).host); }
function requireCsrf(request, expected) {
  const values = rawHeaderValues(request, 'x-nomad-csrf');
  if (values.length !== 1 || typeof values[0] !== 'string') reject('CSRF_REJECTED');
  const actualBytes = Buffer.from(values[0]); const expectedBytes = Buffer.from(expected);
  if (actualBytes.length !== expectedBytes.length || !timingSafeEqual(actualBytes, expectedBytes)) reject('CSRF_REJECTED');
}
function exactHeader(request, name, expected) { const values = rawHeaderValues(request, name); if (values.length !== 1 || values[0] !== expected) reject('ORIGIN_REJECTED'); }
function optionalExactHeader(request, name, expected) { const values = rawHeaderValues(request, name); if (values.length > 1 || values.length === 1 && values[0] !== expected) reject('ORIGIN_REJECTED'); }
function rawHeaderValues(request, name) { const values = []; for (let index = 0; index < request.rawHeaders.length; index += 2) if (request.rawHeaders[index].toLowerCase() === name) values.push(request.rawHeaders[index + 1]); return values; }

function strictJson(raw) {
  let index = 0; let nodes = 0;
  const ws = () => { while (' \t\r\n'.includes(raw[index] ?? '!')) index += 1; };
  const value = (depth) => { ws(); if (++nodes > 4096 || depth > 12) throw new Error('budget'); const char = raw[index]; if (char === '{') return objectValue(depth + 1); if (char === '[') return arrayValue(depth + 1); if (char === '"') return stringValue(); for (const pair of [['true', true], ['false', false], ['null', null]]) if (raw.startsWith(pair[0], index)) { index += pair[0].length; return pair[1]; } const match = raw.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/); if (!match) throw new Error('value'); index += match[0].length; const number = Number(match[0]); if (!Number.isFinite(number)) throw new Error('number'); return number; };
  const stringValue = () => { const start = index++; while (index < raw.length) { const code = raw.charCodeAt(index++); if (code === 34) return JSON.parse(raw.slice(start, index)); if (code < 32) throw new Error('string'); if (code === 92) { const escaped = raw[index++]; if (escaped === 'u') { if (!/^[0-9a-fA-F]{4}$/.test(raw.slice(index, index + 4))) throw new Error('escape'); index += 4; } else if (!'"\\/bfnrt'.includes(escaped ?? '')) throw new Error('escape'); } } throw new Error('string'); };
  const objectValue = (depth) => { index += 1; ws(); const result = {}; const keys = new Set(); if (raw[index] === '}') { index += 1; return result; } while (true) { ws(); if (raw[index] !== '"') throw new Error('key'); const key = stringValue(); if (keys.has(key)) throw new Error('duplicate'); keys.add(key); ws(); if (raw[index++] !== ':') throw new Error('colon'); result[key] = value(depth); ws(); const delimiter = raw[index++]; if (delimiter === '}') return result; if (delimiter !== ',') throw new Error('delimiter'); } };
  const arrayValue = (depth) => { index += 1; ws(); const result = []; if (raw[index] === ']') { index += 1; return result; } while (true) { result.push(value(depth)); ws(); const delimiter = raw[index++]; if (delimiter === ']') return result; if (delimiter !== ',') throw new Error('delimiter'); } };
  const result = value(0); ws(); if (index !== raw.length) throw new Error('trailing'); return result;
}

function object(value) { if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) reject('INVALID_COMMAND', 400); }
function exact(value, keys) { const actual = Object.keys(value).sort(); const expected = [...keys].sort(); if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) reject('INVALID_COMMAND', 400); }
function positive(value) { return Number.isSafeInteger(value) && value > 0; }
function opaque(value) { return typeof value === 'string' && /^[A-Za-z0-9_-]{8,160}$/.test(value); }
function alias(value, prefix) { return typeof value === 'string' && value.startsWith(prefix) && /^[a-z]+-[0-9a-f]{32}$/.test(value); }
function digest(value) { return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value); }
function timestamp(value) { return typeof value === 'string' && Number.isFinite(Date.parse(value)); }
function reject(code, status = 403) { throw new CommandSecurityError(code, status); }
