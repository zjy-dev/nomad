#!/usr/bin/env node
import { createReadStream, existsSync, readFileSync, statSync } from 'node:fs';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { extname, join, normalize } from 'node:path';
import { randomUUID } from 'node:crypto';
import { RelayClient } from './relay-client.mjs';
import { commandSubmission, decodePilotSessionMessage } from './view.mjs';

const MAX_BODY = 64 * 1024;

export function createGateway(options) {
  const relay = options.relayClient ?? new RelayClient(options.relayUrl, options.relayToken);
  const channel = options.channel;
  const distDir = options.distDir;
  return async (request, response) => {
    setHeaders(response);
    try {
      const url = new URL(request.url, 'http://gateway.local');
      if (url.pathname === '/api/pilot/session' && request.method === 'GET') {
        const messages = await relay.list(channel, 'mobile');
        const session = [...messages].reverse().find((item) => item.payload?.type === 'pilot.session');
        if (!session) return json(response, 503, { error: 'SESSION_UNAVAILABLE' });
        return json(response, 200, decodePilotSessionMessage(session));
      }
      if (url.pathname === '/api/pilot/commands' && request.method === 'POST') {
        const command = await readJson(request);
        validateCommand(command);
        // Transport delivery has its own ID. Business execution remains
        // idempotent on the stable command.request_id in the Host journal.
        await relay.post(channel, 'host', `pilot.command:${command.request_id}:${randomUUID()}`, { type: 'pilot.command', command });
        return json(response, 202, { status: 'RelayReceived', result: { error_code: 'OK', error_message: null } });
      }
      const match = url.pathname.match(/^\/api\/pilot\/commands\/([A-Za-z0-9_.:-]{1,256})$/);
      if (match && request.method === 'GET') {
        const requestId = match[1];
        const messages = await relay.list(channel, 'mobile');
        const result = messages.find((item) => item.payload?.type === 'pilot.command.result' && item.payload.request_id === requestId);
        if (!result) return json(response, 200, { status: 'RelayReceived', result: { error_code: 'OK', error_message: null } });
        await relay.ack(channel, 'mobile', [result.message_id]);
        return json(response, 200, commandSubmission(result.payload));
      }
      if (url.pathname.startsWith('/api/')) return json(response, 404, { error: 'NOT_FOUND' });
      return serveStatic(distDir, url.pathname, response);
    } catch (error) {
      // Do not log request bodies, Relay tokens or Session content.
      return json(response, error.statusCode ?? 502, { error: error.publicCode ?? 'GATEWAY_FAILURE' });
    }
  };
}

function validateCommand(command) {
  if (!command || typeof command !== 'object' || !/^[A-Za-z0-9_.:-]{1,256}$/.test(command.request_id ?? '')) {
    const error = new Error('invalid command'); error.statusCode = 400; error.publicCode = 'INVALID_COMMAND'; throw error;
  }
  if (!['reply', 'stop', 'permission_decision'].includes(command.command_type)) {
    const error = new Error('unsupported command'); error.statusCode = 400; error.publicCode = 'INVALID_COMMAND'; throw error;
  }
}

async function readJson(request) {
  const chunks = []; let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY) { const error = new Error('too large'); error.statusCode = 413; error.publicCode = 'REQUEST_TOO_LARGE'; throw error; }
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { const error = new Error('invalid json'); error.statusCode = 400; error.publicCode = 'INVALID_JSON'; throw error; }
}

function setHeaders(response) {
  response.setHeader('Content-Security-Policy', "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'");
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Cache-Control', 'no-store');
}

function json(response, status, body) {
  response.statusCode = status; response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify(body));
}

function serveStatic(distDir, pathname, response) {
  const requested = pathname === '/' ? 'index.html' : normalize(pathname).replace(/^([.][.]\/)+/, '').replace(/^\//, '');
  let file = join(distDir, requested);
  if (!existsSync(file) || !statSync(file).isFile()) file = join(distDir, 'index.html');
  if (!existsSync(file)) return json(response, 503, { error: 'MOBILE_BUILD_MISSING' });
  const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png' };
  response.statusCode = 200; response.setHeader('Content-Type', types[extname(file)] ?? 'application/octet-stream'); createReadStream(file).pipe(response);
}

export function startGateway(config) {
  const nonLoopback = !['127.0.0.1', 'localhost', '::1'].includes(config.host);
  if (nonLoopback && (!config.tlsCert || !config.tlsKey)) throw new Error('Non-loopback Pilot Gateway requires --tls-cert and --tls-key');
  const handler = createGateway(config);
  const server = config.tlsCert && config.tlsKey
    ? createHttpsServer({ cert: readFileSync(config.tlsCert), key: readFileSync(config.tlsKey) }, handler)
    : createHttpServer(handler);
  return server.listen(config.port, config.host);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = parseArgs(process.argv.slice(2));
  startGateway(args);
  console.log(JSON.stringify({ ready: true, protocol: args.tlsCert ? 'https' : 'http', host: args.host, port: args.port }));
}

function parseArgs(args) {
  const out = { host: '127.0.0.1', port: 4173, distDir: new URL('../dist', import.meta.url).pathname };
  for (let index = 0; index < args.length; index += 2) out[args[index].replace(/^--/, '').replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = args[index + 1];
  out.port = Number(out.port);
  for (const key of ['relayUrl', 'relayToken', 'channel']) if (!out[key]) throw new Error(`Missing --${key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`);
  return out;
}
