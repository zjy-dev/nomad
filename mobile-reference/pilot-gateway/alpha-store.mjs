import { chmodSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { browserProjectionFromHost, canonicalJson, validateBrowserProjection, validateHostProjection } from './view.mjs';
import { browserProjectionFromProductHost, validateProductHostSnapshot } from './product-host-client.mjs';

const PRODUCT_STALE_AFTER_MS = 60_000;

export class AlphaStateError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

export class AlphaStore {
  constructor(path) {
    if (!path || path === ':memory:' || /^file:.*(?:mode=memory|:memory:)/i.test(path)) {
      throw new Error('Alpha Gateway requires a file-backed state database');
    }
    this.db = new DatabaseSync(path);
    chmodSync(path, 0o600);
    this.db.exec('PRAGMA journal_mode=WAL');
    this.db.exec('PRAGMA synchronous=FULL');
    this.db.exec('PRAGMA busy_timeout=5000');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS alpha_host_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        session_id TEXT NOT NULL,
        seq INTEGER NOT NULL CHECK (seq >= 0),
        host_digest TEXT NOT NULL,
        host_json TEXT NOT NULL,
        response_json TEXT NOT NULL,
        stored_at TEXT NOT NULL
      ) STRICT
    `);
    this.db.exec('CREATE TABLE IF NOT EXISTS product_host_state (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), host_instance_id TEXT NOT NULL, snapshot_seq INTEGER NOT NULL CHECK (snapshot_seq >= 1), digest TEXT NOT NULL, envelope_json TEXT NOT NULL, stored_at_ms INTEGER NOT NULL, disconnected_at_ms INTEGER) STRICT');
  }

  close() {
    this.db.close();
  }

  current() {
    return this.#readRecord()?.response ?? null;
  }

  get(sessionId) {
    const current = this.current();
    return current?.session.session_id === sessionId ? current : null;
  }

  persist(host) {
    validateHostProjection(host);
    const response = browserProjectionFromHost(host);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const current = this.#readRecord();
      const result = classify(current?.host ?? null, host);
      if (result === 'stored') {
        this.db.prepare(`
          INSERT INTO alpha_host_state (singleton, session_id, seq, host_digest, host_json, response_json, stored_at)
          VALUES (1, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(singleton) DO UPDATE SET
            session_id = excluded.session_id,
            seq = excluded.seq,
            host_digest = excluded.host_digest,
            host_json = excluded.host_json,
            response_json = excluded.response_json,
            stored_at = excluded.stored_at
        `).run(
          host.session.session_id,
          host.seq,
          host.digest,
          JSON.stringify(host),
          JSON.stringify(response),
          new Date().toISOString(),
        );
      }
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      try { this.db.exec('ROLLBACK'); } catch {}
      throw error;
    }
  }

  productEnvelope() {
    return this.#readProductRecord()?.envelope ?? null;
  }

  productCurrent(connectivity = {}) {
    const record = this.#readProductRecord();
    return record ? browserProjectionFromProductHost(record.envelope, connectivity) : null;
  }

  persistProduct(envelope, { source = 'stream', nowMs = Date.now() } = {}) {
    validateProductHostSnapshot(envelope);
    if (!['current', 'stream'].includes(source)) throw new AlphaStateError('INVALID_SOURCE');
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new AlphaStateError('INVALID_TIME');
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const current = this.#readProductRecord();
      const result = classifyProduct(current?.envelope ?? null, envelope, source);
      const wasDisconnected = current?.disconnectedAtMs !== null && current?.disconnectedAtMs !== undefined;
      if (result !== 'duplicate' || wasDisconnected) {
        this.db.prepare('INSERT INTO product_host_state (singleton, host_instance_id, snapshot_seq, digest, envelope_json, stored_at_ms, disconnected_at_ms) VALUES (1, ?, ?, ?, ?, ?, NULL) ON CONFLICT(singleton) DO UPDATE SET host_instance_id = excluded.host_instance_id, snapshot_seq = excluded.snapshot_seq, digest = excluded.digest, envelope_json = excluded.envelope_json, stored_at_ms = excluded.stored_at_ms, disconnected_at_ms = NULL').run(envelope.host_instance_id, envelope.snapshot_seq, envelope.digest, JSON.stringify(envelope), nowMs);
      }
      this.db.exec('COMMIT');
      return { result, wasDisconnected };
    } catch (error) {
      try { this.db.exec('ROLLBACK'); } catch {}
      throw error;
    }
  }

  productDisconnected(nowMs = Date.now()) {
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new AlphaStateError('INVALID_TIME');
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const current = this.#readProductRecord();
      if (!current) { this.db.exec('COMMIT'); return null; }
      const disconnectedAtMs = current.disconnectedAtMs ?? nowMs;
      if (current.disconnectedAtMs === null) this.db.prepare('UPDATE product_host_state SET disconnected_at_ms = ? WHERE singleton = 1').run(disconnectedAtMs);
      this.db.exec('COMMIT');
      return browserProjectionFromProductHost(current.envelope, {
        hostConnectivity: 'Offline',
        clientFreshness: nowMs - disconnectedAtMs >= PRODUCT_STALE_AFTER_MS ? 'Stale' : 'Reconnecting',
      });
    } catch (error) {
      try { this.db.exec('ROLLBACK'); } catch {}
      throw error;
    }
  }

  #readRecord() {
    const row = this.db.prepare(`
      SELECT session_id, seq, host_digest, host_json, response_json
      FROM alpha_host_state WHERE singleton = 1
    `).get();
    if (!row) return null;
    try {
      const host = JSON.parse(row.host_json);
      const response = JSON.parse(row.response_json);
      validateHostProjection(host);
      validateBrowserProjection(response);
      const expectedResponse = browserProjectionFromHost(host);
      if (
        host.session.session_id !== row.session_id
        || host.seq !== row.seq
        || host.digest !== row.host_digest
        || canonicalJson(response) !== canonicalJson(expectedResponse)
      ) throw new Error('row mismatch');
      return { host, response };
    } catch {
      throw new AlphaStateError('SQLITE_INCONSISTENT');
    }
  }

  #readProductRecord() {
    const row = this.db.prepare('SELECT host_instance_id, snapshot_seq, digest, envelope_json, stored_at_ms, disconnected_at_ms FROM product_host_state WHERE singleton = 1').get();
    if (!row) return null;
    try {
      const envelope = JSON.parse(row.envelope_json);
      validateProductHostSnapshot(envelope);
      if (envelope.host_instance_id !== row.host_instance_id || envelope.snapshot_seq !== row.snapshot_seq || envelope.digest !== row.digest) throw new Error('row mismatch');
      return { envelope, storedAtMs: row.stored_at_ms, disconnectedAtMs: row.disconnected_at_ms };
    } catch {
      throw new AlphaStateError('SQLITE_INCONSISTENT');
    }
  }
}

function classify(current, next) {
  if (!current) return 'stored';
  if (next.session.session_id !== current.session.session_id) throw new AlphaStateError('SESSION_SWITCH');
  if (next.seq < current.seq) throw new AlphaStateError('STALE_SEQ');
  if (next.seq > current.seq + 1) throw new AlphaStateError('SEQ_GAP');
  if (next.seq === current.seq) {
    if (next.digest !== current.digest) throw new AlphaStateError('SEQ_CONFLICT');
    return 'duplicate';
  }
  return 'stored';
}

function classifyProduct(current, next, source) {
  if (!current) return 'stored';
  if (next.host_instance_id !== current.host_instance_id) {
    if (source !== 'current') throw new AlphaStateError('HOST_INSTANCE_SWITCH');
    return 'restarted';
  }
  if (next.snapshot_seq < current.snapshot_seq) throw new AlphaStateError('STALE_SEQ');
  if (next.snapshot_seq > current.snapshot_seq + 1) throw new AlphaStateError('SEQ_GAP');
  if (next.snapshot_seq === current.snapshot_seq) {
    if (next.digest !== current.digest) throw new AlphaStateError('SEQ_CONFLICT');
    return 'duplicate';
  }
  return 'stored';
}
