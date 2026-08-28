import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { isPublicCommandType, PUBLIC_COMMAND_TYPES, type PublicCommandRequest, type PublicCommandResult } from './types';

interface CommandVariant {
  required: string[];
  additionalProperties: false;
  properties: Record<string, unknown> & { command_type: { const: string } };
}

interface CommandSchema {
  oneOf: CommandVariant[];
}

function load(path: string): { raw: string; schema: CommandSchema } {
  const raw = readFileSync(path, 'utf8');
  return { raw, schema: JSON.parse(raw) as CommandSchema };
}

function matchesPublicVariant(command: Record<string, unknown>, variant: CommandVariant): boolean {
  const properties = Object.keys(variant.properties);
  return variant.additionalProperties === false
    && command.command_type === variant.properties.command_type.const
    && variant.required.every((field) => field in command)
    && Object.keys(command).every((field) => properties.includes(field));
}

describe('First Real User public command contract', () => {
  const root = resolve(process.cwd(), '../contracts/schemas/commands.schema.json');
  const bundled = resolve(process.cwd(), 'public/contracts/commands.schema.json');

  it('keeps source and bundled schemas byte-identical with reply, deny, stop only', () => {
    const source = load(root);
    const copy = load(bundled);
    expect(copy.raw).toBe(source.raw);
    expect(source.schema.oneOf.map((variant) => variant.properties.command_type.const)).toEqual(PUBLIC_COMMAND_TYPES);
  });

  it.each(['interrupt_and_send', 'allow_once', 'permission_decision'])('excludes historical %s from the public schema and type guard', (forbidden) => {
    const source = load(root);
    expect(source.raw).not.toContain(forbidden);
    expect(isPublicCommandType(forbidden)).toBe(false);
  });

  it.each([
    { command_type: 'interrupt_and_send', request_id: 'r', session_id: 's', seq: 1, interrupt_turn_id: 't', new_content: 'next' },
    { command_type: 'permission_decision', request_id: 'r', session_id: 's', seq: 1, permission_id: 'p', decision: 'allow_once', action_hash: 'h', expires_at: '2026-08-25T00:00:00Z' },
  ])('does not match legacy command object $command_type against any public schema variant', (legacy) => {
    const schema = load(root).schema;
    expect(schema.oneOf.some((variant) => matchesPublicVariant(legacy, variant))).toBe(false);
  });

  it.each([
    { command_type: 'reply', request_id: 'r', session_id: 's', observed_seq: 0, content: 'hello', status: 'Completed' },
    { command_type: 'stop', request_id: 'r', session_id: 's', observed_seq: 0, target_turn_id: 't', result: { error_code: 'OK' } },
    { command_type: 'reply', request_id: 'r', session_id: 's', seq: 1, content: 'legacy cursor' },
  ])('rejects request DTO pollution with response or legacy cursor fields', (polluted) => {
    const schema = load(root).schema;
    expect(schema.oneOf.some((variant) => matchesPublicVariant(polluted, variant))).toBe(false);
  });

  it('defines observed_seq as a non-allocating current-state CAS input', () => {
    const schema = load(root).schema;
    for (const variant of schema.oneOf) {
      expect(variant.required).toContain('observed_seq');
      expect(variant.required).not.toContain('seq');
      expect(variant.properties).not.toHaveProperty('status');
      expect(variant.properties).not.toHaveProperty('result');
    }
    const raw = load(root).raw;
    expect(raw).toContain('MUST equal the currently observed last_applied_seq');
    expect(raw).toContain('MUST NOT allocate, predict, or claim a Host or durable event sequence');
  });

  it('keeps schema limits aligned with the runtime validator', () => {
    const [reply, deny, stop] = load(root).schema.oneOf;
    for (const variant of [reply, deny, stop]) {
      expect(variant.properties.request_id).toEqual(expect.objectContaining({ minLength: 1, maxLength: 128 }));
      expect(variant.properties.session_id).toEqual(expect.objectContaining({ minLength: 1, maxLength: 64 }));
      expect(variant.properties.observed_seq).toEqual(expect.objectContaining({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }));
    }
    expect(reply.properties.content).toEqual(expect.objectContaining({ minLength: 1, maxLength: 65536 }));
    expect(reply.properties.turn_id).toEqual(expect.objectContaining({ type: ['string', 'null'], minLength: 1, maxLength: 64 }));
    expect(deny.properties.permission_id).toEqual(expect.objectContaining({ minLength: 1, maxLength: 128 }));
    expect(deny.properties.action_hash).toEqual(expect.objectContaining({ minLength: 1, maxLength: 128 }));
    expect(deny.properties.expires_at).toEqual(expect.objectContaining({ minLength: 20, maxLength: 20, pattern: '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' }));
    expect(stop.properties.target_turn_id).toEqual(expect.objectContaining({ minLength: 1, maxLength: 64 }));
  });

  it('models deny as an explicit public command without an allow decision field', () => {
    const deny: PublicCommandRequest = {
      command_type: 'deny',
      request_id: 'req-1',
      session_id: 'sess-1',
      observed_seq: 1,
      permission_id: 'perm-1',
      action_hash: 'sha256:action',
      expires_at: '2026-08-25T00:00:00Z',
    };
    expect(deny.command_type).toBe('deny');
    expect('decision' in deny).toBe(false);
  });

  it('does not expose interrupt result fields through the public result type', () => {
    const result: PublicCommandResult = { error_code: 'OK', error_message: null, accepted_at_seq: 2 };
    expect(result).not.toHaveProperty('stopped_at_seq');
    expect(result).not.toHaveProperty('new_event_id');
  });
});
