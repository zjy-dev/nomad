import { describe, expect, it } from 'vitest';
import { PilotSessionClient } from './pilot-client';

describe('PilotSessionClient', () => {
  it('loads a deterministic product session without UI-specific state', async () => {
    const view = await new PilotSessionClient().loadCurrentSession();
    expect(view.provenance).toBe('pilot');
    expect(view.state.session.turn_state).toBe('NeedsPermission');
    expect(view.state.session.host_connectivity).toBe('Online');
    expect(view.state.session.client_freshness).toBe('Live');
    expect(view.approval?.tool).toBeTruthy();
  });

  it('never manufactures diff files from diffFileCount', async () => {
    const view = await new PilotSessionClient().loadCurrentSession();
    view.state.diffFileCount = 3;
    expect(view.changes).toEqual(expect.objectContaining({ status: 'empty', source: null, baseline: null, files: [] }));
  });

  it('keeps golden traces behind the explicit lab API', async () => {
    const client = new PilotSessionClient();
    await expect(client.listTraceSessions()).resolves.toHaveLength(9);
    await expect(client.loadTraceSession('trace-001-normal-completion')).resolves.toEqual(expect.objectContaining({ provenance: 'trace-lab' }));
  });

  it('keeps version-incompatible trace stale after digest verification', async () => {
    const view = await new PilotSessionClient().loadTraceSession('trace-007-version-mismatch');
    expect(view.state.versionStatus).toBe('incompatible');
    expect(view.state.session.client_freshness).toBe('Stale');
  });
});
