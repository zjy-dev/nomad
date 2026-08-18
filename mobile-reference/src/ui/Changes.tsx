import { useEffect, useState } from 'react';
import type { ChangesView } from '../client/types';
import type { ViewState } from '../contracts/reducer';
import { StatusChips } from './StatusChips';

export function Changes({ state, changes }: { state: ViewState; changes: ChangesView }) {
  const [openPath, setOpenPath] = useState<string | null>(changes.files[0]?.path ?? null);
  useEffect(() => setOpenPath(changes.files[0]?.path ?? null), [changes]);
  const available = changes.status === 'available' && changes.source !== null && changes.baseline !== null;

  return (
    <div className="stack">
      <StatusChips state={state} />
      <section className="section" aria-labelledby="changes-title">
        <div className="page-heading"><span className="eyebrow">WORKSPACE</span><h1 id="changes-title">Changes</h1><p>Only a Host-verified diff for the current baseline appears here.</p></div>

        {!available && (
          <div className={`empty-state ${changes.status === 'invalid' ? 'empty-state--warn' : ''}`} data-testid="changes-empty">
            <span className="empty-state-mark" aria-hidden="true">{changes.status === 'invalid' ? '!' : '—'}</span>
            <strong>{changes.status === 'invalid' ? 'The previous diff is no longer valid' : 'No verified changes yet'}</strong>
            <p>{changes.reason ?? 'The Host has not supplied a verified workspace diff for this session.'}</p>
            {state.diffFileCount > 0 && <p className="integrity-note">An event mentioned changed files, but file details were not authoritative, so nothing is shown.</p>}
          </div>
        )}

        {available && (
          <>
            <dl className="diff-provenance"><div><dt>Source</dt><dd>{changes.source}</dd></div><div><dt>Baseline</dt><dd>{changes.baseline}</dd></div><div><dt>Files</dt><dd>{changes.files.length}</dd></div></dl>
            {changes.files.length === 0 && <div className="empty-state"><strong>No workspace changes</strong><p>The Host verified the baseline and found no changed files.</p></div>}
            {changes.files.map((file) => (
              <article className="diff-file" key={file.path}>
                <button className="diff-file-head" onClick={() => setOpenPath(openPath === file.path ? null : file.path)} aria-expanded={openPath === file.path}>
                  <span><strong className="diff-file-path">{file.path}</strong><small>{[file.external && 'External edit', file.binary && 'Binary', file.truncated && 'Large file · partial'].filter(Boolean).join(' · ') || 'Host verified'}</small></span>
                  <span className="diff-file-stats"><b>+{file.added}</b> / <i>-{file.removed}</i></span>
                </button>
                {openPath === file.path && (
                  <div className="diff-file-body">
                    {file.binary && file.hunks.length === 0 && <div className="binary-note">Binary content is not displayed.</div>}
                    {file.hunks.map((hunk) => (
                      <div key={hunk.header}><div className="diff-hunk">{hunk.header}</div>{hunk.lines.map((line, index) => <div className={`diff-line ${line.type}`} key={`${hunk.header}-${index}`}><span className="ln">{line.type === 'add' ? '+' : line.type === 'del' ? '-' : ' '}</span><span className="code">{line.text}</span></div>)}</div>
                    ))}
                  </div>
                )}
              </article>
            ))}
          </>
        )}
      </section>
    </div>
  );
}
