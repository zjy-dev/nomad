import React, { useState } from 'react';
import { ViewState } from '../contracts/reducer';
import { StatusChips } from './StatusChips';
import { ContractEvent } from '../contracts/types';

interface ChangesProps {
  state: ViewState;
}

// Synthetic diff fixtures. These are NOT canonical Host diffs — they
// represent the kind of data Host diff.updated events carry so the
// mobile reference can exercise the viewer. The real E2E path replaces
// this module with the Host's chunked diff API (MB-010).
const SAMPLE_FILES: DiffFile[] = [
  {
    path: 'src/app.tsx',
    stats: { added: 18, removed: 4 },
    hunks: [
      {
        head: '@@ -1,3 +1,5 @@',
        lines: [
          { type: 'ctx', text: 'import { App } from \'./ui/App\';' },
          { type: 'ctx', text: 'import { reducer } from \'./contracts/reducer\';' },
          { type: 'add', text: 'import { StatusChips } from \'./ui/StatusChips\';' },
          { type: 'add', text: '' },
          { type: 'add', text: '// Mobile reference bootstraps the deterministic reducer.' },
          { type: 'ctx', text: '' },
        ],
      },
    ],
  },
  {
    path: 'src/contracts/reducer.ts',
    stats: { added: 52, removed: 2 },
    hunks: [
      {
        head: '@@ -10,2 +10,44 @@',
        lines: [
          { type: 'ctx', text: 'import type { ContractEvent, Snapshot } from \'./types\';' },
          { type: 'del', text: 'import { digest } from \'./digest\';' },
          { type: 'add', text: 'import { computeSnapshotDigest, verifySnapshotDigest } from \'./digest\';' },
          { type: 'add', text: '' },
          { type: 'add', text: '// INV-004-1: snapshot digest is verified before transition to Live.' },
          { type: 'add', text: '// INV-004-3: gap handling is manual; auto-fill is forbidden.' },
          { type: 'ctx', text: '' },
        ],
      },
    ],
  },
  {
    path: 'src/ui/styles.css',
    stats: { added: 30, removed: 0 },
    hunks: [
      {
        head: '@@ -0,0 +1,30 @@',
        lines: [
          { type: 'add', text: ':root { --bg: #0c0d10; --text: #e6e8ee; }' },
          { type: 'add', text: '.card { border: 1px solid var(--border); }' },
          { type: 'add', text: '.chip { font-family: var(--mono); }' },
        ],
      },
    ],
  },
];

type HunkLine = { type: 'add' | 'del' | 'ctx'; text: string };
interface Hunk { head: string; lines: HunkLine[] }
interface DiffFile { path: string; stats: { added: number; removed: number }; hunks: Hunk[] }

export function Changes({ state }: ChangesProps) {
  const files = deriveFiles(state) ?? SAMPLE_FILES;
  const [openIdx, setOpenIdx] = useState<number | null>(files.length > 0 ? 0 : null);

  return (
    <div className="stack">
      <StatusChips state={state} />

      <div className="section">
        <div className="section-header">
          <span className="section-title">Changes</span>
          <span className="muted" style={{ fontSize: 11, fontFamily: 'var(--mono)' }}>
            {files.length} file(s) · derived from diff.updated summary
          </span>
        </div>

        {files.length === 0 && (
          <div className="muted" style={{ fontSize: 13 }}>
            No diff yet. The Host will emit a <span className="inline-code">diff.updated</span> event once
            tool output is processed.
          </div>
        )}

        {files.map((f, i) => (
          <div className="diff-file" key={f.path}>
            <button
              className="diff-file-head"
              onClick={() => setOpenIdx(openIdx === i ? null : i)}
              aria-expanded={openIdx === i}
              aria-controls={`diff-body-${i}`}
              style={{ width: '100%', background: 'transparent', border: 'none', cursor: 'pointer', padding: '8px 12px', textAlign: 'left' }}
            >
              <span className="diff-file-path">{f.path}</span>
              <span className="diff-file-stats">+{f.stats.added} / -{f.stats.removed}</span>
            </button>
            {openIdx === i && (
              <div className="diff-file-body" id={`diff-body-${i}`}>
                {f.hunks.map((h, j) => (
                  <React.Fragment key={j}>
                    <div style={{ padding: '4px 12px', color: 'var(--text-muted)', background: 'var(--bg-elev-2)', fontSize: 11 }}>
                      {h.head}
                    </div>
                    {h.lines.map((ln, k) => (
                      <div className={`diff-line ${ln.type}`} key={k}>
                        <span className="ln">{ln.type === 'add' ? '+' : ln.type === 'del' ? '-' : ' '}</span>
                        <span className="code">{ln.text}</span>
                      </div>
                    ))}
                  </React.Fragment>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function deriveFiles(state: ViewState): DiffFile[] | null {
  // We do not have a real diff store yet. Return null so the viewer
  // falls back to synthetic fixtures, making it clear these are NOT
  // authoritative. The E2E Host swap-in will populate a real diff.
  if (state.diffFileCount > 0) return null;
  return null;
}

// Keep type import referenced to avoid noUnusedLocals errors
export type { ContractEvent };
