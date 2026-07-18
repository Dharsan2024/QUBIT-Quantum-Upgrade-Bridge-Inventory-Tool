import { AnimatedPage } from '../components/AnimatedPage';
import { ArrowLeft, Check, X, RefreshCw, HardDriveUpload, Code2 } from 'lucide-react';
import { Link, useParams } from 'react-router';
import ReactDiffViewer, { DiffMethod } from 'react-diff-viewer-continued';

const OLD_CODE = `import hashlib

def hash_password(password: str) -> str:
    # Use MD5 for speed
    h = hashlib.md5()
    h.update(password.encode('utf-8'))
    return h.hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed
`;

const NEW_CODE = `import hashlib
from passlib.hash import argon2

def hash_password(password: str) -> str:
    # Upgraded to Argon2 for post-quantum resistance
    return argon2.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return argon2.verify(password, hashed)
`;

export function MigrationDetail() {
  const { mid } = useParams();

  return (
    <AnimatedPage className="flex flex-col gap-5 py-4 max-w-7xl mx-auto">
      <div className="flex items-center gap-4 text-sm text-[color:var(--color-ink-faint)] mb-2">
        <Link to="/migrations" className="flex items-center gap-1 hover:text-[color:var(--color-accent)] transition-colors">
          <ArrowLeft className="w-4 h-4" />
          Back to Queue
        </Link>
        <span>/</span>
        <span className="text-[color:var(--color-ink-dim)] font-mono">{mid || 'm-101'}</span>
      </div>

      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white mb-2 font-mono flex items-center gap-2 tracking-tight">
            <Code2 className="w-6 h-6 text-indigo-400" />
            src/auth/hash.py:42
          </h1>
          <div className="flex gap-2 items-center text-sm">
            <span className="px-2 py-1 bg-rose-500/10 text-[color:var(--color-danger)] rounded border border-rose-500/20">MD5</span>
            <span className="text-[color:var(--color-ink-faint)]">&rarr;</span>
            <span className="px-2 py-1 bg-emerald-500/10 text-[color:var(--color-safe)] rounded border border-emerald-500/20">argon2</span>
          </div>
        </div>
        
        <div className="flex gap-3">
          <button className="glass-input flex items-center gap-2 text-sm font-medium hover:border-[color:var(--color-ink-dim)]">
            <RefreshCw className="w-4 h-4" /> Regenerate
          </button>
          <button className="glass-input flex items-center gap-2 text-sm font-medium border-rose-500/40 text-rose-300 hover:bg-rose-500/10">
            <X className="w-4 h-4" /> Reject
          </button>
          <button className="flex items-center gap-2 text-sm font-medium rounded-lg px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-white transition-colors shadow-lg shadow-emerald-500/20">
            <Check className="w-4 h-4" /> Approve
          </button>
          {/* Apply button appears when approved and allow_apply is true */}
          <button className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-white rounded-lg flex items-center gap-2 transition-colors shadow-lg shadow-cyan-500/20 text-sm font-medium opacity-50 cursor-not-allowed hidden">
            <HardDriveUpload className="w-4 h-4" /> Apply to Disk
          </button>
        </div>
      </div>

      <div className="glass-card overflow-hidden">
        <div>
          <div className="p-4 border-b border-[color:var(--glass-border)] bg-black/10">
            <h3 className="font-medium text-[color:var(--color-ink-dim)]">LLM Rationale</h3>
            <p className="text-sm text-[color:var(--color-ink-faint)] mt-1">
              MD5 is cryptographically broken and highly vulnerable to collision attacks, providing 0 bits of post-quantum security. The patch upgrades the hashing algorithm to Argon2id via `passlib`, which is the industry standard memory-hard algorithm.
            </p>
          </div>
          <div className="overflow-x-auto text-sm">
          <ReactDiffViewer
            oldValue={OLD_CODE}
            newValue={NEW_CODE}
            splitView={true}
            compareMethod={DiffMethod.WORDS}
            useDarkTheme={true}
            styles={{
              variables: {
                dark: {
                  diffViewerBackground: 'transparent',
                  diffViewerTitleBackground: 'rgba(0,0,0,0.1)',
                  diffViewerTitleColor: '#cbd5e1',
                  diffViewerTitleBorderColor: 'rgba(255,255,255,0.05)',
                  addedBackground: 'rgba(16, 185, 129, 0.1)',
                  addedColor: '#34d399',
                  removedBackground: 'rgba(244, 63, 94, 0.1)',
                  removedColor: '#fb7185',
                  wordAddedBackground: 'rgba(16, 185, 129, 0.2)',
                  wordRemovedBackground: 'rgba(244, 63, 94, 0.2)',
                  addedGutterBackground: 'rgba(16, 185, 129, 0.05)',
                  removedGutterBackground: 'rgba(244, 63, 94, 0.05)',
                  gutterBackground: 'rgba(0,0,0,0.05)',
                  gutterBackgroundDark: 'rgba(0,0,0,0.05)',
                  highlightBackground: 'rgba(255, 255, 255, 0.05)',
                  highlightGutterBackground: 'rgba(255, 255, 255, 0.05)',
                  codeFoldGutterBackground: 'transparent',
                  codeFoldBackground: 'transparent',
                  emptyLineBackground: 'transparent',
                  gutterColor: '#64748b',
                  addedGutterColor: '#34d399',
                  removedGutterColor: '#fb7185',
                  codeFoldContentColor: '#94a3b8',
                }
              }
            }}
          />
          </div>
        </div>
      </div>
    </AnimatedPage>
  );
}
