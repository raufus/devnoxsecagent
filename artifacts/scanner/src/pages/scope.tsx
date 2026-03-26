import { useState } from "react";
import { Layout } from "@/components/layout";
import { Target, Plus, Trash2, CheckCircle, XCircle } from "lucide-react";
import { cn } from "@/lib/utils";

interface ScopeEntry { id: string; pattern: string; type: "include"|"exclude"; protocol: string; host: string; port: string; path: string; }

const STORAGE_KEY = "devnox_scope";
function load(): ScopeEntry[] { try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]"); } catch { return []; } }
function save(s: ScopeEntry[]) { localStorage.setItem(STORAGE_KEY, JSON.stringify(s)); }

export function isInScope(url: string): boolean {
  const scope = load();
  if (scope.length === 0) return true;
  const includes = scope.filter(s => s.type === "include");
  const excludes = scope.filter(s => s.type === "exclude");
  const matchPattern = (entry: ScopeEntry, u: string) => {
    try {
      const p = entry.pattern || `${entry.protocol}://${entry.host}${entry.port ? `:${entry.port}` : ""}${entry.path}`;
      if (p.includes("*")) return new RegExp(p.replace(/\*/g, ".*")).test(u);
      return u.startsWith(p) || u.includes(entry.host);
    } catch { return false; }
  };
  const inInclude = includes.length === 0 || includes.some(e => matchPattern(e, url));
  const inExclude = excludes.some(e => matchPattern(e, url));
  return inInclude && !inExclude;
}

export default function ScopePage() {
  const [scope, setScope] = useState<ScopeEntry[]>(load);
  const [testUrl, setTestUrl] = useState("");

  const add = (type: "include"|"exclude") => {
    const e: ScopeEntry = { id: crypto.randomUUID(), pattern: "", type, protocol: "https", host: "", port: "", path: "/" };
    const u = [...scope, e]; setScope(u); save(u);
  };

  const update = (id: string, changes: Partial<ScopeEntry>) => {
    const u = scope.map(s => s.id === id ? { ...s, ...changes } : s); setScope(u); save(u);
  };

  const del = (id: string) => { const u = scope.filter(s => s.id !== id); setScope(u); save(u); };

  const includes = scope.filter(s => s.type === "include");
  const excludes = scope.filter(s => s.type === "exclude");
  const testResult = testUrl ? isInScope(testUrl) : null;

  const EntryRow = ({ e }: { e: ScopeEntry }) => (
    <div className="flex items-center gap-2 p-2 border border-border/20 flex-wrap">
      <select value={e.protocol} onChange={ev => update(e.id, { protocol: ev.target.value })}
        className="bg-black/50 border border-primary/30 px-2 py-1 font-mono text-[10px] text-foreground focus:outline-none w-20">
        {["https","http","any"].map(p => <option key={p}>{p}</option>)}
      </select>
      <input value={e.host} onChange={ev => update(e.id, { host: ev.target.value })}
        className="flex-1 min-w-32 bg-black/50 border border-primary/30 px-2 py-1 font-mono text-[10px] text-foreground focus:outline-none"
        placeholder="*.example.com" />
      <input value={e.port} onChange={ev => update(e.id, { port: ev.target.value })}
        className="w-16 bg-black/50 border border-primary/30 px-2 py-1 font-mono text-[10px] text-foreground focus:outline-none"
        placeholder="443" />
      <input value={e.path} onChange={ev => update(e.id, { path: ev.target.value })}
        className="flex-1 min-w-24 bg-black/50 border border-primary/30 px-2 py-1 font-mono text-[10px] text-foreground focus:outline-none"
        placeholder="/api/*" />
      <button onClick={() => del(e.id)} className="text-red-400/60 hover:text-red-400 transition-colors">
        <Trash2 className="w-3.5 h-3.5" />
      </button>
    </div>
  );

  return (
    <Layout>
      <div className="space-y-4 animate-in fade-in duration-500">
        <header className="border-b border-primary/20 pb-3">
          <h1 className="text-xl font-display font-bold flex items-center gap-2">
            <Target className="w-5 h-5 text-primary" /> SCOPE CONTROL
          </h1>
          <p className="text-[10px] font-mono text-muted-foreground mt-0.5">Define in-scope and out-of-scope targets</p>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="space-y-3">
            <div className="cyber-box p-4 space-y-2 border-primary/30">
              <div className="flex items-center justify-between">
                <label className="font-mono text-xs text-primary flex items-center gap-2">
                  <CheckCircle className="w-4 h-4" /> INCLUDE IN SCOPE ({includes.length})
                </label>
                <button onClick={() => add("include")} className="cyber-button !py-1 !px-2 text-[10px] flex items-center gap-1">
                  <Plus className="w-3 h-3" /> ADD
                </button>
              </div>
              {includes.length === 0
                ? <p className="font-mono text-[10px] text-muted-foreground">No include rules — all URLs in scope</p>
                : includes.map(e => <EntryRow key={e.id} e={e} />)}
            </div>

            <div className="cyber-box p-4 space-y-2 border-red-400/20">
              <div className="flex items-center justify-between">
                <label className="font-mono text-xs text-red-400 flex items-center gap-2">
                  <XCircle className="w-4 h-4" /> EXCLUDE FROM SCOPE ({excludes.length})
                </label>
                <button onClick={() => add("exclude")} className="cyber-button !py-1 !px-2 text-[10px] flex items-center gap-1 !border-red-400/30 !text-red-400">
                  <Plus className="w-3 h-3" /> ADD
                </button>
              </div>
              {excludes.length === 0
                ? <p className="font-mono text-[10px] text-muted-foreground">No exclude rules</p>
                : excludes.map(e => <EntryRow key={e.id} e={e} />)}
            </div>
          </div>

          <div className="cyber-box p-4 space-y-3">
            <label className="font-mono text-xs text-primary">TEST URL AGAINST SCOPE</label>
            <input value={testUrl} onChange={e => setTestUrl(e.target.value)}
              className="w-full bg-black/50 border border-primary/30 px-3 py-2 font-mono text-sm text-foreground focus:outline-none focus:border-primary"
              placeholder="https://example.com/api/users" />
            {testResult !== null && (
              <div className={cn("p-3 border font-mono text-sm flex items-center gap-2",
                testResult ? "border-primary/40 bg-primary/10 text-primary" : "border-red-400/40 bg-red-400/10 text-red-400")}>
                {testResult ? <CheckCircle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                {testResult ? "IN SCOPE — This URL will be tested" : "OUT OF SCOPE — This URL will be skipped"}
              </div>
            )}
            <div className="font-mono text-[10px] text-muted-foreground space-y-1">
              <p>• Use * as wildcard: *.example.com</p>
              <p>• Leave port empty to match any port</p>
              <p>• Path /api/* matches all API endpoints</p>
              <p>• Scope is used by Scanner and Crawler</p>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
