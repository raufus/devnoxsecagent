import { useState, useEffect } from "react";
import { Layout } from "@/components/layout";
import { History, Filter, Trash2, ExternalLink, Search, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
import { Link } from "wouter";

interface HistoryEntry {
  id: string; timestamp: number; method: string; url: string;
  status: number; length: number; time: number; mimeType: string;
  request: string; response: string;
}

const STORAGE_KEY = "devnox_http_history";

function loadHistory(): HistoryEntry[] {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]"); } catch { return []; }
}

export function addToHistory(entry: Omit<HistoryEntry, "id"|"timestamp">) {
  const history = loadHistory();
  const newEntry: HistoryEntry = { ...entry, id: crypto.randomUUID(), timestamp: Date.now() };
  const updated = [newEntry, ...history].slice(0, 500);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
}

export default function HttpHistoryPage() {
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [selected, setSelected] = useState<HistoryEntry | null>(null);
  const [search, setSearch] = useState("");
  const [filterMethod, setFilterMethod] = useState("ALL");
  const [filterStatus, setFilterStatus] = useState("ALL");

  useEffect(() => { setHistory(loadHistory()); }, []);

  const refresh = () => setHistory(loadHistory());
  const clear = () => { localStorage.removeItem(STORAGE_KEY); setHistory([]); setSelected(null); };

  const filtered = history.filter(h =>
    (filterMethod === "ALL" || h.method === filterMethod) &&
    (filterStatus === "ALL" || String(h.status).startsWith(filterStatus)) &&
    (!search || h.url.toLowerCase().includes(search.toLowerCase()))
  );

  const sc = (s: number) => s < 300 ? "text-green-400" : s < 400 ? "text-yellow-400" : s < 500 ? "text-orange-400" : "text-red-400";

  return (
    <Layout>
      <div className="space-y-3 animate-in fade-in duration-500">
        <header className="border-b border-primary/20 pb-3 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-display font-bold flex items-center gap-2">
              <History className="w-5 h-5 text-primary" /> HTTP HISTORY
            </h1>
            <p className="text-[10px] font-mono text-muted-foreground mt-0.5">All HTTP requests made through Repeater and Interceptor</p>
          </div>
          <div className="flex gap-2">
            <button onClick={refresh} className="cyber-button !py-1.5 !px-3 text-[10px] flex items-center gap-1">
              <RefreshCw className="w-3 h-3" /> REFRESH
            </button>
            <button onClick={clear} className="cyber-button !py-1.5 !px-3 text-[10px] flex items-center gap-1 !border-red-400/30 !text-red-400">
              <Trash2 className="w-3 h-3" /> CLEAR
            </button>
          </div>
        </header>

        {/* Filters */}
        <div className="flex flex-wrap gap-2 items-center">
          <div className="relative flex-1 min-w-48">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground" />
            <input value={search} onChange={e => setSearch(e.target.value)}
              className="w-full bg-black/50 border border-primary/30 pl-7 pr-3 py-1.5 font-mono text-xs text-foreground focus:outline-none focus:border-primary"
              placeholder="Filter by URL..." />
          </div>
          <div className="flex gap-1">
            {["ALL","GET","POST","PUT","DELETE"].map(m => (
              <button key={m} onClick={() => setFilterMethod(m)}
                className={cn("px-2 py-1.5 font-mono text-[10px] border transition-all",
                  filterMethod === m ? "border-primary text-primary bg-primary/10" : "border-border/30 text-muted-foreground")}>
                {m}
              </button>
            ))}
          </div>
          <div className="flex gap-1">
            {["ALL","2","3","4","5"].map(s => (
              <button key={s} onClick={() => setFilterStatus(s)}
                className={cn("px-2 py-1.5 font-mono text-[10px] border transition-all",
                  filterStatus === s ? "border-primary text-primary bg-primary/10" : "border-border/30 text-muted-foreground")}>
                {s === "ALL" ? "ALL" : `${s}xx`}
              </button>
            ))}
          </div>
          <span className="font-mono text-[10px] text-muted-foreground">{filtered.length} entries</span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className="cyber-box overflow-hidden" style={{ maxHeight: "600px" }}>
            <div className="grid grid-cols-12 p-2 border-b border-primary/20 font-mono text-[10px] text-muted-foreground bg-black/30">
              <span className="col-span-1">#</span>
              <span className="col-span-2">METHOD</span>
              <span className="col-span-5">URL</span>
              <span className="col-span-2 text-center">STATUS</span>
              <span className="col-span-2 text-center">TIME</span>
            </div>
            <div className="overflow-y-auto" style={{ maxHeight: "540px" }}>
              {filtered.length === 0 ? (
                <div className="p-8 text-center font-mono text-xs text-muted-foreground">
                  <History className="w-8 h-8 mx-auto mb-2 opacity-20" />
                  No history yet — use Repeater or Interceptor
                </div>
              ) : filtered.map((h, i) => (
                <div key={h.id} onClick={() => setSelected(h)}
                  className={cn("grid grid-cols-12 p-2 border-b border-border/20 cursor-pointer hover:bg-white/5 transition-colors font-mono text-[10px]",
                    selected?.id === h.id && "bg-primary/10 border-l-2 border-l-primary")}>
                  <span className="col-span-1 text-muted-foreground">{i + 1}</span>
                  <span className={cn("col-span-2 font-bold", h.method === "GET" ? "text-cyan-400" : h.method === "POST" ? "text-orange-400" : "text-yellow-400")}>{h.method}</span>
                  <span className="col-span-5 truncate text-foreground/80">{h.url}</span>
                  <span className={cn("col-span-2 text-center font-bold", sc(h.status))}>{h.status}</span>
                  <span className="col-span-2 text-center text-muted-foreground">{h.time}ms</span>
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            {selected ? (
              <>
                <div className="cyber-box p-3">
                  <div className="font-mono text-[10px] text-primary mb-2 flex items-center justify-between">
                    REQUEST
                    <Link href="/tools/repeater" className="text-[9px] text-cyan-400 flex items-center gap-1 hover:text-cyan-300">
                      <ExternalLink className="w-2.5 h-2.5" /> Open in Repeater
                    </Link>
                  </div>
                  <pre className="bg-black/50 p-2 font-mono text-[10px] text-foreground/80 overflow-auto max-h-48 whitespace-pre-wrap break-all border border-primary/10">
                    {selected.request || `${selected.method} ${selected.url} HTTP/1.1`}
                  </pre>
                </div>
                <div className="cyber-box p-3">
                  <div className="font-mono text-[10px] text-primary mb-2 flex items-center justify-between">
                    RESPONSE
                    <span className={cn("font-bold", sc(selected.status))}>{selected.status} · {selected.length}B · {selected.time}ms</span>
                  </div>
                  <pre className="bg-black/50 p-2 font-mono text-[10px] text-green-300 overflow-auto max-h-48 whitespace-pre-wrap break-all border border-primary/10">
                    {selected.response || "(no response captured)"}
                  </pre>
                </div>
              </>
            ) : (
              <div className="cyber-box flex items-center justify-center" style={{ minHeight: "300px" }}>
                <div className="text-center font-mono text-muted-foreground">
                  <History className="w-10 h-10 mx-auto mb-2 opacity-20" />
                  <p className="text-sm">Select a request to view details</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}
