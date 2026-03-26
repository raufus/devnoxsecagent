import { useState, useRef } from "react";
import { Layout } from "@/components/layout";
import { cn } from "@/lib/utils";
import { Send, Clock, Plus, Trash2, Copy, Check, ChevronDown, ChevronUp } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"] as const;
type Method = typeof METHODS[number];

interface Header { key: string; value: string; enabled: boolean; }
interface RepeaterTab {
  id: string;
  label: string;
  method: Method;
  url: string;
  headers: Header[];
  body: string;
  followRedirects: boolean;
  response: RepeaterResponse | null;
  loading: boolean;
}
interface RepeaterResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  elapsed: number;
  url: string;
  error?: string;
}

const DEFAULT_HEADERS: Header[] = [
  { key: "User-Agent", value: "Devnox-Sec-Agent/2.0", enabled: true },
  { key: "Accept", value: "*/*", enabled: true },
];

let tabCounter = 1;

function newTab(overrides: Partial<RepeaterTab> = {}): RepeaterTab {
  return {
    id: String(Date.now()),
    label: `REQ-${tabCounter++}`,
    method: "GET",
    url: "",
    headers: [...DEFAULT_HEADERS.map(h => ({ ...h }))],
    body: "",
    followRedirects: false,
    response: null,
    loading: false,
    ...overrides,
  };
}

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      className="p-1 text-muted-foreground hover:text-primary transition-colors">
      {copied ? <Check className="w-3 h-3 text-primary" /> : <Copy className="w-3 h-3" />}
    </button>
  );
}

function statusColor(s: number) {
  if (s < 300) return "text-primary border-primary bg-primary/10";
  if (s < 400) return "text-cyan-400 border-cyan-400 bg-cyan-400/10";
  if (s < 500) return "text-yellow-400 border-yellow-400 bg-yellow-400/10";
  return "text-red-400 border-red-400 bg-red-400/10";
}

function HeadersEditor({ headers, onChange }: { headers: Header[]; onChange: (h: Header[]) => void }) {
  const update = (i: number, field: keyof Header, val: any) => {
    const next = [...headers];
    next[i] = { ...next[i], [field]: val };
    onChange(next);
  };
  const remove = (i: number) => onChange(headers.filter((_, j) => j !== i));
  const add = () => onChange([...headers, { key: "", value: "", enabled: true }]);

  return (
    <div className="space-y-1">
      {headers.map((h, i) => (
        <div key={i} className="flex gap-1 items-center">
          <input type="checkbox" checked={h.enabled} onChange={e => update(i, "enabled", e.target.checked)}
            className="w-3 h-3 accent-primary shrink-0 cursor-pointer" />
          <input value={h.key} onChange={e => update(i, "key", e.target.value)}
            placeholder="Header-Name"
            className={cn("flex-1 bg-black/40 border border-border/50 px-2 py-1 font-mono text-xs focus:outline-none focus:border-primary transition-colors", !h.enabled && "opacity-40")} />
          <input value={h.value} onChange={e => update(i, "value", e.target.value)}
            placeholder="value"
            className={cn("flex-[2] bg-black/40 border border-border/50 px-2 py-1 font-mono text-xs focus:outline-none focus:border-primary transition-colors", !h.enabled && "opacity-40")} />
          <button onClick={() => remove(i)} className="p-1 text-muted-foreground hover:text-red-400 transition-colors shrink-0">
            <Trash2 className="w-3 h-3" />
          </button>
        </div>
      ))}
      <button onClick={add} className="font-mono text-[10px] text-primary/60 hover:text-primary flex items-center gap-1 mt-1 transition-colors">
        <Plus className="w-3 h-3" /> ADD HEADER
      </button>
    </div>
  );
}

export default function Repeater() {
  const [tabs, setTabs] = useState<RepeaterTab[]>([newTab()]);
  const [activeTab, setActiveTab] = useState(0);
  const [showRespHeaders, setShowRespHeaders] = useState(false);
  const { toast } = useToast();

  const tab = tabs[activeTab];

  const updateTab = (updates: Partial<RepeaterTab>) => {
    setTabs(prev => prev.map((t, i) => i === activeTab ? { ...t, ...updates } : t));
  };

  const addTab = () => {
    const newT = newTab();
    setTabs(prev => [...prev, newT]);
    setActiveTab(tabs.length);
  };

  const removeTab = (i: number, e: React.MouseEvent) => {
    e.stopPropagation();
    if (tabs.length === 1) return;
    const next = tabs.filter((_, j) => j !== i);
    setTabs(next);
    setActiveTab(Math.min(activeTab, next.length - 1));
  };

  const sendRequest = async () => {
    if (!tab.url) { toast({ title: "URL required", variant: "destructive" }); return; }
    updateTab({ loading: true, response: null });

    const enabledHeaders: Record<string, string> = {};
    tab.headers.filter(h => h.enabled && h.key).forEach(h => { enabledHeaders[h.key] = h.value; });

    try {
      const res = await fetch("/api/tools/repeater", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          method: tab.method,
          url: tab.url,
          headers: enabledHeaders,
          body: tab.body || "",
          followRedirects: tab.followRedirects,
          timeout: 15000,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        updateTab({ loading: false, response: data });
        // Auto-save to HTTP History
        try {
          const history = JSON.parse(localStorage.getItem("devnox_http_history") || "[]");
          history.unshift({
            id: crypto.randomUUID(), timestamp: Date.now(),
            method: tab.method, url: tab.url,
            status: data.status, length: data.body?.length || 0,
            time: data.elapsed || 0, mimeType: data.headers?.["content-type"] || "",
            request: rawRequest, response: data.body?.substring(0, 2000) || "",
          });
          localStorage.setItem("devnox_http_history", JSON.stringify(history.slice(0, 500)));
        } catch { }
      } else {
        updateTab({ loading: false, response: { status: 0, statusText: "Error", headers: {}, body: data.message || "Request failed", elapsed: data.elapsed || 0, url: tab.url, error: data.message } });
      }
    } catch (err: any) {
      updateTab({ loading: false, response: { status: 0, statusText: "Network Error", headers: {}, body: err.message, elapsed: 0, url: tab.url, error: err.message } });
    }
  };

  const rawRequest = `${tab.method} ${tab.url} HTTP/1.1\n${tab.headers.filter(h => h.enabled && h.key).map(h => `${h.key}: ${h.value}`).join("\n")}${tab.body ? `\n\n${tab.body}` : ""}`;

  return (
    <Layout>
      <div className="space-y-3 animate-in fade-in duration-500">
        <header>
          <h1 className="text-2xl sm:text-3xl">HTTP_REPEATER</h1>
          <p className="text-muted-foreground font-mono text-xs mt-1">// Craft, send and analyze raw HTTP requests</p>
        </header>

        {/* Tabs */}
        <div className="flex items-center gap-1 border-b border-primary/20 overflow-x-auto">
          {tabs.map((t, i) => (
            <button
              key={t.id}
              onClick={() => setActiveTab(i)}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 font-mono text-[11px] border-b-2 whitespace-nowrap shrink-0 transition-colors",
                i === activeTab ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground"
              )}
            >
              <span className={cn("w-1.5 h-1.5 rounded-full shrink-0",
                t.response ? (t.response.status >= 400 ? "bg-red-500" : t.response.status >= 300 ? "bg-yellow-500" : "bg-primary") : "bg-muted-foreground/40"
              )} />
              {t.label}
              {tabs.length > 1 && (
                <span onClick={e => removeTab(i, e)} className="ml-1 hover:text-red-400 transition-colors">×</span>
              )}
            </button>
          ))}
          <button onClick={addTab} className="px-2 py-1.5 text-muted-foreground hover:text-primary transition-colors font-mono text-sm shrink-0">+</button>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          {/* Request Panel */}
          <div className="space-y-3">
            {/* Method + URL + Send */}
            <div className="flex gap-2">
              <select
                value={tab.method}
                onChange={e => updateTab({ method: e.target.value as Method })}
                className="bg-black/60 border border-primary/40 text-primary font-mono text-xs px-2 py-2 focus:outline-none focus:border-primary shrink-0 cursor-pointer"
              >
                {METHODS.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
              <input
                value={tab.url}
                onChange={e => updateTab({ url: e.target.value })}
                onKeyDown={e => e.key === "Enter" && sendRequest()}
                placeholder="https://target.example.com/api/endpoint?param=value"
                className="flex-1 bg-black/50 border border-border/50 px-3 py-2 font-mono text-sm text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary transition-colors min-w-0"
              />
              <button
                onClick={sendRequest}
                disabled={tab.loading}
                className="cyber-button !py-2 !px-4 flex items-center gap-1.5 text-sm shrink-0"
              >
                {tab.loading
                  ? <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                  : <Send className="w-4 h-4" />}
                SEND
              </button>
            </div>

            {/* Options */}
            <div className="flex items-center gap-4 text-xs font-mono">
              <label className="flex items-center gap-1.5 cursor-pointer text-muted-foreground hover:text-foreground">
                <input type="checkbox" checked={tab.followRedirects} onChange={e => updateTab({ followRedirects: e.target.checked })}
                  className="w-3 h-3 accent-primary" />
                FOLLOW REDIRECTS
              </label>
            </div>

            {/* Headers */}
            <div className="cyber-box p-3">
              <h3 className="font-mono text-xs text-primary mb-2">HEADERS</h3>
              <HeadersEditor headers={tab.headers} onChange={headers => updateTab({ headers })} />
            </div>

            {/* Body */}
            {!["GET", "HEAD"].includes(tab.method) && (
              <div className="cyber-box p-0">
                <div className="flex items-center justify-between px-3 py-2 border-b border-primary/20 bg-primary/5">
                  <span className="font-mono text-xs text-primary">REQUEST BODY</span>
                  <CopyBtn text={tab.body} />
                </div>
                <textarea
                  value={tab.body}
                  onChange={e => updateTab({ body: e.target.value })}
                  placeholder='{"key": "value"} or form=data&param=value'
                  className="w-full min-h-[160px] p-3 bg-transparent font-mono text-xs text-foreground resize-y focus:outline-none placeholder:text-muted-foreground/40"
                  spellCheck={false}
                />
              </div>
            )}

            {/* Raw Request Preview */}
            <div className="cyber-box p-0">
              <div className="flex items-center justify-between px-3 py-2 border-b border-border/30">
                <span className="font-mono text-[10px] text-muted-foreground">RAW REQUEST PREVIEW</span>
                <CopyBtn text={rawRequest} />
              </div>
              <pre className="p-3 font-mono text-[10px] text-foreground/50 overflow-x-auto max-h-24 whitespace-pre-wrap break-all">
                {rawRequest}
              </pre>
            </div>
          </div>

          {/* Response Panel */}
          <div className="space-y-3">
            {!tab.response && !tab.loading && (
              <div className="cyber-box p-8 flex flex-col items-center justify-center h-48 text-muted-foreground font-mono text-xs gap-2">
                <Send className="w-8 h-8 opacity-20" />
                <p>Send a request to see the response</p>
              </div>
            )}

            {tab.loading && (
              <div className="cyber-box p-8 flex flex-col items-center justify-center h-48 gap-2">
                <div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin" />
                <p className="font-mono text-xs text-primary animate-pulse">SENDING REQUEST...</p>
              </div>
            )}

            {tab.response && (
              <>
                {/* Status Bar */}
                <div className="cyber-box p-3 flex flex-wrap items-center gap-3">
                  <span className={cn("font-mono font-bold text-sm px-2 py-0.5 border", statusColor(tab.response.status))}>
                    {tab.response.status || "ERR"} {tab.response.statusText}
                  </span>
                  {tab.response.elapsed > 0 && (
                    <span className="font-mono text-xs text-muted-foreground flex items-center gap-1">
                      <Clock className="w-3 h-3" /> {tab.response.elapsed}ms
                    </span>
                  )}
                  {tab.response.headers["content-length"] && (
                    <span className="font-mono text-xs text-muted-foreground">{tab.response.headers["content-length"]} bytes</span>
                  )}
                  {tab.response.redirected && (
                    <span className="font-mono text-[10px] text-yellow-400 border border-yellow-400/30 px-1">REDIRECTED</span>
                  )}
                  <span className="font-mono text-[10px] text-muted-foreground/60 ml-auto truncate max-w-[200px]" title={tab.response.url}>
                    {tab.response.url}
                  </span>
                </div>

                {/* Response Headers (collapsible) */}
                <div className="cyber-box p-0">
                  <button
                    onClick={() => setShowRespHeaders(!showRespHeaders)}
                    className="w-full flex items-center justify-between px-3 py-2 border-b border-primary/20 bg-primary/5 hover:bg-primary/10 transition-colors"
                  >
                    <span className="font-mono text-xs text-primary">
                      RESPONSE HEADERS ({Object.keys(tab.response.headers).length})
                    </span>
                    {showRespHeaders ? <ChevronUp className="w-3.5 h-3.5 text-primary" /> : <ChevronDown className="w-3.5 h-3.5 text-primary" />}
                  </button>
                  {showRespHeaders && (
                    <div className="p-2 max-h-48 overflow-y-auto">
                      {Object.entries(tab.response.headers).map(([k, v]) => (
                        <div key={k} className="flex gap-2 py-0.5 font-mono text-[11px]">
                          <span className="text-cyan-400 shrink-0">{k}:</span>
                          <span className="text-foreground/70 break-all">{v}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Response Body */}
                <div className="cyber-box p-0">
                  <div className="flex items-center justify-between px-3 py-2 border-b border-primary/20 bg-primary/5">
                    <span className="font-mono text-xs text-primary">
                      RESPONSE BODY ({tab.response.headers["content-type"] || "text/plain"})
                    </span>
                    <CopyBtn text={tab.response.body} />
                  </div>
                  <pre className="p-3 font-mono text-[11px] text-foreground/80 overflow-auto max-h-[400px] whitespace-pre-wrap break-all">
                    {tab.response.body || "(Empty response)"}
                  </pre>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}
