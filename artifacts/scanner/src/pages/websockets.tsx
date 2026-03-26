import { useState, useRef, useEffect } from "react";
import { Layout } from "@/components/layout";
import { Wifi, Send, Trash2, Circle, Download } from "lucide-react";
import { cn } from "@/lib/utils";

interface WsMessage { id: string; direction: "sent"|"received"; data: string; timestamp: number; size: number; }

export default function WebSocketsPage() {
  const [url, setUrl] = useState("wss://");
  const [connected, setConnected] = useState(false);
  const [messages, setMessages] = useState<WsMessage[]>([]);
  const [input, setInput] = useState("");
  const [error, setError] = useState("");
  const [interceptMode, setInterceptMode] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  const connect = () => {
    if (wsRef.current) { wsRef.current.close(); }
    setError(""); setMessages([]);
    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;
      ws.onopen = () => { setConnected(true); addMsg("connected", "received", 0); };
      ws.onmessage = (e) => { addMsg(String(e.data), "received", String(e.data).length); };
      ws.onerror = () => { setError("Connection error"); setConnected(false); };
      ws.onclose = () => { setConnected(false); addMsg("disconnected", "received", 0); };
    } catch (e: any) { setError(e.message); }
  };

  const disconnect = () => { wsRef.current?.close(); wsRef.current = null; setConnected(false); };

  const addMsg = (data: string, direction: "sent"|"received", size: number) => {
    setMessages(p => [...p, { id: crypto.randomUUID(), direction, data, timestamp: Date.now(), size }]);
  };

  const send = () => {
    if (!input || !wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    wsRef.current.send(input);
    addMsg(input, "sent", input.length);
    setInput("");
  };

  const exportHistory = () => {
    const blob = new Blob([JSON.stringify(messages, null, 2)], { type: "application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "ws_history.json"; a.click();
  };

  return (
    <Layout>
      <div className="space-y-3 animate-in fade-in duration-500">
        <header className="border-b border-primary/20 pb-3 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-display font-bold flex items-center gap-2">
              <Wifi className="w-5 h-5 text-primary" /> WEBSOCKETS TESTER
            </h1>
            <p className="text-[10px] font-mono text-muted-foreground mt-0.5">Real WebSocket connection — send/receive messages, test security</p>
          </div>
          <div className="flex gap-2">
            <button onClick={exportHistory} disabled={messages.length === 0}
              className="cyber-button !py-1.5 !px-3 text-[10px] flex items-center gap-1">
              <Download className="w-3 h-3" /> EXPORT
            </button>
            <button onClick={() => setMessages([])} className="cyber-button !py-1.5 !px-3 text-[10px] flex items-center gap-1 !border-red-400/30 !text-red-400">
              <Trash2 className="w-3 h-3" /> CLEAR
            </button>
          </div>
        </header>

        {/* Connection */}
        <div className="cyber-box p-4 space-y-3">
          <div className="flex gap-2 items-center">
            <Circle className={cn("w-3 h-3 shrink-0", connected ? "text-primary fill-primary animate-pulse" : "text-muted-foreground")} />
            <input value={url} onChange={e => setUrl(e.target.value)} disabled={connected}
              className="flex-1 bg-black/50 border border-primary/30 px-3 py-2 font-mono text-sm text-foreground focus:outline-none focus:border-primary disabled:opacity-50"
              placeholder="wss://target.com/ws" />
            {!connected
              ? <button onClick={connect} className="cyber-button !py-2 !px-4 text-xs">CONNECT</button>
              : <button onClick={disconnect} className="cyber-button !py-2 !px-4 text-xs !border-red-400/40 !text-red-400">DISCONNECT</button>}
          </div>
          {error && <div className="font-mono text-[10px] text-red-400 border border-red-400/20 bg-red-400/5 p-2">{error}</div>}
        </div>

        {/* Messages */}
        <div className="cyber-box overflow-hidden" style={{ height: "400px" }}>
          <div className="flex items-center justify-between p-2 border-b border-primary/20 bg-black/20">
            <span className="font-mono text-[10px] text-primary">{messages.length} messages</span>
            <label className="flex items-center gap-2 font-mono text-[10px] text-muted-foreground cursor-pointer">
              <input type="checkbox" checked={interceptMode} onChange={e => setInterceptMode(e.target.checked)} className="accent-primary" />
              INTERCEPT MODE
            </label>
          </div>
          <div className="overflow-y-auto p-2 space-y-1" style={{ height: "340px" }}>
            {messages.map(m => (
              <div key={m.id} className={cn("flex gap-2 font-mono text-[10px]", m.direction === "sent" ? "justify-end" : "justify-start")}>
                <div className={cn("max-w-[80%] p-2 border break-all",
                  m.direction === "sent" ? "border-primary/30 bg-primary/10 text-primary" : "border-border/30 bg-black/30 text-foreground/80",
                  m.data === "connected" || m.data === "disconnected" ? "opacity-50 italic" : "")}>
                  <div className="text-[8px] text-muted-foreground mb-0.5">
                    {m.direction === "sent" ? "→ SENT" : "← RECV"} · {new Date(m.timestamp).toLocaleTimeString()} · {m.size}B
                  </div>
                  {m.data}
                </div>
              </div>
            ))}
            <div ref={bottomRef} />
          </div>
        </div>

        {/* Send */}
        <div className="flex gap-2">
          <input value={input} onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === "Enter" && !e.shiftKey && send()}
            disabled={!connected}
            className="flex-1 bg-black/50 border border-primary/30 px-3 py-2 font-mono text-sm text-foreground focus:outline-none focus:border-primary disabled:opacity-50"
            placeholder={connected ? 'Type message and press Enter...' : 'Connect first'} />
          <button onClick={send} disabled={!connected || !input}
            className="cyber-button !py-2 !px-4 text-xs flex items-center gap-1.5 disabled:opacity-40">
            <Send className="w-3.5 h-3.5" /> SEND
          </button>
        </div>

        {/* Security Tests */}
        {connected && (
          <div className="cyber-box p-4">
            <label className="font-mono text-xs text-primary mb-3 block">QUICK SECURITY TESTS</label>
            <div className="flex flex-wrap gap-2">
              {[
                { label: "XSS Test", payload: `<script>alert(1)</script>` },
                { label: "SQLi Test", payload: `' OR 1=1--` },
                { label: "JSON Injection", payload: `{"__proto__":{"admin":true}}` },
                { label: "Large Payload", payload: "A".repeat(10000) },
                { label: "Null Byte", payload: `test\x00injection` },
                { label: "CRLF", payload: `test\r\ninjection` },
              ].map(({ label, payload }) => (
                <button key={label} onClick={() => { wsRef.current?.send(payload); addMsg(payload, "sent", payload.length); }}
                  className="cyber-button !py-1 !px-2 text-[10px] !border-red-400/30 !text-red-400">
                  {label}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
