import { useState, useRef } from "react";
import { Layout } from "@/components/layout";
import { Radio, Trash2, Copy, Send, RefreshCw, Download, ChevronDown, ChevronUp, AlertTriangle, Plus, Filter } from "lucide-react";
import { cn } from "@/lib/utils";

interface Req {
  id: string; method: string; url: string;
  headers: Record<string, string>; body: string;
  status?: number; responseHeaders?: Record<string, string>;
  responseBody?: string; responseTime?: number;
  tag?: string; flagged: boolean;
}

const METHODS = ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"];
const TAGS = ["XSS","SQLi","SSRF","Auth","IDOR","Interesting","Ignore"];
const TAG_COLORS: Record<string,string> = {
  XSS:"text-red-400 border-red-400/40 bg-red-400/10",
  SQLi:"text-orange-400 border-orange-400/40 bg-orange-400/10",
  SSRF:"text-yellow-400 border-yellow-400/40 bg-yellow-400/10",
  Auth:"text-purple-400 border-purple-400/40 bg-purple-400/10",
  IDOR:"text-blue-400 border-blue-400/40 bg-blue-400/10",
  Interesting:"text-primary border-primary/40 bg-primary/10",
  Ignore:"text-muted-foreground border-border/40",
};
const sc = (s?:number) => !s?"text-muted-foreground":s<300?"text-green-400":s<400?"text-yellow-400":s<500?"text-orange-400":"text-red-400";

export default function InterceptorPage() {
  const [reqs, setReqs] = useState<Req[]>([]);
  const [sel, setSel] = useState<Req|null>(null);
  const [url, setUrl] = useState(""); const [method, setMethod] = useState("GET");
  const [headers, setHeaders] = useState('{"User-Agent":"DevNox-Interceptor/2.0","Accept":"*/*"}');
  const [body, setBody] = useState(""); const [sending, setSending] = useState(false);
  const [newUrl, setNewUrl] = useState("https://"); const [newMethod, setNewMethod] = useState("GET");
  const [filterM, setFilterM] = useState("ALL"); const [showResp, setShowResp] = useState(true);
  const ctr = useRef(0);

  const pick = (r:Req) => { setSel(r); setUrl(r.url); setMethod(r.method); setHeaders(JSON.stringify(r.headers,null,2)); setBody(r.body); };

  const add = () => {
    if (!newUrl || newUrl==="https://") return;
    const r:Req = { id:`r${++ctr.current}`, method:newMethod, url:newUrl, headers:{"User-Agent":"DevNox-Interceptor/2.0"}, body:"", flagged:false };
    setReqs(p=>[r,...p]); pick(r);
  };

  const send = async () => {
    if (!url) return; setSending(true);
    try {
      let h:Record<string,string>={};
      try{h=JSON.parse(headers);}catch{}
      const res = await fetch("/api/tools/repeater",{method:"POST",headers:{"Content-Type":"application/json"},credentials:"include",
        body:JSON.stringify({method,url,headers:h,body,followRedirects:false,timeout:15000})});
      const d = await res.json();
      const updated:Req = { id:sel?.id||`r${++ctr.current}`, method, url, headers:h, body,
        status:d.status, responseHeaders:d.headers||{}, responseBody:d.body||"", responseTime:d.elapsed,
        tag:sel?.tag, flagged:sel?.flagged||false };
      setReqs(p=>{ const i=p.findIndex(x=>x.id===updated.id); if(i>=0){const n=[...p];n[i]=updated;return n;} return [updated,...p]; });
      setSel(updated);
      // Auto-save to HTTP History
      try {
        const hist = JSON.parse(localStorage.getItem("devnox_http_history")||"[]");
        hist.unshift({ id:crypto.randomUUID(), timestamp:Date.now(), method:editMethod, url:editUrl,
          status:d.status, length:d.body?.length||0, time:d.elapsed||(Date.now()-start),
          mimeType:d.headers?.["content-type"]||"",
          request:`${editMethod} ${editUrl}\n${editHeaders}${editBody?"\n\n"+editBody:""}`,
          response:d.body?.substring(0,2000)||"" });
        localStorage.setItem("devnox_http_history", JSON.stringify(hist.slice(0,500)));
      } catch {}
    } catch(e){console.error(e);} finally{setSending(false);}
  };

  const tag = (id:string,t:string) => {
    setReqs(p=>p.map(r=>r.id===id?{...r,tag:t,flagged:t!=="Ignore"}:r));
    if(sel?.id===id) setSel(p=>p?{...p,tag:t,flagged:t!=="Ignore"}:null);
  };

  const curl = () => {
    let c=`curl -X ${method} '${url}'`;
    try{Object.entries(JSON.parse(headers)).forEach(([k,v])=>{c+=` \\\n  -H '${k}: ${v}'`;});}catch{}
    if(body&&!["GET","HEAD"].includes(method)) c+=` \\\n  -d '${body}'`;
    navigator.clipboard.writeText(c);
  };

  const analyze = (r:Req) => {
    if(!r.responseBody) return [];
    const b=r.responseBody.toLowerCase(); const flags=[];
    if(b.includes("sql")||b.includes("mysql")||b.includes("ora-")) flags.push({l:"SQL Error",c:"text-red-400 border-red-400/40"});
    if(b.includes("exception")||b.includes("stack trace")) flags.push({l:"Exception",c:"text-red-400 border-red-400/40"});
    if(b.includes("password")||b.includes("secret")) flags.push({l:"Secret Leak",c:"text-orange-400 border-orange-400/40"});
    if(r.responseBody.includes("<script")) flags.push({l:"Script Tag",c:"text-red-400 border-red-400/40"});
    if((r.responseTime||0)>4000) flags.push({l:"Slow (SQLi?)",c:"text-yellow-400 border-yellow-400/40"});
    if(r.status===500) flags.push({l:"500 Error",c:"text-red-400 border-red-400/40"});
    if(r.responseHeaders?.["access-control-allow-origin"]==="*") flags.push({l:"CORS *",c:"text-orange-400 border-orange-400/40"});
    if(!r.responseHeaders?.["x-frame-options"]) flags.push({l:"No XFO",c:"text-cyan-400 border-cyan-400/40"});
    return flags;
  };

  const filtered = reqs.filter(r=>filterM==="ALL"||r.method===filterM);

  return (
    <Layout>
      <div className="space-y-3 animate-in fade-in duration-500">
        <header className="border-b border-primary/20 pb-3 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-display font-bold flex items-center gap-2">
              <Radio className="w-5 h-5 text-primary"/> HTTP INTERCEPTOR
            </h1>
            <p className="text-[10px] font-mono text-muted-foreground mt-0.5">Intercept · Modify · Replay · Auto-Analyze</p>
          </div>
          <div className="flex gap-2">
            <button onClick={()=>{const b=new Blob([JSON.stringify(reqs,null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(b);a.download="intercepted.json";a.click();}}
              disabled={reqs.length===0} className="cyber-button !py-1.5 !px-3 text-[10px] flex items-center gap-1">
              <Download className="w-3 h-3"/> EXPORT
            </button>
            <button onClick={()=>{setReqs([]);setSel(null);}} className="cyber-button !py-1.5 !px-3 text-[10px] flex items-center gap-1 !border-red-400/30 !text-red-400">
              <Trash2 className="w-3 h-3"/> CLEAR
            </button>
          </div>
        </header>

        <div className="flex gap-2">
          <select value={newMethod} onChange={e=>setNewMethod(e.target.value)} className="bg-black/50 border border-primary/30 px-2 py-2 font-mono text-xs text-foreground focus:outline-none w-24">
            {METHODS.map(m=><option key={m}>{m}</option>)}
          </select>
          <input value={newUrl} onChange={e=>setNewUrl(e.target.value)} onKeyDown={e=>e.key==="Enter"&&add()}
            className="flex-1 bg-black/50 border border-primary/30 px-3 py-2 font-mono text-sm text-foreground focus:outline-none focus:border-primary"
            placeholder="https://target.com/api/endpoint"/>
          <button onClick={add} className="cyber-button !py-2 !px-4 text-xs flex items-center gap-1.5">
            <Plus className="w-3.5 h-3.5"/> ADD
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-5 gap-3">
          <div className="lg:col-span-2 cyber-box overflow-hidden flex flex-col" style={{maxHeight:"680px"}}>
            <div className="flex gap-1 p-2 border-b border-primary/10 flex-wrap bg-black/20">
              <Filter className="w-3 h-3 text-muted-foreground mt-1 shrink-0"/>
              {["ALL","GET","POST","PUT","DELETE"].map(m=>(
                <button key={m} onClick={()=>setFilterM(m)} className={cn("px-1.5 py-0.5 font-mono text-[9px] border transition-all",filterM===m?"border-primary text-primary bg-primary/10":"border-border/30 text-muted-foreground")}>{m}</button>
              ))}
              <span className="ml-auto font-mono text-[9px] text-muted-foreground">{filtered.length}</span>
            </div>
            <div className="flex-1 overflow-y-auto">
              {filtered.length===0?(
                <div className="p-8 text-center font-mono text-xs text-muted-foreground"><Radio className="w-8 h-8 mx-auto mb-2 opacity-20"/>Add a URL above</div>
              ):filtered.map(r=>(
                <div key={r.id} onClick={()=>pick(r)} className={cn("p-2.5 border-b border-border/20 cursor-pointer hover:bg-white/5 transition-colors",sel?.id===r.id&&"bg-primary/10 border-l-2 border-l-primary",r.flagged&&"bg-red-500/5")}>
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 min-w-0 flex-1">
                      <span className={cn("font-mono text-[9px] font-bold shrink-0 w-10",r.method==="GET"?"text-cyan-400":r.method==="POST"?"text-orange-400":"text-yellow-400")}>{r.method}</span>
                      <span className="font-mono text-[10px] text-foreground/80 truncate">{r.url}</span>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      {r.status&&<span className={cn("font-mono text-[9px] font-bold",sc(r.status))}>{r.status}</span>}
                      {r.tag&&<span className={cn("font-mono text-[8px] px-1 border",TAG_COLORS[r.tag]||"")}>{r.tag}</span>}
                    </div>
                  </div>
                  {r.responseTime&&<div className="font-mono text-[9px] text-muted-foreground mt-0.5">{r.responseTime}ms · {r.responseBody?.length||0}B</div>}
                </div>
              ))}
            </div>
          </div>

          <div className="lg:col-span-3 flex flex-col gap-3">
            {sel?(
              <>
                <div className="cyber-box p-3 space-y-2">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs text-primary font-bold">REQUEST EDITOR</span>
                    <div className="flex gap-1 flex-wrap">
                      {TAGS.map(t=>(
                        <button key={t} onClick={()=>tag(sel.id,t)} className={cn("font-mono text-[8px] px-1.5 py-0.5 border transition-all",sel.tag===t?TAG_COLORS[t]:"border-border/30 text-muted-foreground hover:border-primary/30")}>{t}</button>
                      ))}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <select value={method} onChange={e=>setMethod(e.target.value)} className="bg-black/50 border border-primary/30 px-2 py-1.5 font-mono text-xs text-foreground focus:outline-none w-20">
                      {METHODS.map(m=><option key={m}>{m}</option>)}
                    </select>
                    <input value={url} onChange={e=>setUrl(e.target.value)} className="flex-1 bg-black/50 border border-primary/30 px-2 py-1.5 font-mono text-xs text-foreground focus:outline-none focus:border-primary"/>
                  </div>
                  <div>
                    <label className="font-mono text-[10px] text-muted-foreground">HEADERS (JSON)</label>
                    <textarea value={headers} onChange={e=>setHeaders(e.target.value)} rows={4} className="w-full bg-black/50 border border-primary/30 p-2 font-mono text-[10px] text-foreground focus:outline-none mt-1 resize-none"/>
                  </div>
                  <div>
                    <label className="font-mono text-[10px] text-muted-foreground">BODY</label>
                    <textarea value={body} onChange={e=>setBody(e.target.value)} rows={3} className="w-full bg-black/50 border border-primary/30 p-2 font-mono text-[10px] text-foreground focus:outline-none mt-1 resize-none" placeholder="Request body"/>
                  </div>
                  <div className="flex gap-2 pt-1">
                    <button onClick={send} disabled={sending} className="cyber-button !py-1.5 !px-4 text-xs flex items-center gap-1.5 flex-1 justify-center">
                      {sending?<><RefreshCw className="w-3.5 h-3.5 animate-spin"/>SENDING...</>:<><Send className="w-3.5 h-3.5"/>SEND</>}
                    </button>
                    <button onClick={curl} className="cyber-button !py-1.5 !px-3 text-[10px] flex items-center gap-1 !border-muted-foreground/30 !text-muted-foreground"><Copy className="w-3 h-3"/>cURL</button>
                    <button onClick={()=>{setReqs(p=>p.filter(r=>r.id!==sel.id));setSel(null);}} className="cyber-button !py-1.5 !px-3 text-[10px] !border-red-400/30 !text-red-400"><Trash2 className="w-3 h-3"/></button>
                  </div>
                </div>

                {sel.status&&(
                  <div className="cyber-box overflow-hidden">
                    <button onClick={()=>setShowResp(!showResp)} className="w-full flex items-center justify-between p-3 hover:bg-white/5 transition-colors">
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-xs text-primary font-bold">RESPONSE</span>
                        <span className={cn("font-mono text-sm font-bold",sc(sel.status))}>{sel.status}</span>
                        {sel.responseTime&&<span className="font-mono text-[10px] text-muted-foreground">{sel.responseTime}ms</span>}
                        {sel.responseBody&&<span className="font-mono text-[10px] text-muted-foreground">{sel.responseBody.length}B</span>}
                      </div>
                      {showResp?<ChevronUp className="w-4 h-4 text-muted-foreground"/>:<ChevronDown className="w-4 h-4 text-muted-foreground"/>}
                    </button>
                    {showResp&&(
                      <div className="border-t border-border/20">
                        {sel.responseHeaders&&Object.keys(sel.responseHeaders).length>0&&(
                          <div className="p-3 border-b border-border/20 max-h-32 overflow-y-auto">
                            <div className="font-mono text-[10px] text-muted-foreground mb-1">HEADERS</div>
                            {Object.entries(sel.responseHeaders).map(([k,v])=>(
                              <div key={k} className="flex gap-2 font-mono text-[10px]"><span className="text-cyan-400 shrink-0">{k}:</span><span className="text-foreground/70 break-all">{v}</span></div>
                            ))}
                          </div>
                        )}
                        <div className="p-3">
                          <div className="font-mono text-[10px] text-muted-foreground mb-1">BODY</div>
                          <pre className="bg-black/50 p-3 font-mono text-[10px] text-green-300 overflow-auto max-h-64 whitespace-pre-wrap break-all border border-primary/10">{sel.responseBody||"(empty)"}</pre>
                        </div>
                        {(()=>{const f=analyze(sel);return f.length>0?(
                          <div className="p-3 border-t border-border/20">
                            <div className="font-mono text-[10px] text-primary mb-2 flex items-center gap-1"><AlertTriangle className="w-3 h-3"/>AUTO ANALYSIS</div>
                            <div className="flex flex-wrap gap-1">{f.map(({l,c})=><span key={l} className={cn("font-mono text-[9px] px-1.5 py-0.5 border",c)}>⚠ {l}</span>)}</div>
                          </div>
                        ):null;})()}
                      </div>
                    )}
                  </div>
                )}
              </>
            ):(
              <div className="cyber-box flex items-center justify-center" style={{minHeight:"400px"}}>
                <div className="text-center font-mono text-muted-foreground">
                  <Radio className="w-12 h-12 mx-auto mb-3 opacity-20"/>
                  <p className="text-sm">Add a URL → Click ADD → Click SEND</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}
