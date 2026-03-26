import { useState } from "react";
import { useLocation } from "wouter";
import { useCreateScan } from "@workspace/api-client-react";
import { Layout } from "@/components/layout";
import {
  Shield, ShieldAlert, AlertCircle, Zap, Brain, Globe,
  Network, Bug, Lock, Server, Activity, ChevronRight
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

const ALL_MODULES = [
  "recon", "headers", "ssl", "cors", "xss", "sqli", "cmdi",
  "lfi", "xxe", "ssrf", "csrf", "idor", "redirect", "auth",
  "graphql", "info",
];

const PIPELINE = [
  { icon: Globe, label: "OSINT Recon", desc: "DNS · WHOIS · Subdomains · Emails · Ports · Cloud", color: "text-cyan-400" },
  { icon: Brain, label: "AI Strategy", desc: "GPT-4o-mini analyzes attack surface", color: "text-purple-400" },
  { icon: Bug, label: "Vulnerability Scan", desc: "XSS · SQLi · SSRF · IDOR · Auth Bypass · GraphQL · 16 modules", color: "text-red-400" },
  { icon: Zap, label: "Exploit Engine", desc: "Real payload testing + Exploit-DB lookup", color: "text-orange-400" },
  { icon: Network, label: "Attack Graph", desc: "Maltego-style visual attack map", color: "text-yellow-400" },
  { icon: Activity, label: "AI Report", desc: "CVSS scoring · PDF export · Remediation", color: "text-primary" },
];

export default function NewScan() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const createScan = useCreateScan();
  const [url, setUrl] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [urlError, setUrlError] = useState("");

  const handleLaunch = async () => {
    setUrlError("");
    if (!url) { setUrlError("Target URL is required"); return; }
    try { new URL(url); } catch { setUrlError("Invalid URL format (e.g. https://example.com)"); return; }
    if (!consent) { toast({ title: "Authorization Required", description: "You must confirm legal authorization first.", variant: "destructive" }); return; }

    setLoading(true);
    try {
      const result = await createScan.mutateAsync({
        data: {
          targetUrl: url,
          scanType: "full",
          modules: ALL_MODULES as any,
          consentAcknowledged: true,
        },
      });
      toast({ title: "AUTONOMOUS SCAN LAUNCHED", description: `Target: ${url}` });
      setLocation(`/scans/${result.id}/live`);
    } catch (err: any) {
      toast({ title: "LAUNCH FAILED", description: err.message || "Failed to start scan", variant: "destructive" });
      setLoading(false);
    }
  };

  return (
    <Layout>
      {/* Mobile launch button */}
      <div className="lg:hidden fixed bottom-14 left-0 right-0 z-30 px-4 pb-2">
        <button onClick={handleLaunch} disabled={loading || !consent}
          className={cn("w-full py-3 font-mono font-bold text-sm flex items-center justify-center gap-2 border transition-all",
            consent ? "bg-primary text-black border-primary shadow-[0_0_20px_rgba(0,255,128,0.5)]" : "bg-primary/10 text-primary border-primary/40")}>
          {loading ? <><div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" /> LAUNCHING...</>
            : <><Zap className="w-4 h-4" /> LAUNCH AUTONOMOUS SCAN</>}
        </button>
      </div>

      <div className="max-w-3xl mx-auto space-y-6 animate-in slide-in-from-bottom-4 duration-500 pb-28 lg:pb-6">

        {/* Header */}
        <header className="text-center pt-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 border border-primary/30 bg-primary/5 font-mono text-[10px] text-primary mb-4">
            <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
            FULLY AUTONOMOUS — NO MANUAL CONFIGURATION NEEDED
          </div>
          <h1 className="text-3xl sm:text-4xl font-display font-bold flex items-center justify-center gap-3">
            <Shield className="w-8 h-8 text-primary" />
            AUTONOMOUS SCAN
          </h1>
          <p className="text-muted-foreground font-mono mt-2 text-xs sm:text-sm">
            Enter target URL → AI handles everything automatically
          </p>
        </header>

        {/* URL Input — the only thing user needs to fill */}
        <div className="cyber-box p-6 border-primary/40">
          <label className="font-mono text-xs text-primary flex items-center gap-2 mb-3">
            <span className="w-2 h-2 bg-primary animate-pulse" /> TARGET_URL
          </label>
          <div className="relative">
            <ShieldAlert className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-primary/50" />
            <input
              type="url"
              value={url}
              onChange={e => { setUrl(e.target.value); setUrlError(""); }}
              onKeyDown={e => e.key === "Enter" && handleLaunch()}
              className="w-full bg-black/50 border border-primary/30 p-4 pl-12 text-lg font-mono text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all"
              placeholder="https://target.example.com"
              autoFocus
            />
          </div>
          {urlError && (
            <p className="text-red-500 font-mono text-xs flex items-center gap-1 mt-2">
              <AlertCircle className="w-3.5 h-3.5" /> {urlError}
            </p>
          )}
          <p className="font-mono text-[10px] text-muted-foreground mt-2">
            All 16 attack modules run automatically · Full scan depth · AI-powered analysis
          </p>
        </div>

        {/* Autonomous Pipeline — what will happen */}
        <div className="cyber-box p-5">
          <h3 className="font-mono text-xs text-primary mb-4 flex items-center gap-2">
            <span className="w-2 h-2 bg-primary" /> AUTONOMOUS PIPELINE — RUNS AUTOMATICALLY
          </h3>
          <div className="space-y-2">
            {PIPELINE.map(({ icon: Icon, label, desc, color }, i) => (
              <div key={label} className="flex items-center gap-3 p-2.5 border border-border/20 hover:border-primary/20 transition-colors">
                <div className={`w-6 h-6 rounded border border-current/30 flex items-center justify-center shrink-0 ${color} bg-current/5`}>
                  <span className="font-display text-[10px] font-bold">{i + 1}</span>
                </div>
                <Icon className={`w-4 h-4 shrink-0 ${color}`} />
                <div className="flex-1 min-w-0">
                  <span className={`font-mono text-xs font-bold ${color}`}>{label}</span>
                  <span className="font-mono text-[10px] text-muted-foreground ml-2">{desc}</span>
                </div>
                <span className="font-mono text-[9px] text-primary/40 shrink-0">AUTO</span>
              </div>
            ))}
          </div>
        </div>

        {/* Legal Consent */}
        <div className={cn("cyber-box p-5 border transition-all", consent ? "border-primary/40 bg-primary/5" : "border-red-500/30 bg-red-500/5")}>
          <label className="flex items-start gap-3 cursor-pointer">
            <div className={cn("w-5 h-5 mt-0.5 border-2 flex items-center justify-center shrink-0 transition-all",
              consent ? "border-primary bg-primary" : "border-red-500/50")}
              onClick={() => setConsent(!consent)}>
              {consent && <span className="text-black font-bold text-xs">✓</span>}
            </div>
            <div onClick={() => setConsent(!consent)}>
              <h4 className={cn("font-display font-bold tracking-wide text-sm", consent ? "text-primary" : "text-red-500")}>
                {consent ? "✓ AUTHORIZED — READY TO LAUNCH" : "LEGAL AUTHORIZATION REQUIRED"}
              </h4>
              <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                I confirm I have explicit written authorization to perform penetration testing against this target.
                Unauthorized scanning is illegal. I take full legal responsibility.
              </p>
            </div>
          </label>
        </div>

        {/* Launch Button */}
        <button onClick={handleLaunch} disabled={loading || !consent || !url}
          className={cn(
            "hidden lg:flex w-full py-4 font-mono font-bold text-lg items-center justify-center gap-3 border transition-all duration-300",
            consent && url
              ? "bg-primary text-black border-primary shadow-[0_0_30px_rgba(0,255,128,0.4)] hover:shadow-[0_0_50px_rgba(0,255,128,0.6)]"
              : "bg-primary/10 text-primary/50 border-primary/20 cursor-not-allowed"
          )}>
          {loading ? (
            <><div className="w-5 h-5 border-2 border-current border-t-transparent rounded-full animate-spin" /> INITIALIZING AUTONOMOUS SCAN...</>
          ) : (
            <><Zap className="w-5 h-5" /> LAUNCH AUTONOMOUS SCAN <ChevronRight className="w-5 h-5" /></>
          )}
        </button>

        {/* Info */}
        <div className="grid grid-cols-3 gap-3 text-center">
          {[
            { label: "16 Modules", sub: "All attack vectors" },
            { label: "AI Powered", sub: "GPT-4o-mini" },
            { label: "Real Testing", sub: "No simulation" },
          ].map(({ label, sub }) => (
            <div key={label} className="p-3 border border-border/20">
              <div className="font-display font-bold text-primary text-sm">{label}</div>
              <div className="font-mono text-[10px] text-muted-foreground mt-0.5">{sub}</div>
            </div>
          ))}
        </div>
      </div>
    </Layout>
  );
}
