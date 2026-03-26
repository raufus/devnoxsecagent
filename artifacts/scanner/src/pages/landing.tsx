import { Link } from "wouter";
import { Shield, Zap, Brain, Globe, Target, ChevronRight, Lock, Activity, Network, Bug, Eye, Server } from "lucide-react";

const FEATURES = [
  { icon: Brain, title: "AI Orchestrator", desc: "GPT-4o-mini powered decision engine that plans attack strategy, selects payloads, and correlates vulnerabilities autonomously.", color: "text-purple-400 border-purple-400/30 bg-purple-400/5" },
  { icon: Globe, title: "OSINT Recon Engine", desc: "Full intelligence gathering — DNS, WHOIS, subdomain enumeration, email harvesting, cloud provider detection, social footprint.", color: "text-cyan-400 border-cyan-400/30 bg-cyan-400/5" },
  { icon: Bug, title: "Multi-Vector Scanner", desc: "XSS, SQLi, SSRF, CSRF, IDOR, XXE, Command Injection, Path Traversal, Auth Bypass, GraphQL testing — all automated.", color: "text-red-400 border-red-400/30 bg-red-400/5" },
  { icon: Zap, title: "Exploit Engine", desc: "AI-generated exploit payloads, attack chain construction, privilege escalation paths, and proof-of-concept generation.", color: "text-orange-400 border-orange-400/30 bg-orange-400/5" },
  { icon: Network, title: "Attack Graph (Maltego-style)", desc: "Visual attack surface mapping — Domain → IP → Server → Vulnerability → Exploit path visualization with React Flow.", color: "text-yellow-400 border-yellow-400/30 bg-yellow-400/5" },
  { icon: Activity, title: "Real-time Dashboard", desc: "Live scan progress via SSE, instant vulnerability alerts, phase tracking, and comprehensive PDF/JSON report export.", color: "text-primary border-primary/30 bg-primary/5" },
  { icon: Target, title: "Intruder Tool", desc: "Built-in Burp Suite Intruder alternative — automated payload injection with SQL, XSS, fuzzing, and custom wordlists.", color: "text-pink-400 border-pink-400/30 bg-pink-400/5" },
  { icon: Server, title: "Shodan Integration", desc: "Query Shodan for open ports, running services, known CVEs, and infrastructure intelligence on target hosts.", color: "text-blue-400 border-blue-400/30 bg-blue-400/5" },
];

const STATS = [
  { value: "20+", label: "Vulnerability Types" },
  { value: "100+", label: "Attack Payloads" },
  { value: "AI", label: "Powered Engine" },
  { value: "Real-time", label: "Live Monitoring" },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-background text-foreground overflow-x-hidden">
      {/* Background */}
      <div className="fixed inset-0 bg-[radial-gradient(ellipse_at_top,rgba(0,255,128,0.08)_0%,transparent_60%)] pointer-events-none" />
      <div className="fixed inset-0 bg-[linear-gradient(to_bottom,transparent_0%,rgba(0,0,0,0.5)_100%)] pointer-events-none" />

      {/* Navbar */}
      <nav className="fixed top-0 left-0 right-0 z-50 border-b border-primary/20 bg-background/90 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <img src="/images/logo.png" alt="DevNox" className="w-9 h-9 object-contain" />
            <span className="font-display font-bold text-primary tracking-widest text-sm">DEVNOX</span>
            <span className="font-mono text-[9px] text-primary/50 hidden sm:block">SEC_AGENT v2.0</span>
          </div>
          <div className="flex items-center gap-2">
            <Link href="/login" className="font-mono text-xs text-muted-foreground hover:text-primary transition-colors px-3 py-1.5">
              LOGIN
            </Link>
            <Link href="/register" className="cyber-button !py-1.5 !px-4 text-xs">
              GET STARTED
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative pt-32 pb-20 px-4 sm:px-6 text-center">
        <div className="max-w-4xl mx-auto">
          <div className="inline-flex items-center gap-2 px-3 py-1 border border-primary/30 bg-primary/5 font-mono text-[10px] text-primary mb-6">
            <img src="/images/logo.png" alt="" className="w-4 h-4 object-contain" />
            AUTONOMOUS AI-POWERED PENETRATION TESTING
          </div>

          <h1 className="text-4xl sm:text-6xl lg:text-7xl font-display font-bold leading-tight mb-6">
            <span className="text-primary">DEVNOX</span>
            <br />
            <span className="text-foreground/90">SEC AGENT</span>
          </h1>

          <p className="text-base sm:text-lg text-muted-foreground font-mono max-w-2xl mx-auto mb-8 leading-relaxed">
            Fully autonomous web application vulnerability scanner powered by AI. 
            Recon → Scan → Exploit → Report — with minimal human interaction.
          </p>

          <div className="flex flex-col sm:flex-row gap-3 justify-center">
            <Link href="/register" className="cyber-button text-sm flex items-center justify-center gap-2 px-8 py-3">
              <Shield className="w-4 h-4" /> START FREE SCAN
              <ChevronRight className="w-4 h-4" />
            </Link>
            <Link href="/login" className="font-mono text-sm border border-border/50 px-8 py-3 text-muted-foreground hover:border-primary/50 hover:text-primary transition-all flex items-center justify-center gap-2">
              <Lock className="w-4 h-4" /> SIGN IN
            </Link>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-16 max-w-2xl mx-auto">
            {STATS.map(({ value, label }) => (
              <div key={label} className="cyber-box p-4 text-center">
                <div className="text-2xl font-display font-bold text-primary">{value}</div>
                <div className="font-mono text-[10px] text-muted-foreground mt-1">{label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="py-20 px-4 sm:px-6">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-2xl sm:text-3xl font-display font-bold text-primary mb-3">CORE_MODULES</h2>
            <p className="font-mono text-sm text-muted-foreground">Enterprise-grade security testing — fully automated</p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {FEATURES.map(({ icon: Icon, title, desc, color }) => (
              <div key={title} className={`cyber-box p-5 border ${color} hover:scale-[1.02] transition-transform`}>
                <Icon className={`w-6 h-6 mb-3 ${color.split(" ")[0]}`} />
                <h3 className="font-mono text-xs font-bold text-foreground mb-2">{title}</h3>
                <p className="font-mono text-[10px] text-muted-foreground leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How it works */}
      <section className="py-20 px-4 sm:px-6 border-t border-primary/10">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-2xl sm:text-3xl font-display font-bold text-primary mb-3">HOW_IT_WORKS</h2>
            <p className="font-mono text-sm text-muted-foreground">6-phase autonomous attack pipeline</p>
          </div>
          <div className="space-y-3">
            {[
              { step: "01", phase: "INPUT", desc: "Enter target URL and select scan modules", color: "text-cyan-400" },
              { step: "02", phase: "RECON", desc: "OSINT gathering — DNS, subdomains, emails, tech stack, cloud providers", color: "text-blue-400" },
              { step: "03", phase: "AI ANALYSIS", desc: "AI Orchestrator analyzes recon data and plans attack strategy", color: "text-purple-400" },
              { step: "04", phase: "SCANNING", desc: "Multi-vector vulnerability scanning — XSS, SQLi, SSRF, IDOR, Auth Bypass, GraphQL...", color: "text-yellow-400" },
              { step: "05", phase: "EXPLOITATION", desc: "AI generates exploit payloads, attack chains, and privilege escalation paths", color: "text-orange-400" },
              { step: "06", phase: "REPORT", desc: "PDF/JSON report with CVSS scores, PoC payloads, and remediation recommendations", color: "text-primary" },
            ].map(({ step, phase, desc, color }) => (
              <div key={step} className="flex items-start gap-4 p-4 border border-border/30 hover:border-primary/30 transition-colors bg-black/20">
                <span className={`font-display text-2xl font-bold ${color} shrink-0 w-10`}>{step}</span>
                <div>
                  <div className={`font-mono text-xs font-bold ${color} mb-1`}>{phase}</div>
                  <div className="font-mono text-[11px] text-muted-foreground">{desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20 px-4 sm:px-6 border-t border-primary/10">
        <div className="max-w-2xl mx-auto text-center">
          <img src="/images/logo.png" alt="DevNox" className="w-20 h-20 object-contain mx-auto mb-4" />
          <h2 className="text-2xl sm:text-3xl font-display font-bold mb-4">
            Ready to <span className="text-primary">Hack Ethically?</span>
          </h2>
          <p className="font-mono text-sm text-muted-foreground mb-8">
            Create your free account and start scanning authorized targets today.
            Only scan systems you have explicit permission to test.
          </p>
          <Link href="/register" className="cyber-button text-sm px-10 py-3 flex items-center justify-center gap-2 max-w-xs mx-auto">
            <Shield className="w-4 h-4" /> CREATE FREE ACCOUNT
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-primary/10 py-8 px-4 sm:px-6">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <img src="/images/logo.png" alt="DevNox" className="w-7 h-7 object-contain" />
            <span className="font-mono text-xs text-muted-foreground">DEVNOX SEC AGENT v2.0 — Authorized Use Only</span>
          </div>
          <div className="flex gap-4 font-mono text-[10px] text-muted-foreground">
            <Link href="/login" className="hover:text-primary transition-colors">Login</Link>
            <Link href="/register" className="hover:text-primary transition-colors">Register</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
