import { useState } from "react";
import { useLocation, Link } from "wouter";
import { Shield, Lock, User, Eye, EyeOff, AlertCircle } from "lucide-react";
import { useAuth } from "@/lib/auth";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const { login, isAuthenticated, isLoading } = useAuth();
  const [, setLocation] = useLocation();

  // Already logged in — go to dashboard
  if (!isLoading && isAuthenticated) {
    setLocation("/dashboard");
    return null;
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(username, password);
      setLocation("/dashboard");
    } catch (err: any) {
      setError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="fixed inset-0 bg-[radial-gradient(ellipse_at_center,rgba(0,255,128,0.05)_0%,transparent_70%)]" />

      <div className="w-full max-w-md relative z-10">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-20 h-20 mb-4">
            <img src="/images/logo.png" alt="DevNox" className="w-full h-full object-contain" />
          </div>
          <h1 className="text-3xl font-display font-bold text-primary tracking-widest">DEVNOX</h1>
          <p className="text-xs font-mono text-muted-foreground mt-1 tracking-[0.2em]">SEC_AGENT v2.0 — AUTONOMOUS PENTEST</p>
        </div>

        {/* Login Box */}
        <div className="cyber-box p-6 sm:p-8 border-primary/30">
          <div className="flex items-center gap-2 mb-6">
            <Lock className="w-4 h-4 text-primary" />
            <h2 className="font-mono text-sm text-primary tracking-wider">AUTHENTICATION_REQUIRED</h2>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="font-mono text-[10px] text-muted-foreground uppercase tracking-wider block mb-1.5">Username</label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-primary/40" />
                <input
                  type="text"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  className="w-full bg-black/50 border border-primary/30 pl-10 pr-4 py-3 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all"
                  placeholder="admin"
                  autoComplete="username"
                  required
                />
              </div>
            </div>

            <div>
              <label className="font-mono text-[10px] text-muted-foreground uppercase tracking-wider block mb-1.5">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-primary/40" />
                <input
                  type={showPass ? "text" : "password"}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  className="w-full bg-black/50 border border-primary/30 pl-10 pr-10 py-3 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all"
                  placeholder="••••••••"
                  autoComplete="current-password"
                  required
                />
                <button type="button" onClick={() => setShowPass(!showPass)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-primary transition-colors">
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2 p-3 border border-red-500/30 bg-red-500/10 text-red-400 font-mono text-xs">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {error}
              </div>
            )}

            <button type="submit" disabled={loading}
              className="w-full cyber-button py-3 flex items-center justify-center gap-2 mt-2">
              {loading
                ? <><div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" /> AUTHENTICATING...</>
                : <><Lock className="w-4 h-4" /> ACCESS_SYSTEM</>}
            </button>
          </form>

          <div className="mt-6 pt-4 border-t border-primary/10">
            <p className="font-mono text-[11px] text-muted-foreground text-center">
              No account?{" "}
              <Link href="/register" className="text-primary hover:underline">Create one</Link>
              <span className="mx-2 text-muted-foreground/30">|</span>
              <Link href="/" className="text-muted-foreground hover:text-primary transition-colors">← Home</Link>
            </p>
            <p className="font-mono text-[10px] text-muted-foreground/50 text-center mt-2">
              Default admin: admin / admin123
            </p>
          </div>
        </div>

        <p className="text-center font-mono text-[10px] text-muted-foreground/30 mt-4">
          DEVNOX SEC AGENT — Authorized Use Only
        </p>
      </div>
    </div>
  );
}
