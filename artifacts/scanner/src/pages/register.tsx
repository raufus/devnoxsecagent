import { useState } from "react";
import { Link, useLocation } from "wouter";
import { Shield, Lock, Mail, User, Eye, EyeOff, AlertCircle, CheckCircle } from "lucide-react";

export default function RegisterPage() {
  const [form, setForm] = useState({ firstName: "", lastName: "", email: "", password: "", confirm: "" });
  const [showPass, setShowPass] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);
  const [, setLocation] = useLocation();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (form.password !== form.confirm) {
      setError("Passwords do not match");
      return;
    }
    if (form.password.length < 6) {
      setError("Password must be at least 6 characters");
      return;
    }
    setLoading(true);
    try {
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: form.email, password: form.password, firstName: form.firstName, lastName: form.lastName }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || "Registration failed");
      setSuccess(true);
      setTimeout(() => setLocation("/login"), 2000);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm(p => ({ ...p, [k]: e.target.value }));

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="fixed inset-0 bg-[radial-gradient(ellipse_at_center,rgba(0,255,128,0.05)_0%,transparent_70%)]" />

      <div className="w-full max-w-md relative z-10">
        {/* Logo */}
        <div className="text-center mb-8">
          <Link href="/" className="inline-flex flex-col items-center">
            <div className="inline-flex items-center justify-center w-16 h-16 mb-3">
              <img src="/images/logo.png" alt="DevNox" className="w-full h-full object-contain" />
            </div>
            <h1 className="text-2xl font-display font-bold text-primary tracking-widest">DEVNOX</h1>
            <p className="text-[10px] font-mono text-muted-foreground mt-0.5 tracking-[0.2em]">SEC_AGENT v2.0</p>
          </Link>
        </div>

        <div className="cyber-box p-6 sm:p-8 border-primary/30">
          <div className="flex items-center gap-2 mb-6">
            <User className="w-4 h-4 text-primary" />
            <h2 className="font-mono text-sm text-primary tracking-wider">CREATE_ACCOUNT</h2>
          </div>

          {success ? (
            <div className="flex flex-col items-center gap-3 py-8">
              <CheckCircle className="w-12 h-12 text-primary" />
              <p className="font-mono text-sm text-primary">ACCOUNT_CREATED</p>
              <p className="font-mono text-xs text-muted-foreground">Redirecting to login...</p>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="font-mono text-[10px] text-muted-foreground uppercase tracking-wider block mb-1.5">First Name</label>
                  <input value={form.firstName} onChange={set("firstName")}
                    className="w-full bg-black/50 border border-primary/30 px-3 py-2.5 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary transition-all"
                    placeholder="John" />
                </div>
                <div>
                  <label className="font-mono text-[10px] text-muted-foreground uppercase tracking-wider block mb-1.5">Last Name</label>
                  <input value={form.lastName} onChange={set("lastName")}
                    className="w-full bg-black/50 border border-primary/30 px-3 py-2.5 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary transition-all"
                    placeholder="Doe" />
                </div>
              </div>

              <div>
                <label className="font-mono text-[10px] text-muted-foreground uppercase tracking-wider block mb-1.5">Email Address</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-primary/40" />
                  <input type="email" value={form.email} onChange={set("email")} required
                    className="w-full bg-black/50 border border-primary/30 pl-10 pr-4 py-2.5 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary transition-all"
                    placeholder="you@example.com" />
                </div>
              </div>

              <div>
                <label className="font-mono text-[10px] text-muted-foreground uppercase tracking-wider block mb-1.5">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-primary/40" />
                  <input type={showPass ? "text" : "password"} value={form.password} onChange={set("password")} required
                    className="w-full bg-black/50 border border-primary/30 pl-10 pr-10 py-2.5 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary transition-all"
                    placeholder="Min. 6 characters" />
                  <button type="button" onClick={() => setShowPass(!showPass)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-primary transition-colors">
                    {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div>
                <label className="font-mono text-[10px] text-muted-foreground uppercase tracking-wider block mb-1.5">Confirm Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-primary/40" />
                  <input type="password" value={form.confirm} onChange={set("confirm")} required
                    className="w-full bg-black/50 border border-primary/30 pl-10 pr-4 py-2.5 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary transition-all"
                    placeholder="Repeat password" />
                </div>
              </div>

              {error && (
                <div className="flex items-center gap-2 p-3 border border-red-500/30 bg-red-500/10 text-red-400 font-mono text-xs">
                  <AlertCircle className="w-4 h-4 shrink-0" /> {error}
                </div>
              )}

              <div className="p-3 border border-yellow-500/20 bg-yellow-500/5 font-mono text-[10px] text-yellow-400/80">
                ⚠ Only scan systems you have explicit written authorization to test. Unauthorized scanning is illegal.
              </div>

              <button type="submit" disabled={loading}
                className="w-full cyber-button py-3 flex items-center justify-center gap-2">
                {loading
                  ? <><div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" /> CREATING ACCOUNT...</>
                  : <><User className="w-4 h-4" /> CREATE_ACCOUNT</>}
              </button>
            </form>
          )}

          <div className="mt-5 pt-4 border-t border-primary/10 text-center">
            <p className="font-mono text-[11px] text-muted-foreground">
              Already have an account?{" "}
              <Link href="/login" className="text-primary hover:underline">Sign in</Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
