import { useEffect, useState } from "react";
import { Link } from "wouter";
import { useAuth } from "@/lib/auth";
import { Layout } from "@/components/layout";
import { Users, ShieldAlert, Bug, Brain, Activity, Settings, AlertTriangle, Zap, RefreshCw } from "lucide-react";

interface AdminStats {
  totalUsers: number;
  totalScans: number;
  totalFindings: number;
  totalAiDecisions: number;
  scansByStatus: { status: string; count: number }[];
  findingsBySeverity: { severity: string; count: number }[];
  recentScans: any[];
  activeUsers: any[];
}

export default function AdminDashboard() {
  const { user, isLoading, isAuthenticated } = useAuth();
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isAuthenticated) return;
    fetch("/api/admin/stats", { credentials: "include" })
      .then(r => r.json())
      .then(data => { setStats(data); setLoading(false); })
      .catch(() => { setError("Failed to load stats"); setLoading(false); });
  }, [isAuthenticated]);

  if (isLoading || loading) return (
    <Layout>
      <div className="flex items-center justify-center h-64 font-mono text-sm text-muted-foreground">
        <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin mr-3" />
        LOADING ADMIN PANEL...
      </div>
    </Layout>
  );

  const userRole = (user as any)?.role;
  if (!isAuthenticated || userRole !== "admin") return (
    <Layout>
      <div className="flex flex-col items-center justify-center h-64 gap-4">
        <ShieldAlert className="w-16 h-16 text-red-500 opacity-60" />
        <p className="font-mono text-sm text-muted-foreground">ACCESS_DENIED — Admin privileges required.</p>
        <Link href="/" className="cyber-button text-xs">← BACK TO OVERVIEW</Link>
      </div>
    </Layout>
  );

  const quickLinks = [
    { href: "/admin/users", label: "USER_MANAGEMENT", icon: Users, color: "text-cyan-400 border-cyan-400/30", count: stats?.totalUsers },
    { href: "/admin/scans", label: "SCAN_MANAGEMENT", icon: ShieldAlert, color: "text-orange-400 border-orange-400/30", count: stats?.totalScans },
    { href: "/admin/findings", label: "FINDINGS_DATABASE", icon: Bug, color: "text-red-400 border-red-400/30", count: stats?.totalFindings },
    { href: "/admin/settings", label: "SYSTEM_SETTINGS", icon: Settings, color: "text-primary border-primary/30", count: null },
  ];

  return (
    <Layout>
      <div className="space-y-6 animate-in fade-in duration-500">
        <header>
          <div className="font-mono text-[10px] text-primary/50 tracking-widest mb-1">DEVNOX ADMIN v2.0</div>
          <h1 className="text-2xl sm:text-3xl">ADMIN_PANEL</h1>
          <p className="text-muted-foreground font-mono mt-1 text-xs">// System control center — manage users, scans, and platform settings</p>
        </header>

        {/* System Stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {[
            { label: "TOTAL_USERS", value: stats?.totalUsers ?? 0, icon: Users, color: "text-cyan-400", border: "border-cyan-400/20" },
            { label: "TOTAL_SCANS", value: stats?.totalScans ?? 0, icon: ShieldAlert, color: "text-orange-400", border: "border-orange-400/20" },
            { label: "TOTAL_FINDINGS", value: stats?.totalFindings ?? 0, icon: Bug, color: "text-red-400", border: "border-red-400/20" },
            { label: "AI_DECISIONS", value: stats?.totalAiDecisions ?? 0, icon: Brain, color: "text-purple-400", border: "border-purple-400/20" },
          ].map(({ label, value, icon: Icon, color, border }) => (
            <div key={label} className={`cyber-box p-4 flex flex-col gap-2 ${border}`}>
              <div className={`flex items-center justify-between ${color}`}>
                <span className="font-mono text-[10px]">{label}</span>
                <Icon className="w-4 h-4" />
              </div>
              <span className={`text-3xl font-display font-bold ${color}`}>{value}</span>
            </div>
          ))}
        </div>

        {/* Quick Nav Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {quickLinks.map(({ href, label, icon: Icon, color, count }) => (
            <Link key={href} href={href}>
              <div className={`cyber-box p-4 flex flex-col gap-3 cursor-pointer hover:bg-white/5 transition-all group ${color}`}>
                <div className="flex items-center justify-between">
                  <Icon className="w-5 h-5 group-hover:scale-110 transition-transform" />
                  {count !== null && count !== undefined && (
                    <span className="font-mono text-[10px] opacity-60">{count} records</span>
                  )}
                </div>
                <div className="font-mono text-xs font-bold tracking-wider">{label}</div>
                <div className="h-0.5 bg-current opacity-20 group-hover:opacity-60 transition-opacity" />
              </div>
            </Link>
          ))}
        </div>

        {/* Quick Actions */}
        <div className="cyber-box p-4">
          <h3 className="font-mono text-xs text-primary mb-3 flex items-center gap-2">
            <span className="w-2 h-2 bg-primary" /> QUICK_ACTIONS
          </h3>
          <div className="flex flex-wrap gap-2">
            <Link href="/scans/new" className="cyber-button !py-1.5 !px-3 text-[10px] flex items-center gap-1.5">
              <ShieldAlert className="w-3 h-3" /> NEW_SCAN
            </Link>
            <Link href="/admin/users" className="cyber-button !py-1.5 !px-3 text-[10px] flex items-center gap-1.5 !border-cyan-400/40 !text-cyan-400">
              <Users className="w-3 h-3" /> MANAGE_USERS
            </Link>
            <Link href="/admin/scans" className="cyber-button !py-1.5 !px-3 text-[10px] flex items-center gap-1.5 !border-orange-400/40 !text-orange-400">
              <Activity className="w-3 h-3" /> VIEW_ALL_SCANS
            </Link>
            <Link href="/admin/settings" className="cyber-button !py-1.5 !px-3 text-[10px] flex items-center gap-1.5 !border-primary/40 !text-primary">
              <Settings className="w-3 h-3" /> SYSTEM_SETTINGS
            </Link>
            <Link href="/tools/intruder" className="cyber-button !py-1.5 !px-3 text-[10px] flex items-center gap-1.5 !border-red-400/40 !text-red-400">
              <Zap className="w-3 h-3" /> INTRUDER_TOOL
            </Link>
            <button onClick={() => { setLoading(true); fetch("/api/admin/stats", { credentials: "include" }).then(r => r.json()).then(d => { setStats(d); setLoading(false); }); }}
              className="cyber-button !py-1.5 !px-3 text-[10px] flex items-center gap-1.5 !border-muted-foreground/30 !text-muted-foreground">
              <RefreshCw className="w-3 h-3" /> REFRESH_STATS
            </button>
          </div>
        </div>
        {/* Stats Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Findings by Severity */}
          <div className="cyber-box p-4 sm:p-5">
            <h3 className="font-mono text-xs text-primary mb-4 flex items-center gap-2">
              <span className="w-2 h-2 bg-primary" /> FINDINGS_BY_SEVERITY
            </h3>
            <div className="space-y-2">
              {(stats?.findingsBySeverity ?? []).map(({ severity, count }) => {
                const colors: Record<string, string> = { critical: "bg-red-500", high: "bg-orange-500", medium: "bg-yellow-500", low: "bg-blue-400", info: "bg-gray-500" };
                const textColors: Record<string, string> = { critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400", low: "text-blue-400", info: "text-gray-400" };
                const total = stats!.totalFindings || 1;
                return (
                  <div key={severity} className="flex items-center gap-3">
                    <span className={`font-mono text-[10px] w-16 ${textColors[severity] || "text-muted-foreground"} uppercase`}>{severity}</span>
                    <div className="flex-1 h-2 bg-primary/10 rounded-full overflow-hidden">
                      <div className={`h-2 rounded-full ${colors[severity] || "bg-gray-500"}`} style={{ width: `${(count / total) * 100}%` }} />
                    </div>
                    <span className="font-mono text-[10px] text-muted-foreground w-8 text-right">{count}</span>
                  </div>
                );
              })}
              {(!stats?.findingsBySeverity?.length) && (
                <p className="font-mono text-xs text-muted-foreground text-center py-4">No findings yet</p>
              )}
            </div>
          </div>

          {/* Scans by Status */}
          <div className="cyber-box p-4 sm:p-5">
            <h3 className="font-mono text-xs text-primary mb-4 flex items-center gap-2">
              <span className="w-2 h-2 bg-primary" /> SCANS_BY_STATUS
            </h3>
            <div className="space-y-2">
              {(stats?.scansByStatus ?? []).map(({ status, count }) => {
                const colors: Record<string, string> = { completed: "text-cyan-400 border-cyan-400/50", running: "text-primary border-primary/50", failed: "text-red-400 border-red-400/50", cancelled: "text-gray-400 border-gray-400/50" };
                return (
                  <div key={status} className="flex items-center justify-between p-2 border border-border/30">
                    <span className={`font-mono text-[10px] px-2 py-0.5 border uppercase ${colors[status] || "text-muted-foreground border-border"}`}>{status}</span>
                    <span className="font-mono text-sm font-bold">{count}</span>
                  </div>
                );
              })}
              {(!stats?.scansByStatus?.length) && (
                <p className="font-mono text-xs text-muted-foreground text-center py-4">No scans yet</p>
              )}
            </div>
          </div>
        </div>

        {/* Active Users */}
        <div className="cyber-box p-4 sm:p-5">
          <h3 className="font-mono text-xs text-primary mb-4 flex items-center gap-2">
            <span className="w-2 h-2 bg-primary" /> RECENT_ACTIVE_USERS
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full font-mono text-xs">
              <thead>
                <tr className="border-b border-primary/20 text-muted-foreground">
                  <th className="p-2 text-left font-normal">USER</th>
                  <th className="p-2 text-left font-normal">EMAIL</th>
                  <th className="p-2 text-left font-normal">ROLE</th>
                  <th className="p-2 text-left font-normal">LAST LOGIN</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/30">
                {(stats?.activeUsers ?? []).map((u: any) => (
                  <tr key={u.id} className="hover:bg-primary/5">
                    <td className="p-2">{u.firstName || u.id.slice(0, 8)}</td>
                    <td className="p-2 text-muted-foreground">{u.email || "—"}</td>
                    <td className="p-2">
                      <span className={`px-1.5 py-0.5 border text-[9px] uppercase ${u.role === "admin" ? "text-red-400 border-red-400/50" : "text-cyan-400 border-cyan-400/50"}`}>{u.role}</span>
                    </td>
                    <td className="p-2 text-muted-foreground">{u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : "Never"}</td>
                  </tr>
                ))}
                {(!stats?.activeUsers?.length) && (
                  <tr><td colSpan={4} className="p-4 text-center text-muted-foreground">No users yet</td></tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="mt-3 flex justify-end">
            <Link href="/admin/users" className="cyber-button !py-1 !px-3 text-[10px] font-mono">
              MANAGE ALL USERS →
            </Link>
          </div>
        </div>
      </div>
    </Layout>
  );
}
