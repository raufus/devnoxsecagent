import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import { Layout } from "@/components/layout";
import { Users, ShieldAlert, Trash2, Shield, Eye, Edit3, CheckCircle, XCircle } from "lucide-react";
import { Link } from "wouter";
import { useToast } from "@/hooks/use-toast";

interface User {
  id: string;
  email: string | null;
  firstName: string | null;
  lastName: string | null;
  role: string;
  isActive: string;
  lastLoginAt: string | null;
  createdAt: string;
}

const ROLES = ["user", "analyst", "viewer", "admin"];
const ROLE_COLORS: Record<string, string> = {
  admin: "text-red-400 border-red-400/50 bg-red-400/10",
  analyst: "text-orange-400 border-orange-400/50 bg-orange-400/10",
  viewer: "text-blue-400 border-blue-400/50 bg-blue-400/10",
  user: "text-cyan-400 border-cyan-400/50 bg-cyan-400/10",
};

export default function AdminUsers() {
  const { user, isAuthenticated, isLoading } = useAuth();
  const { toast } = useToast();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchUsers = () => {
    fetch("/api/admin/users", { credentials: "include" })
      .then(r => r.json())
      .then(d => { setUsers(d.users || []); setLoading(false); });
  };

  useEffect(() => { if (isAuthenticated) fetchUsers(); }, [isAuthenticated]);

  const handleRoleChange = async (userId: string, role: string) => {
    const res = await fetch(`/api/admin/users/${userId}/role`, {
      method: "PATCH", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role }),
    });
    if (res.ok) { fetchUsers(); toast({ title: "ROLE_UPDATED", description: `User role changed to ${role}` }); }
    else toast({ title: "ERROR", description: "Failed to update role", variant: "destructive" });
  };

  const handleToggleStatus = async (u: User) => {
    const newStatus = u.isActive !== "true";
    const res = await fetch(`/api/admin/users/${u.id}/status`, {
      method: "PATCH", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ isActive: newStatus }),
    });
    if (res.ok) { fetchUsers(); toast({ title: newStatus ? "USER_ACTIVATED" : "USER_DEACTIVATED", description: u.email || u.id }); }
    else toast({ title: "ERROR", description: "Failed to update status", variant: "destructive" });
  };

  const handleDelete = async (userId: string) => {
    if (!confirm("PERMANENTLY DELETE this user record?")) return;
    const res = await fetch(`/api/admin/users/${userId}`, { method: "DELETE", credentials: "include" });
    if (res.ok) { fetchUsers(); toast({ title: "USER_DELETED", description: "User record purged." }); }
    else toast({ title: "ERROR", description: "Cannot delete", variant: "destructive" });
  };

  if (isLoading || loading) return (
    <Layout>
      <div className="flex items-center justify-center h-64 font-mono text-sm text-muted-foreground">
        <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin mr-3" />
        LOADING...
      </div>
    </Layout>
  );

  const userRole = (user as any)?.role;
  if (!isAuthenticated || userRole !== "admin") return (
    <Layout><div className="flex flex-col items-center justify-center h-64 gap-4">
      <ShieldAlert className="w-16 h-16 text-red-500 opacity-60" />
      <p className="font-mono text-sm text-muted-foreground">ACCESS_DENIED</p>
      <Link href="/" className="cyber-button text-xs">← BACK</Link>
    </div></Layout>
  );

  return (
    <Layout>
      <div className="space-y-6 animate-in fade-in duration-500">
        <header className="flex items-center justify-between">
          <div>
            <Link href="/admin" className="font-mono text-[10px] text-muted-foreground hover:text-primary transition-colors flex items-center gap-1 mb-1">
              ← ADMIN PANEL
            </Link>
            <h1 className="text-2xl sm:text-3xl flex items-center gap-3">
              <Users className="w-7 h-7 text-cyan-400 shrink-0" />
              USER_MANAGEMENT
            </h1>
            <p className="text-muted-foreground font-mono mt-1 text-xs">// Manage user accounts, roles, and access permissions</p>
          </div>
          <div className="font-mono text-xs text-muted-foreground">{users.length} USERS</div>
        </header>

        {/* Promote Self to Admin */}
        {users.length > 0 && !users.some(u => u.role === "admin") && (
          <div className="cyber-box p-4 border-yellow-400/30 bg-yellow-400/5">
            <p className="font-mono text-xs text-yellow-400 mb-3">⚠ No admin users found. Promote yourself to admin?</p>
            <button
              onClick={() => fetch("/api/admin/promote-first", { method: "POST", credentials: "include", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ userId: user?.id }) }).then(() => fetchUsers())}
              className="cyber-button text-xs !border-yellow-400/40 !text-yellow-400"
            >
              PROMOTE_ME_TO_ADMIN
            </button>
          </div>
        )}

        {/* Desktop Table */}
        <div className="cyber-box overflow-hidden hidden md:block">
          <div className="overflow-x-auto">
            <table className="w-full font-mono text-sm">
              <thead>
                <tr className="border-b border-primary/30 bg-black/50 text-primary/70">
                  <th className="p-4 font-normal text-left">USER</th>
                  <th className="p-4 font-normal text-left">EMAIL</th>
                  <th className="p-4 font-normal text-left">ROLE</th>
                  <th className="p-4 font-normal text-left">STATUS</th>
                  <th className="p-4 font-normal text-left">LAST LOGIN</th>
                  <th className="p-4 font-normal text-left">JOINED</th>
                  <th className="p-4 font-normal text-right">ACTIONS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/50">
                {users.map(u => (
                  <tr key={u.id} className="hover:bg-primary/5 transition-colors">
                    <td className="p-4">
                      <div className="flex items-center gap-2">
                        <div className="w-7 h-7 rounded border border-primary/30 bg-primary/10 flex items-center justify-center text-primary font-bold text-[10px]">
                          {(u.firstName?.[0] || u.email?.[0] || "?").toUpperCase()}
                        </div>
                        <span className="text-foreground text-xs">{u.firstName || "Unknown"} {u.lastName || ""}</span>
                        {u.id === (user as any)?.id && <span className="text-[8px] font-mono text-primary border border-primary/30 px-1">YOU</span>}
                      </div>
                    </td>
                    <td className="p-4 text-muted-foreground text-xs">{u.email || "—"}</td>
                    <td className="p-4">
                      <select
                        value={u.role}
                        onChange={e => handleRoleChange(u.id, e.target.value)}
                        className={`font-mono text-[10px] px-2 py-0.5 border bg-background cursor-pointer ${ROLE_COLORS[u.role] || "text-muted-foreground border-border"}`}
                        disabled={u.id === (user as any)?.id}
                      >
                        {ROLES.map(r => <option key={r} value={r}>{r.toUpperCase()}</option>)}
                      </select>
                    </td>
                    <td className="p-4">
                      <button onClick={() => handleToggleStatus(u)} className="flex items-center gap-1">
                        {u.isActive !== "false" ? (
                          <CheckCircle className="w-4 h-4 text-primary" />
                        ) : (
                          <XCircle className="w-4 h-4 text-red-500" />
                        )}
                        <span className={`font-mono text-[10px] ${u.isActive !== "false" ? "text-primary" : "text-red-500"}`}>
                          {u.isActive !== "false" ? "ACTIVE" : "INACTIVE"}
                        </span>
                      </button>
                    </td>
                    <td className="p-4 text-muted-foreground text-xs">{u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleDateString() : "Never"}</td>
                    <td className="p-4 text-muted-foreground text-xs">{new Date(u.createdAt).toLocaleDateString()}</td>
                    <td className="p-4 text-right">
                      {u.id !== (user as any)?.id && (
                        <button onClick={() => handleDelete(u.id)} className="text-red-500/70 hover:text-red-500 transition-colors">
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {users.length === 0 && (
                  <tr><td colSpan={7} className="p-8 text-center text-muted-foreground font-mono text-xs">NO_USERS_FOUND</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Mobile Cards */}
        <div className="md:hidden space-y-3">
          {users.map(u => (
            <div key={u.id} className="cyber-box p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded border border-primary/30 bg-primary/10 flex items-center justify-center text-primary font-bold text-xs">
                    {(u.firstName?.[0] || u.email?.[0] || "?").toUpperCase()}
                  </div>
                  <div>
                    <div className="font-mono text-xs text-foreground">{u.firstName || "Unknown"} {u.lastName || ""}</div>
                    <div className="font-mono text-[10px] text-muted-foreground">{u.email || "—"}</div>
                  </div>
                </div>
                <span className={`font-mono text-[9px] px-1.5 py-0.5 border uppercase ${ROLE_COLORS[u.role] || ""}`}>{u.role}</span>
              </div>
              <div className="flex gap-2">
                <select
                  value={u.role}
                  onChange={e => handleRoleChange(u.id, e.target.value)}
                  className="flex-1 font-mono text-[10px] p-1.5 border border-border bg-background text-foreground"
                  disabled={u.id === (user as any)?.id}
                >
                  {ROLES.map(r => <option key={r} value={r}>{r.toUpperCase()}</option>)}
                </select>
                {u.id !== (user as any)?.id && (
                  <button onClick={() => handleDelete(u.id)} className="text-red-500/70 hover:text-red-500 p-1.5 border border-red-500/30">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </Layout>
  );
}
