import { Router, type IRouter, type Request, type Response } from "express";
import { db, usersTable, scansTable, findingsTable, aiDecisionsTable } from "@workspace/db";
import { eq, desc, count } from "drizzle-orm";

const router: IRouter = Router();

function requireAdmin(req: Request, res: Response): boolean {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "unauthorized", message: "Authentication required" });
    return false;
  }
  const user = req.user as any;
  // Allow if role is admin OR if it's the local-admin user
  if (user.role !== "admin" && user.id !== "local-admin") {
    res.status(403).json({ error: "forbidden", message: "Admin access required" });
    return false;
  }
  return true;
}

router.get("/admin/stats", async (req: Request, res: Response) => {
  if (!requireAdmin(req, res)) return;
  try {
    const [usersCount] = await db.select({ count: count() }).from(usersTable);
    const [scansCount] = await db.select({ count: count() }).from(scansTable);
    const [findingsCount] = await db.select({ count: count() }).from(findingsTable);
    const [aiCount] = await db.select({ count: count() }).from(aiDecisionsTable);
    const statusCounts = await db.select({ status: scansTable.status, count: count() }).from(scansTable).groupBy(scansTable.status);
    const severityCounts = await db.select({ severity: findingsTable.severity, count: count() }).from(findingsTable).groupBy(findingsTable.severity);
    const recentScans = await db.select().from(scansTable).orderBy(desc(scansTable.createdAt)).limit(5);
    const activeUsers = await db.select().from(usersTable).orderBy(desc(usersTable.lastLoginAt)).limit(5);
    res.json({ totalUsers: usersCount.count, totalScans: scansCount.count, totalFindings: findingsCount.count, totalAiDecisions: aiCount.count, scansByStatus: statusCounts, findingsBySeverity: severityCounts, recentScans, activeUsers });
  } catch (err) {
    req.log.error({ err }, "Failed to get admin stats");
    res.status(500).json({ error: "internal_error" });
  }
});

router.get("/admin/users", async (req: Request, res: Response) => {
  if (!requireAdmin(req, res)) return;
  try {
    const users = await db.select().from(usersTable).orderBy(desc(usersTable.createdAt));
    res.json({ users });
  } catch (err) {
    req.log.error({ err }, "Failed to get users");
    res.status(500).json({ error: "internal_error" });
  }
});

router.patch("/admin/users/:userId/role", async (req: Request, res: Response) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { userId } = req.params;
    const { role } = req.body;
    if (!["admin", "user", "analyst", "viewer"].includes(role)) {
      return res.status(400).json({ error: "invalid_role", message: "Role must be admin, analyst, viewer, or user" });
    }
    await db.update(usersTable).set({ role, updatedAt: new Date() }).where(eq(usersTable.id, userId));
    const [updated] = await db.select().from(usersTable).where(eq(usersTable.id, userId)).limit(1);
    if (!updated) return res.status(404).json({ error: "not_found" });
    res.json({ user: updated });
  } catch (err) {
    req.log.error({ err }, "Failed to update user role");
    res.status(500).json({ error: "internal_error" });
  }
});

router.patch("/admin/users/:userId/status", async (req: Request, res: Response) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { userId } = req.params;
    const { isActive } = req.body;
    await db.update(usersTable).set({ isActive: String(isActive), updatedAt: new Date() }).where(eq(usersTable.id, userId));
    const [updated] = await db.select().from(usersTable).where(eq(usersTable.id, userId)).limit(1);
    if (!updated) return res.status(404).json({ error: "not_found" });
    res.json({ user: updated });
  } catch (err) {
    req.log.error({ err }, "Failed to update user status");
    res.status(500).json({ error: "internal_error" });
  }
});

router.delete("/admin/users/:userId", async (req: Request, res: Response) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { userId } = req.params;
    const currentUser = req.user as any;
    if (userId === currentUser.id) {
      return res.status(400).json({ error: "cannot_delete_self", message: "Cannot delete your own account" });
    }
    await db.delete(usersTable).where(eq(usersTable.id, userId));
    res.json({ success: true });
  } catch (err) {
    req.log.error({ err }, "Failed to delete user");
    res.status(500).json({ error: "internal_error" });
  }
});

router.get("/admin/scans", async (req: Request, res: Response) => {
  if (!requireAdmin(req, res)) return;
  try {
    const scans = await db.select().from(scansTable).orderBy(desc(scansTable.createdAt)).limit(100);
    res.json({ scans });
  } catch (err) {
    req.log.error({ err }, "Failed to get admin scans");
    res.status(500).json({ error: "internal_error" });
  }
});

router.delete("/admin/scans/:scanId", async (req: Request, res: Response) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { scanId } = req.params;
    await db.delete(scansTable).where(eq(scansTable.id, scanId));
    res.json({ success: true });
  } catch (err) {
    req.log.error({ err }, "Failed to delete scan");
    res.status(500).json({ error: "internal_error" });
  }
});

router.get("/admin/findings", async (req: Request, res: Response) => {
  if (!requireAdmin(req, res)) return;
  try {
    const findings = await db.select().from(findingsTable).orderBy(desc(findingsTable.createdAt)).limit(200);
    res.json({ findings });
  } catch (err) {
    req.log.error({ err }, "Failed to get admin findings");
    res.status(500).json({ error: "internal_error" });
  }
});

router.post("/admin/promote-first", async (req: Request, res: Response) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: "userId required" });
    const [user] = await db.select().from(usersTable).where(eq(usersTable.id, userId)).limit(1);
    if (!user) return res.status(404).json({ error: "user not found" });
    await db.update(usersTable).set({ role: "admin" }).where(eq(usersTable.id, userId));
    const [updated] = await db.select().from(usersTable).where(eq(usersTable.id, userId)).limit(1);
    res.json({ success: true, user: updated });
  } catch (err) {
    res.status(500).json({ error: "internal_error" });
  }
});

export default router;
