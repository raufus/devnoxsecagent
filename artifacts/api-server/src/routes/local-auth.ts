import { Router, type Request, type Response } from "express";
import { db, usersTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { createSession, clearSession, SESSION_COOKIE, SESSION_TTL } from "../lib/auth";
import type { SessionData } from "../lib/auth";
import { randomUUID, createHash } from "crypto";

const router = Router();

function hashPassword(password: string): string {
  return createHash("sha256").update(password + "devnox_salt_2024").digest("hex");
}

// ─── Register ─────────────────────────────────────────────────────────────────
router.post("/auth/register", async (req: Request, res: Response) => {
  const { email, password, firstName, lastName } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "validation_error", message: "Email and password are required" });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "validation_error", message: "Password must be at least 6 characters" });
  }
  try {
    const existing = await db.select().from(usersTable).where(eq(usersTable.email, email)).limit(1);
    if (existing.length > 0) {
      return res.status(409).json({ error: "conflict", message: "Email already registered" });
    }
    const userId = randomUUID();
    const passwordHash = hashPassword(password);
    await db.insert(usersTable).values({
      id: userId, email,
      firstName: firstName || email.split("@")[0],
      lastName: lastName || "",
      role: "user", isActive: "true",
      profileImageUrl: `hash:${passwordHash}`,
      lastLoginAt: new Date(),
    });
    res.status(201).json({ success: true, message: "Account created successfully" });
  } catch {
    res.status(500).json({ error: "internal_error", message: "Registration failed" });
  }
});

// ─── Login ────────────────────────────────────────────────────────────────────
router.post("/auth/local/login", async (req: Request, res: Response) => {
  const { username, password } = req.body;
  const adminUser = process.env.ADMIN_USERNAME || "admin";
  const adminPass = process.env.ADMIN_PASSWORD || "admin123";

  let userId: string;
  let userEmail: string;
  let userFirstName: string;
  let userLastName: string;
  let userRole: string;

  if (username === adminUser && password === adminPass) {
    userId = "local-admin";
    userEmail = `${adminUser}@local.dev`;
    userFirstName = "Admin";
    userLastName = "User";
    userRole = "admin";
    const existing = await db.select().from(usersTable).where(eq(usersTable.id, userId)).limit(1);
    if (existing.length === 0) {
      await db.insert(usersTable).values({
        id: userId, email: userEmail, firstName: userFirstName,
        lastName: userLastName, role: "admin", isActive: "true", lastLoginAt: new Date(),
      });
    } else {
      await db.update(usersTable).set({ lastLoginAt: new Date() }).where(eq(usersTable.id, userId));
    }
  } else {
    const passwordHash = hashPassword(password);
    const [dbUser] = await db.select().from(usersTable).where(eq(usersTable.email, username)).limit(1);
    if (!dbUser || dbUser.profileImageUrl !== `hash:${passwordHash}`) {
      return res.status(401).json({ error: "invalid_credentials", message: "Invalid email or password" });
    }
    if (dbUser.isActive === "false") {
      return res.status(403).json({ error: "account_disabled", message: "Your account has been disabled" });
    }
    userId = dbUser.id;
    userEmail = dbUser.email || "";
    userFirstName = dbUser.firstName || "";
    userLastName = dbUser.lastName || "";
    userRole = dbUser.role || "user";
    await db.update(usersTable).set({ lastLoginAt: new Date() }).where(eq(usersTable.id, userId));
  }

  const sessionData: SessionData = {
    user: { id: userId, email: userEmail, firstName: userFirstName, lastName: userLastName, profileImageUrl: null, role: userRole },
    access_token: "local-token",
    expires_at: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
  };

  const sid = await createSession(sessionData);
  res.cookie(SESSION_COOKIE, sid, { httpOnly: true, secure: false, sameSite: "lax", path: "/", maxAge: SESSION_TTL });
  res.json({ success: true, user: sessionData.user });
});

// ─── Logout ───────────────────────────────────────────────────────────────────
router.post("/auth/local/logout", async (req: Request, res: Response) => {
  const sid = req.cookies?.[SESSION_COOKIE];
  await clearSession(res, sid);
  res.json({ success: true });
});

// ─── Me ───────────────────────────────────────────────────────────────────────
router.get("/auth/local/me", (req: Request, res: Response) => {
  if (!req.isAuthenticated()) return res.status(401).json({ user: null });
  res.json({ user: req.user });
});

export default router;
