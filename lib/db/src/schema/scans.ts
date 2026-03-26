import { mysqlTable, varchar, text, int, json, timestamp } from "drizzle-orm/mysql-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const scansTable = mysqlTable("scans", {
  id: varchar("id", { length: 36 }).primaryKey(),
  targetUrl: text("target_url").notNull(),
  scanType: varchar("scan_type", { length: 20 }).notNull().$type<"quick" | "full" | "deep">(),
  status: varchar("status", { length: 20 }).notNull().default("pending").$type<"pending" | "running" | "completed" | "failed" | "cancelled">(),
  progress: int("progress").notNull().default(0),
  currentPhase: varchar("current_phase", { length: 30 }).notNull().default("idle").$type<"idle" | "recon" | "scanning" | "ai_analysis" | "exploitation" | "reporting" | "done">(),
  totalFindings: int("total_findings").notNull().default(0),
  criticalCount: int("critical_count").notNull().default(0),
  highCount: int("high_count").notNull().default(0),
  mediumCount: int("medium_count").notNull().default(0),
  lowCount: int("low_count").notNull().default(0),
  infoCount: int("info_count").notNull().default(0),
  techStack: json("tech_stack").$type<string[]>(),
  subdomains: json("subdomains").$type<string[]>(),
  endpoints: json("endpoints").$type<string[]>(),
  modules: json("modules").$type<string[]>(),
  aiAnalysis: text("ai_analysis"),
  riskScore: int("risk_score").default(0),
  startedAt: timestamp("started_at").defaultNow(),
  completedAt: timestamp("completed_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertScanSchema = createInsertSchema(scansTable).omit({
  totalFindings: true,
  criticalCount: true,
  highCount: true,
  mediumCount: true,
  lowCount: true,
  infoCount: true,
  progress: true,
  status: true,
  currentPhase: true,
  techStack: true,
  subdomains: true,
  endpoints: true,
  completedAt: true,
  startedAt: true,
});

export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scansTable.$inferSelect;
