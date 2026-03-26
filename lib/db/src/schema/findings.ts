import { mysqlTable, varchar, text, float, boolean, timestamp, index } from "drizzle-orm/mysql-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const findingsTable = mysqlTable("findings", {
  id: varchar("id", { length: 36 }).primaryKey(),
  scanId: varchar("scan_id", { length: 36 }).notNull(),
  type: varchar("type", { length: 100 }).notNull(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  severity: varchar("severity", { length: 20 }).notNull().$type<"critical" | "high" | "medium" | "low" | "info">(),
  endpoint: text("endpoint").notNull(),
  method: varchar("method", { length: 20 }),
  parameter: varchar("parameter", { length: 255 }),
  payload: text("payload"),
  evidence: text("evidence"),
  request: text("request"),
  response: text("response"),
  recommendation: text("recommendation").notNull(),
  cweId: varchar("cwe_id", { length: 50 }),
  cvssScore: float("cvss_score"),
  aiAnalysis: text("ai_analysis"),
  falsePositive: boolean("false_positive").notNull().default(false),
  bypassConfirmed: boolean("bypass_confirmed").default(false),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => [
  index("idx_findings_scan_id").on(table.scanId),
  index("idx_findings_severity").on(table.severity),
]);

export const insertFindingSchema = createInsertSchema(findingsTable).omit({
  falsePositive: true,
  createdAt: true,
});

export type InsertFinding = z.infer<typeof insertFindingSchema>;
export type Finding = typeof findingsTable.$inferSelect;
