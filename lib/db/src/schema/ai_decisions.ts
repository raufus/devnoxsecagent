import { mysqlTable, varchar, text, json, int, timestamp, index } from "drizzle-orm/mysql-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const aiDecisionsTable = mysqlTable("ai_decisions", {
  id: varchar("id", { length: 36 }).primaryKey(),
  scanId: varchar("scan_id", { length: 36 }).notNull(),
  phase: varchar("phase", { length: 50 }).notNull(),
  input: text("input").notNull(),
  reasoning: text("reasoning").notNull(),
  decision: text("decision").notNull(),
  actions: json("actions").$type<Array<{ action: string; priority: number; reason: string }>>(),
  confidence: int("confidence").notNull().default(80),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => [
  index("idx_ai_decisions_scan_id").on(table.scanId),
]);

export const insertAiDecisionSchema = createInsertSchema(aiDecisionsTable).omit({ createdAt: true });
export type InsertAiDecision = z.infer<typeof insertAiDecisionSchema>;
export type AiDecision = typeof aiDecisionsTable.$inferSelect;
