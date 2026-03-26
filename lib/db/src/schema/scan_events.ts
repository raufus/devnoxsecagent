import { mysqlTable, varchar, text, timestamp, index } from "drizzle-orm/mysql-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const scanEventsTable = mysqlTable("scan_events", {
  id: varchar("id", { length: 36 }).primaryKey(),
  scanId: varchar("scan_id", { length: 36 }).notNull(),
  phase: varchar("phase", { length: 50 }).notNull(),
  message: text("message").notNull(),
  level: varchar("level", { length: 20 }).notNull().default("info").$type<"info" | "warning" | "success" | "error">(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => [
  index("idx_scan_events_scan_id").on(table.scanId),
]);

export const insertScanEventSchema = createInsertSchema(scanEventsTable).omit({
  createdAt: true,
});

export type InsertScanEvent = z.infer<typeof insertScanEventSchema>;
export type ScanEvent = typeof scanEventsTable.$inferSelect;
