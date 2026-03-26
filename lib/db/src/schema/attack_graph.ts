import { mysqlTable, varchar, text, json, timestamp, index } from "drizzle-orm/mysql-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const graphNodesTable = mysqlTable("graph_nodes", {
  id: varchar("id", { length: 36 }).primaryKey(),
  scanId: varchar("scan_id", { length: 36 }).notNull(),
  nodeType: varchar("node_type", { length: 50 }).notNull().$type<"domain" | "subdomain" | "ip" | "server" | "vulnerability" | "exploit" | "email" | "service">(),
  label: text("label").notNull(),
  data: json("data").$type<Record<string, unknown>>(),
  severity: varchar("severity", { length: 20 }).default("none").$type<"critical" | "high" | "medium" | "low" | "info" | "none">(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => [
  index("idx_graph_nodes_scan_id").on(table.scanId),
]);

export const graphEdgesTable = mysqlTable("graph_edges", {
  id: varchar("id", { length: 36 }).primaryKey(),
  scanId: varchar("scan_id", { length: 36 }).notNull(),
  sourceId: varchar("source_id", { length: 36 }).notNull(),
  targetId: varchar("target_id", { length: 36 }).notNull(),
  edgeType: varchar("edge_type", { length: 50 }).notNull().$type<"resolves_to" | "has_subdomain" | "runs" | "vulnerable_to" | "exploited_via" | "hosts" | "owns" | "communicates_with">(),
  label: varchar("label", { length: 255 }),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => [
  index("idx_graph_edges_scan_id").on(table.scanId),
  index("idx_graph_edges_source").on(table.sourceId),
  index("idx_graph_edges_target").on(table.targetId),
]);

export const insertGraphNodeSchema = createInsertSchema(graphNodesTable).omit({ createdAt: true });
export const insertGraphEdgeSchema = createInsertSchema(graphEdgesTable).omit({ createdAt: true });

export type InsertGraphNode = z.infer<typeof insertGraphNodeSchema>;
export type InsertGraphEdge = z.infer<typeof insertGraphEdgeSchema>;
export type GraphNode = typeof graphNodesTable.$inferSelect;
export type GraphEdge = typeof graphEdgesTable.$inferSelect;
