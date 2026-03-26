import { mysqlTable, varchar, text, json, timestamp, index } from "drizzle-orm/mysql-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const reconDataTable = mysqlTable("recon_data", {
  id: varchar("id", { length: 36 }).primaryKey(),
  scanId: varchar("scan_id", { length: 36 }).notNull(),
  targetDomain: varchar("target_domain", { length: 255 }).notNull(),
  ipAddresses: json("ip_addresses").$type<string[]>(),
  subdomains: json("subdomains").$type<Array<{ name: string; ip?: string; status?: string }>>(),
  dnsRecords: json("dns_records").$type<Array<{ type: string; value: string }>>(),
  whoisData: json("whois_data").$type<Record<string, string>>(),
  emails: json("emails").$type<string[]>(),
  socialProfiles: json("social_profiles").$type<Array<{ platform: string; url: string }>>(),
  techStack: json("tech_stack").$type<string[]>(),
  openPorts: json("open_ports").$type<Array<{ port: number; service: string; banner?: string }>>(),
  cloudProviders: json("cloud_providers").$type<string[]>(),
  networkInfo: json("network_info").$type<{ asn?: string; org?: string; country?: string; range?: string }>(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => [
  index("idx_recon_data_scan_id").on(table.scanId),
]);

export const insertReconDataSchema = createInsertSchema(reconDataTable).omit({ createdAt: true });
export type InsertReconData = z.infer<typeof insertReconDataSchema>;
export type ReconData = typeof reconDataTable.$inferSelect;
