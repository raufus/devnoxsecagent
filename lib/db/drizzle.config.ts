import { defineConfig } from "drizzle-kit";

// @ts-ignore
const dbUrl = process.env.DATABASE_URL as string;

export default defineConfig({
  schema: "./src/schema/index.ts",
  dialect: "mysql",
  dbCredentials: {
    url: dbUrl,
  },
});
