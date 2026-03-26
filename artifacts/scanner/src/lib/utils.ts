import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// MySQL JSON fields string ke tor pe return karta hai — ye parse karta hai
export function parseJsonField<T>(value: unknown, fallback: T): T {
  if (value === null || value === undefined) return fallback;
  if (typeof value === "string") {
    try { return JSON.parse(value) as T; } catch { return fallback; }
  }
  return value as T;
}

export function formatUptime(startedAt?: string, completedAt?: string | null) {
  if (!startedAt) return "00:00";
  const start = new Date(startedAt).getTime();
  const end = completedAt ? new Date(completedAt).getTime() : Date.now();
  const diff = Math.floor((end - start) / 1000);
  const m = Math.floor(diff / 60).toString().padStart(2, '0');
  const s = (diff % 60).toString().padStart(2, '0');
  return `${m}:${s}`;
}

export function getSeverityColor(severity: string) {
  switch(severity.toLowerCase()) {
    case 'critical': return 'text-red-500 border-red-500 bg-red-500/10 shadow-[0_0_10px_rgba(255,0,0,0.2)]';
    case 'high': return 'text-orange-500 border-orange-500 bg-orange-500/10 shadow-[0_0_10px_rgba(255,165,0,0.2)]';
    case 'medium': return 'text-yellow-500 border-yellow-500 bg-yellow-500/10 shadow-[0_0_10px_rgba(255,255,0,0.2)]';
    case 'low': return 'text-cyan-500 border-cyan-500 bg-cyan-500/10 shadow-[0_0_10px_rgba(0,255,255,0.2)]';
    default: return 'text-gray-400 border-gray-500 bg-gray-500/10';
  }
}
