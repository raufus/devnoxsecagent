import { useState, useEffect, useRef } from "react";
import { ScanEvent } from "@workspace/api-client-react";

export interface LiveFinding {
  id: string;
  type: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  endpoint: string;
  parameter?: string | null;
  payload?: string | null;
  evidence?: string | null;
  recommendation: string;
  cweId?: string | null;
  cvssScore?: number | null;
  aiAnalysis?: string | null;
  createdAt: string;
}

export function useScanStream(scanId?: string) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [findings, setFindings] = useState<LiveFinding[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const seenEventIds = useRef(new Set<string>());
  const seenFindingIds = useRef(new Set<string>());

  useEffect(() => {
    if (!scanId) return;

    seenEventIds.current.clear();
    seenFindingIds.current.clear();

    const addEvent = (ev: ScanEvent) => {
      if (ev.id && seenEventIds.current.has(ev.id)) return;
      if (ev.id) seenEventIds.current.add(ev.id);
      setEvents(prev => [...prev, ev]);
      // Auto-log to Logger
      try {
        const level = ev.level === "error" ? "error" : ev.level === "warning" ? "warn" : ev.level === "success" ? "success" : "info";
        const entries = JSON.parse(localStorage.getItem("devnox_logger") || "[]");
        entries.unshift({ id: crypto.randomUUID(), timestamp: Date.now(), level, source: `SCAN:${ev.phase}`, message: ev.message });
        localStorage.setItem("devnox_logger", JSON.stringify(entries.slice(0, 1000)));
      } catch { }
    };

    const addFinding = (f: LiveFinding) => {
      if (f.id && seenFindingIds.current.has(f.id)) return;
      if (f.id) seenFindingIds.current.add(f.id);
      setFindings(prev => [...prev, f]);
      // Auto-log findings to Logger
      try {
        const entries = JSON.parse(localStorage.getItem("devnox_logger") || "[]");
        entries.unshift({ id: crypto.randomUUID(), timestamp: Date.now(), level: f.severity === "critical" || f.severity === "high" ? "error" : "warn", source: "FINDING", message: `[${f.severity.toUpperCase()}] ${f.type}: ${f.title}` });
        localStorage.setItem("devnox_logger", JSON.stringify(entries.slice(0, 1000)));
      } catch { }
    };

    fetch(`/api/scans/${scanId}/events`)
      .then(res => res.json())
      .then(data => {
        if (data.events) {
          for (const ev of data.events) addEvent(ev);
        }
      })
      .catch(e => console.error("Failed to load historical events:", e));

    fetch(`/api/scans/${scanId}/findings`)
      .then(res => res.json())
      .then(data => {
        if (data.findings) {
          for (const f of data.findings) addFinding(f);
        }
      })
      .catch(e => console.error("Failed to load historical findings:", e));

    const es = new EventSource(`/api/scans/${scanId}/events-stream`);

    es.onopen = () => {
      setConnected(true);
      setError(null);
    };

    es.onmessage = (e) => {
      try {
        const payload = JSON.parse(e.data);
        if (payload.type === "event" && payload.data) {
          addEvent(payload.data as ScanEvent);
        } else if (payload.type === "finding" && payload.data) {
          addFinding(payload.data as LiveFinding);
        }
      } catch (err) {
        console.error("Failed to parse SSE event:", err);
      }
    };

    es.onerror = () => {
      setError("Connection lost.");
      setConnected(false);
    };

    return () => {
      es.close();
      setConnected(false);
    };
  }, [scanId]);

  return { events, findings, connected, error };
}
