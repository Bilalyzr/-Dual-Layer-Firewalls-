/**
 * useThreatStream — Server-Sent Events subscription (Req 4.1/4.2).
 *
 * Shares a SINGLE EventSource("/api/events") across all dashboard components
 * so multiple panels never exhaust the browser's 6-connection-per-origin
 * HTTP/1.1 socket limit.
 */
import { useEffect, useState } from "react";
import { apiFetch } from "../lib/api";

const MAX_STORE = 100;

const shared = {
  es: null,
  connected: false,
  hydrated: false,
  threats: [],
  agentEvents: [],
  behavior: [],
  moduleAnalyses: [],
  listeners: new Set(),
};

function notify() {
  for (const fn of shared.listeners) {
    try {
      fn();
    } catch {}
  }
}

function pushTo(key, payload) {
  shared[key] = [payload, ...shared[key]].slice(0, MAX_STORE);
  notify();
}

function hydrateInitial() {
  if (shared.hydrated) return;
  shared.hydrated = true;

  fetch("/api/alerts")
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => {
      if (Array.isArray(d?.alerts) && shared.threats.length === 0) {
        shared.threats = d.alerts.slice(0, MAX_STORE);
        notify();
      }
    })
    .catch(() => {});

  apiFetch("/api/behavior/events?limit=30")
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => {
      const list = Array.isArray(d?.events) ? d.events : Array.isArray(d) ? d : null;
      if (list && list.length > 0 && shared.behavior.length === 0) {
        shared.behavior = list.slice(0, MAX_STORE);
        notify();
      }
    })
    .catch(() => {});

  fetch("/api/alerts/module-analyses?limit=30")
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => {
      if (Array.isArray(d?.moduleAnalyses) && shared.moduleAnalyses.length === 0) {
        shared.moduleAnalyses = d.moduleAnalyses.slice(0, MAX_STORE);
        notify();
      }
    })
    .catch(() => {});
}

function ensureSharedStream() {
  if (shared.es) return;
  const es = new EventSource("/api/events?v=2");
  shared.es = es;

  const onConnected = () => {
    shared.connected = true;
    notify();
    hydrateInitial();
  };

  es.addEventListener("open", onConnected);
  es.addEventListener("hello", onConnected);
  es.onerror = () => {
    shared.connected = false;
    notify();
  };

  es.addEventListener("threat", (e) => {
    try {
      const { payload } = JSON.parse(e.data);
      pushTo("threats", payload);
    } catch {}
  });
  es.addEventListener("agent", (e) => {
    try {
      const { payload } = JSON.parse(e.data);
      pushTo("agentEvents", payload);
    } catch {}
  });
  es.addEventListener("behavior", (e) => {
    try {
      const { payload } = JSON.parse(e.data);
      pushTo("behavior", payload);
    } catch {}
  });
  es.addEventListener("module_analysis", (e) => {
    try {
      const { payload } = JSON.parse(e.data);
      // Tag LIVE arrivals: the panel must only score prompts from THIS page
      // load — the hydrated global history (other clients / test traffic)
      // must not appear as an instant "live session score" on open.
      const entry = { ...payload, liveSSE: true };
      const filtered = shared.moduleAnalyses.filter(
        (m) => !(m.ts === entry.ts && m.prompt === entry.prompt)
      );
      shared.moduleAnalyses = [entry, ...filtered].slice(0, MAX_STORE);
      notify();
    } catch {}
  });
  // Enrichment lands out-of-band (geoip/asn/reputation) after the threat is
  // already on screen. Merge it into the matching threat(s) by source IP so the
  // country / org appears next to the address without dropping the live item.
  es.addEventListener("enrichment", (e) => {
    try {
      const { payload } = JSON.parse(e.data);
      const ip = payload?.ip;
      const enrichment = payload?.enrichment;
      if (!ip) return;
      shared.threats = shared.threats.map((t) =>
        t?.forensics?.clientIp === ip
          ? { ...t, forensics: { ...t.forensics, enrichment } }
          : t
      );
      notify();
    } catch {}
  });
}

function teardownIfIdle() {
  if (shared.listeners.size === 0 && shared.es) {
    try {
      shared.es.close();
    } catch {}
    shared.es = null;
    shared.connected = false;
  }
}

export function useThreatStream(max = 50) {
  const [, setTick] = useState(0);

  useEffect(() => {
    const listener = () => setTick((t) => t + 1);
    shared.listeners.add(listener);
    ensureSharedStream();
    return () => {
      shared.listeners.delete(listener);
      teardownIfIdle();
    };
  }, []);

  return {
    threats: shared.threats.slice(0, max),
    agentEvents: shared.agentEvents.slice(0, max),
    behavior: shared.behavior.slice(0, max),
    moduleAnalyses: shared.moduleAnalyses.slice(0, max),
    connected: shared.connected,
  };
}
