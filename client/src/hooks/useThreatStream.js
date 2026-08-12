/**
 * useThreatStream — Server-Sent Events subscription (Req 4.1/4.2).
 *
 * Connects to /api/events and exposes the live stream of `threat` and
 * `biometric` events so the dashboard updates in real time without polling.
 */
import { useEffect, useState } from "react";

export function useThreatStream(max = 50) {
  const [threats, setThreats] = useState([]);
  const [biometric, setBiometric] = useState([]);
  const [agentEvents, setAgentEvents] = useState([]);
  const [behavior, setBehavior] = useState([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const es = new EventSource("/api/events");

    es.addEventListener("open", () => setConnected(true));
    es.addEventListener("hello", () => setConnected(true));
    es.onerror = () => setConnected(false);

    const push = (setter, payload) =>
      setter((prev) => [payload, ...prev].slice(0, max));

    es.addEventListener("threat", (e) => {
      try {
        const { payload } = JSON.parse(e.data);
        push(setThreats, payload);
      } catch {}
    });
    es.addEventListener("biometric", (e) => {
      try {
        const { payload } = JSON.parse(e.data);
        push(setBiometric, payload);
      } catch {}
    });
    es.addEventListener("agent", (e) => {
      try {
        const { payload } = JSON.parse(e.data);
        push(setAgentEvents, payload);
      } catch {}
    });
    es.addEventListener("behavior", (e) => {
      try {
        const { payload } = JSON.parse(e.data);
        push(setBehavior, payload);
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
        setThreats((prev) =>
          prev.map((t) =>
            t?.forensics?.clientIp === ip
              ? { ...t, forensics: { ...t.forensics, enrichment } }
              : t
          )
        );
      } catch {}
    });

    return () => es.close();
  }, [max]);

  return { threats, biometric, agentEvents, behavior, connected };
}
