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

    return () => es.close();
  }, [max]);

  return { threats, biometric, connected };
}
