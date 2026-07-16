/**
 * Tiny in-process pub/sub for Server-Sent Events (Req 4.1/4.2 live feed).
 *
 * The dashboard subscribes to /api/events; any component that records an alert
 * or a biometric decision publishes here and every connected client receives it.
 */

const subscribers = new Set();

export function subscribe(res) {
  subscribers.add(res);
  res.on("close", () => subscribers.delete(res));
  return () => subscribers.delete(res);
}

export function publish(type, payload) {
  const event = { type, ts: new Date().toISOString(), payload };
  const line = `event: ${type}\ndata: ${JSON.stringify(event)}\n\n`;
  for (const res of subscribers) {
    res.write(line);
  }
  return subscribers.size;
}

export function subscriberCount() {
  return subscribers.size;
}
