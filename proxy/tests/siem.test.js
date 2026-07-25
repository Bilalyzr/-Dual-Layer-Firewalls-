/**
 * Tier 3 · Wave 2 · Epic D — SIEM forwarding.
 *
 * Covers the acceptance criterion "every block reaches the configured SIEM":
 *   - a BLOCK event published on the bus is POSTed to the webhook
 *   - a shadow DETECTION is NOT forwarded (unless opted in)
 *   - the payload matches the configured format (splunk / ecs / generic)
 *   - a down SIEM fails soft (no throw; failure counted)
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { publish, __clearListeners } from "../middleware/eventBus.js";
import {
  startSiemRelay,
  formatPayload,
  toRecord,
  siemStats,
  __resetSiemForTests,
} from "../integrations/siem.js";

const threatEvent = (over = {}) => ({
  type: "threat",
  ts: "2026-07-25T00:00:00.000Z",
  payload: {
    blocked: true,
    category: "LLM01",
    categoryTitle: "Prompt Injection",
    label: "ML-classified prompt injection",
    userId: "u1",
    forensics: { clientIp: "203.0.113.9", enrichment: { geoip: { country: "US" }, asn: { asn: 64500 }, abuseScore: 90 } },
    ...over,
  },
});

beforeEach(() => {
  __resetSiemForTests();
  __clearListeners();
  process.env.SIEM_WEBHOOK_URL = "https://siem.example/collect";
  process.env.SIEM_FORMAT = "generic";
  delete process.env.SIEM_FORWARD_DETECTIONS;
  delete process.env.SIEM_TOKEN;
  vi.restoreAllMocks();
});

afterEach(() => {
  __resetSiemForTests();
  __clearListeners();
  delete process.env.SIEM_WEBHOOK_URL;
});

describe("SIEM relay", () => {
  it("forwards a BLOCK event to the webhook", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue({ ok: true, status: 200 });
    expect(startSiemRelay()).toBe(true);

    publish("threat", threatEvent().payload);

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("https://siem.example/collect");
    expect(opts.method).toBe("POST");
    const body = JSON.parse(opts.body);
    expect(body.eventType).toBe("threat");
    expect(body.clientIp).toBe("203.0.113.9");
    expect(siemStats().forwarded).toBe(1);
  });

  it("does NOT forward a shadow detection by default", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue({ ok: true, status: 200 });
    startSiemRelay();
    publish("threat", threatEvent({ blocked: false }).payload);
    await new Promise((r) => setTimeout(r, 30));
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("forwards detections when SIEM_FORWARD_DETECTIONS=true", async () => {
    process.env.SIEM_FORWARD_DETECTIONS = "true";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue({ ok: true, status: 200 });
    startSiemRelay();
    publish("threat", threatEvent({ blocked: false }).payload);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
  });

  it("counts a failed delivery without throwing", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("connection refused"));
    startSiemRelay();
    publish("ban_enforced", { ip: "203.0.113.5", scope: "ip" });
    await vi.waitFor(() => expect(siemStats().failed).toBe(1));
    expect(siemStats().lastError).toMatch(/connection refused/);
  });

  it("forwards a signature block only once (dual-published as signature + threat)", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue({ ok: true, status: 200 });
    startSiemRelay();
    const alert = threatEvent({ kind: "signature", signature: "abc123" }).payload;
    // Mirror the chat pipeline's dual-publish for a signature block.
    publish("signature", alert);
    publish("threat", alert);
    await vi.waitFor(() => expect(siemStats().forwarded).toBe(1));
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("does not start when the webhook URL is unset", () => {
    delete process.env.SIEM_WEBHOOK_URL;
    expect(startSiemRelay()).toBe(false);
  });
});

describe("SIEM payload formats", () => {
  it("wraps in a Splunk HEC envelope", () => {
    process.env.SIEM_FORMAT = "splunk";
    const p = formatPayload(threatEvent());
    expect(p.sourcetype).toBe("_json");
    expect(typeof p.time).toBe("number");
    expect(p.event.category).toBe("LLM01");
  });

  it("maps to Elastic Common Schema", () => {
    process.env.SIEM_FORMAT = "ecs";
    const p = formatPayload(threatEvent());
    expect(p["@timestamp"]).toBe("2026-07-25T00:00:00.000Z");
    expect(p["source.ip"]).toBe("203.0.113.9");
    expect(p["source.geo.country_iso_code"]).toBe("US");
    expect(p["event.action"]).toBe("blocked");
  });

  it("flattens enrichment into the generic record", () => {
    const rec = toRecord(threatEvent());
    expect(rec.country).toBe("US");
    expect(rec.asn).toBe(64500);
    expect(rec.abuseScore).toBe(90);
    expect(rec.severity).toBe("high");
  });
});
