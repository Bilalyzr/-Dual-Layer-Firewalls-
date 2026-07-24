/**
 * Tier 3 · Wave 1 · Epic A — trustworthy client-IP resolution.
 *
 * Everything downstream (GeoIP enrichment, reputation, auto-banning, SIEM) is
 * only as trustworthy as the source IP it is built on. A naive read of
 * `X-Forwarded-For` lets any client forge its apparent address — so we resolve
 * the real client IP against a TRUSTED_PROXIES allow-list:
 *
 *   • The socket peer (`req.socket.remoteAddress`) is the ONE address we can't be
 *     lied to about — it's who actually opened the TCP connection.
 *   • Forwarding headers (XFF / X-Real-IP / CF-Connecting-IP) are trusted ONLY
 *     when the direct peer is itself a trusted proxy. From an untrusted peer they
 *     are attacker-controlled and ignored entirely (→ `spoofed: true`).
 *   • When the peer is trusted we walk the XFF chain from the edge inward,
 *     skipping trusted hops, and take the first non-trusted address as the client.
 *   • `x-client-ip` is our OWN internal propagation header (see lib/forward.js):
 *     a trusted upstream service (the gateway) already resolved the client and
 *     hands it to the next service so the chain isn't re-walked per hop.
 *
 * Attaches `req.ipContext = { clientIp, realIp, proxyChain, peerTrusted, spoofed }`.
 * Cheap and always-on; the IP_FORENSICS_ENABLED flag gates the heavier work of
 * recording forensics onto alerts (see routes/chat.js), not this resolution.
 */
import { normalizeIp, ipInAnyCidr, parseCidrList } from "../lib/cidr.js";

// Loopback + RFC1918 + link-local are trusted by default: a reverse proxy on the
// same host / private network is the normal deployment. Operators extend this
// with TRUSTED_PROXIES for their real edge (nginx/Cloudflare) CIDRs.
const DEFAULT_TRUSTED = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fc00::/7";

let _cache = null;
let _cacheKey = null;

/** Parsed TRUSTED_PROXIES (default private ranges + operator additions). Cached. */
export function trustedProxies() {
  const extra = process.env.TRUSTED_PROXIES || "";
  const key = extra;
  if (_cache && _cacheKey === key) return _cache;
  _cacheKey = key;
  _cache = parseCidrList(`${DEFAULT_TRUSTED},${extra}`);
  return _cache;
}

/** Test hook: force a re-parse after mutating TRUSTED_PROXIES. */
export function __resetTrustedCache() {
  _cache = null;
  _cacheKey = null;
}

/** Feature flag: attach a forensics sub-document to alerts. Default on. */
export function ipForensicsEnabled() {
  return String(process.env.IP_FORENSICS_ENABLED ?? "true").toLowerCase() !== "false";
}

function headerList(req, name) {
  const raw = req.headers?.[name];
  if (!raw) return [];
  return String(raw)
    .split(",")
    .map((x) => normalizeIp(x))
    .filter(Boolean);
}

function firstIp(req, name) {
  return headerList(req, name)[0] || "";
}

/**
 * Resolve the client IP for a request without mutating it (pure — reused by the
 * edge ipGuard in Epic C, which must know the client before the pipeline runs).
 */
export function resolveIpContext(req) {
  const peer = normalizeIp(req.socket?.remoteAddress || req.connection?.remoteAddress || "");
  const trusted = trustedProxies();
  const peerTrusted = peer ? ipInAnyCidr(peer, trusted) : false;

  const xff = headerList(req, "x-forwarded-for");
  const cf = firstIp(req, "cf-connecting-ip");
  const xreal = firstIp(req, "x-real-ip");
  const internal = firstIp(req, "x-client-ip");

  // Untrusted direct peer: forwarding headers are attacker-controlled. Ignore
  // them and pin the client to the socket peer — a forged XFF can't move it.
  if (!peerTrusted) {
    const spoofed = !!(xff.length || cf || xreal || internal);
    return {
      clientIp: peer,
      realIp: peer,
      proxyChain: peer ? [peer] : [],
      peerTrusted: false,
      spoofed,
    };
  }

  // Trusted peer: our own resolved-client header (microservice propagation) wins.
  if (internal) {
    return {
      clientIp: internal,
      realIp: peer,
      proxyChain: [...xff, peer].filter(Boolean),
      peerTrusted: true,
      spoofed: false,
    };
  }

  // Walk the XFF chain from the edge (us) inward, skipping trusted hops; the
  // first non-trusted address is the real client.
  if (xff.length) {
    const chain = [...xff, peer];
    let i = chain.length - 1;
    while (i > 0 && ipInAnyCidr(chain[i], trusted)) i--;
    return {
      clientIp: chain[i],
      realIp: peer,
      proxyChain: chain,
      peerTrusted: true,
      spoofed: false,
    };
  }

  // Single-value forwarding headers set by a trusted proxy.
  if (cf) return { clientIp: cf, realIp: peer, proxyChain: [cf, peer], peerTrusted: true, spoofed: false };
  if (xreal) return { clientIp: xreal, realIp: peer, proxyChain: [xreal, peer], peerTrusted: true, spoofed: false };

  return {
    clientIp: peer,
    realIp: peer,
    proxyChain: peer ? [peer] : [],
    peerTrusted: true,
    spoofed: false,
  };
}

/** Express middleware: attach `req.ipContext`. */
export function ipContextMiddleware(req, _res, next) {
  req.ipContext = resolveIpContext(req);
  next();
}

/**
 * Build the `forensics` sub-document for an alert from a request, or null when
 * forensics is disabled / no IP could be resolved. Epic B enrichment (geoip,
 * asn, reputation) is patched onto this out-of-band, post-response.
 */
export function forensicsFromReq(req) {
  if (!ipForensicsEnabled()) return null;
  const ctx = req?.ipContext || resolveIpContext(req);
  if (!ctx || !ctx.clientIp) return null;
  return {
    clientIp: ctx.clientIp,
    realIp: ctx.realIp,
    proxyChain: ctx.proxyChain || [],
    spoofedForwardedFor: !!ctx.spoofed,
    enrichment: null, // filled asynchronously by Epic B
  };
}
