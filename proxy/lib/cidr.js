/**
 * Tier 3 · Wave 1 — dependency-free IPv4/IPv6 + CIDR utilities.
 *
 * Used in two places that both need trustworthy IP math with no npm dependency:
 *   • Epic A  — matching a source IP against the TRUSTED_PROXIES allow-list so a
 *               spoofed X-Forwarded-For from an untrusted hop can be rejected.
 *   • Epic C  — /24-style range bans (an in-memory CIDR check on the edge guard).
 *
 * Everything works on a normalized byte representation: 4 bytes for IPv4, 16 for
 * IPv6. IPv4-mapped IPv6 (`::ffff:1.2.3.4`) is folded to plain IPv4 so a client
 * that reaches us over a v6 socket but is really v4 matches v4 rules.
 */

/** Strip an IPv6 zone id (`fe80::1%eth0`) and lowercase. */
function clean(ip) {
  if (typeof ip !== "string") return "";
  let s = ip.trim();
  const pct = s.indexOf("%");
  if (pct >= 0) s = s.slice(0, pct);
  return s.toLowerCase();
}

/**
 * Normalize an IP string to a canonical form, folding IPv4-mapped IPv6 to IPv4.
 * Returns "" for anything unparseable.
 */
export function normalizeIp(ip) {
  const bytes = ipToBytes(ip);
  if (!bytes) return "";
  return bytesToIp(bytes);
}

/** Parse an IPv4 dotted-quad into 4 bytes, or null. */
function v4ToBytes(s) {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    if (!/^\d{1,3}$/.test(parts[i])) return null;
    const n = Number(parts[i]);
    if (n > 255) return null;
    out[i] = n;
  }
  return out;
}

/**
 * Parse any IP (v4 or v6, incl. `::ffff:` mapped) into its canonical bytes:
 * a Uint8Array of length 4 (IPv4) or 16 (IPv6). Returns null when unparseable.
 */
export function ipToBytes(ip) {
  const s = clean(ip);
  if (!s) return null;
  if (s.indexOf(":") === -1) return v4ToBytes(s);

  // IPv6 (may embed a trailing IPv4 dotted-quad, e.g. ::ffff:1.2.3.4).
  let head = s;
  let tailV4 = null;
  const lastColon = s.lastIndexOf(":");
  const afterColon = s.slice(lastColon + 1);
  if (afterColon.indexOf(".") !== -1) {
    tailV4 = v4ToBytes(afterColon);
    if (!tailV4) return null;
    head = s.slice(0, lastColon + 1); // keep the colon so splitting is uniform
  }

  const halves = head.split("::");
  if (halves.length > 2) return null; // at most one "::"
  const parseGroups = (str) =>
    str.split(":").filter((x) => x !== "").map((g) => {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return NaN;
      return parseInt(g, 16);
    });

  let groups = [];
  if (halves.length === 2) {
    const left = parseGroups(halves[0]);
    const right = parseGroups(halves[1]);
    if (left.some(Number.isNaN) || right.some(Number.isNaN)) return null;
    const tailGroups = tailV4 ? 2 : 0;
    const fill = 8 - left.length - right.length - tailGroups;
    if (fill < 0) return null;
    groups = [...left, ...Array(fill).fill(0), ...right];
  } else {
    groups = parseGroups(head.replace(/:$/, ""));
    if (groups.some(Number.isNaN)) return null;
  }

  const out = new Uint8Array(16);
  let idx = 0;
  for (const g of groups) {
    out[idx++] = (g >> 8) & 0xff;
    out[idx++] = g & 0xff;
  }
  if (tailV4) {
    out[idx++] = tailV4[0];
    out[idx++] = tailV4[1];
    out[idx++] = tailV4[2];
    out[idx++] = tailV4[3];
  }
  if (idx !== 16) return null;

  // Fold IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible loopback to plain v4.
  const isMapped =
    out.slice(0, 10).every((b) => b === 0) && out[10] === 0xff && out[11] === 0xff;
  if (isMapped) return out.slice(12, 16);
  return out;
}

/** Render canonical bytes back to a string (v4 dotted-quad or compressed v6). */
export function bytesToIp(bytes) {
  if (!bytes) return "";
  if (bytes.length === 4) return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push((bytes[i] << 8) | bytes[i + 1]);
  // Compress the longest run of zero groups to "::".
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else {
      curStart = -1; curLen = 0;
    }
  }
  if (bestLen < 2) return groups.map((g) => g.toString(16)).join(":");
  const head = groups.slice(0, bestStart).map((g) => g.toString(16)).join(":");
  const tail = groups.slice(bestStart + bestLen).map((g) => g.toString(16)).join(":");
  return `${head}::${tail}`;
}

/**
 * Parse a CIDR (or a bare IP, treated as a host route /32 or /128) into
 * { bytes, prefix } or null. Version is implied by bytes.length.
 */
export function parseCidr(cidr) {
  if (typeof cidr !== "string") return null;
  const [addr, prefixStr] = cidr.trim().split("/");
  const bytes = ipToBytes(addr);
  if (!bytes) return null;
  const maxBits = bytes.length * 8;
  let prefix = prefixStr === undefined ? maxBits : Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxBits) return null;
  return { bytes, prefix };
}

/** Parse a comma/space-separated list of CIDRs, dropping unparseable entries. */
export function parseCidrList(list) {
  if (Array.isArray(list)) return list.map(parseCidr).filter(Boolean);
  if (typeof list !== "string") return [];
  return list
    .split(/[,\s]+/)
    .map((x) => x.trim())
    .filter(Boolean)
    .map(parseCidr)
    .filter(Boolean);
}

/** True if the first `prefix` bits of a and b (equal length) match. */
function bitsMatch(a, b, prefix) {
  const fullBytes = prefix >> 3;
  for (let i = 0; i < fullBytes; i++) if (a[i] !== b[i]) return false;
  const rem = prefix & 7;
  if (rem === 0) return true;
  const mask = 0xff << (8 - rem) & 0xff;
  return (a[fullBytes] & mask) === (b[fullBytes] & mask);
}

/** Is `ip` inside the given CIDR? Accepts a string CIDR or a parsed one. */
export function ipInCidr(ip, cidr) {
  const ipBytes = ipToBytes(ip);
  const net = typeof cidr === "string" ? parseCidr(cidr) : cidr;
  if (!ipBytes || !net) return false;
  if (ipBytes.length !== net.bytes.length) return false; // never cross v4/v6
  return bitsMatch(ipBytes, net.bytes, net.prefix);
}

/** True if `ip` matches ANY CIDR in the (parsed or string) list. */
export function ipInAnyCidr(ip, list) {
  const nets = Array.isArray(list) && list[0] && list[0].bytes ? list : parseCidrList(list);
  return nets.some((net) => ipInCidr(ip, net));
}

/** Derive the containing /24 (IPv4) or /64 (IPv6) network string for an IP. */
export function enclosingNetwork(ip) {
  const bytes = ipToBytes(ip);
  if (!bytes) return null;
  if (bytes.length === 4) {
    const net = Uint8Array.from(bytes);
    net[3] = 0;
    return `${bytesToIp(net)}/24`;
  }
  const net = Uint8Array.from(bytes);
  for (let i = 8; i < 16; i++) net[i] = 0;
  return `${bytesToIp(net)}/64`;
}
