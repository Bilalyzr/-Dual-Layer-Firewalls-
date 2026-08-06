/**
 * EPIC E — Client-side device fingerprinting (canvas / WebGL / audio).
 *
 * Three browser-native signals combined into a stable device fingerprint:
 *   - Canvas: render a hidden image, hash the pixel output (catches GPU/driver
 *     differences across devices)
 *   - WebGL: renderer + vendor string (GPU identity)
 *   - AudioContext: oscillator → analyzer → hash (catches audio-stack diffs)
 *
 * ⚠️ GDPR personal data — STRICTLY behind the Epic I consent gate. The hook
 * refuses to collect anything until hasConsent("fingerprint") is true. The
 * fingerprint is hashed before transmission (never raw canvas/audio data).
 */

/** djb2 hash → short hex. Stable for the same input. */
function hash(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h + str.charCodeAt(i)) | 0;
  return (h >>> 0).toString(16).padStart(8, "0");
}

async function canvasFingerprint() {
  try {
    const c = document.createElement("canvas");
    c.width = 240;
    c.height = 60;
    const ctx = c.getContext("2d");
    if (!ctx) return "no-canvas";
    ctx.textBaseline = "top";
    ctx.font = "14px 'Arial'";
    ctx.fillStyle = "#f60";
    ctx.fillRect(0, 0, 100, 30);
    ctx.fillStyle = "#069";
    ctx.fillText("Dual-Layer 🛡️ fingerprint", 2, 15);
    ctx.fillStyle = "rgba(102,204,0,0.7)";
    ctx.fillText("Dual-Layer 🛡️ fingerprint", 4, 17);
    return hash(c.toDataURL());
  } catch {
    return "canvas-blocked";
  }
}

async function webglFingerprint() {
  try {
    const c = document.createElement("canvas");
    const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
    if (!gl) return "no-webgl";
    const dbg = gl.getExtension("WEBGL_debug_renderer_info");
    const renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : "unknown";
    const vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : "unknown";
    return hash(`${renderer}|${vendor}`);
  } catch {
    return "webgl-blocked";
  }
}

async function audioFingerprint() {
  try {
    const AC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!AC) return "no-audio";
    const ctx = new AC(1, 5000, 44100);
    const osc = ctx.createOscillator();
    osc.type = "triangle";
    osc.frequency.value = 1000;
    const comp = ctx.createDynamicsCompressor();
    osc.connect(comp);
    comp.connect(ctx.destination);
    osc.start(0);
    const buffer = await ctx.startRendering();
    // hash a slice of samples
    const data = buffer.getChannelData(0);
    let h = 5381;
    for (let i = 4500; i < 5000; i++) h = ((h << 5) + h + Math.floor(data[i] * 1e9)) | 0;
    return (h >>> 0).toString(16).padStart(8, "0");
  } catch {
    return "audio-blocked";
  }
}

/**
 * Collect all three fingerprints + UA + screen. Returns null if consent missing.
 * @param {boolean} consentGranted — from Epic I consent check
 */
export async function collectFingerprint(consentGranted) {
  if (!consentGranted) return null;
  const [canvas, webgl, audio] = await Promise.all([
    canvasFingerprint(),
    webglFingerprint(),
    audioFingerprint(),
  ]);
  const fp = {
    canvas,
    webgl,
    audio,
    combined: hash(`${canvas}|${webgl}|${audio}`),
    screen: `${screen.width}x${screen.height}x${screen.colorDepth}`,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    collectedAt: new Date().toISOString(),
  };
  return fp;
}

/** Post the fingerprint to the proxy (gated by consent on the server side too). */
export async function sendFingerprint(fp, userId) {
  if (!fp) return;
  try {
    await fetch("/api/biometric/fingerprint", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId, ...fp }),
    });
  } catch {
    /* best-effort */
  }
}
