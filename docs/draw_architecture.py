"""
Draw the system architecture diagram for the Unified Dual-Layer AI Firewall
& Behavioral Zero-Trust Platform. Exports docs/architecture.jpg (JPEG).

Uses PIL only (matplotlib unavailable in this env). Dark cyber theme to
match the dashboard (bg #050810, cyan/green accents, IBM-Plex-ish mono).
"""
from PIL import Image, ImageDraw, ImageFont

W, H = 2400, 2050
BG = (5, 8, 16)
PANEL = (13, 20, 38)
PANEL_EDGE = (0, 240, 255)
CYAN = (0, 240, 255)
BLUE = (0, 102, 255)
GREEN = (0, 255, 157)
AMBER = (255, 204, 51)
RED = (255, 56, 96)
MUTED = (137, 160, 180)
WHITE = (220, 235, 245)
BOX_FILL = (10, 16, 32)

img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)


def font(size, bold=False):
    """Load a Windows font with graceful fallbacks."""
    candidates = [
        (f"consolab.ttf" if bold else "consola.ttf"),
        (f"arialbd.ttf" if bold else "arial.ttf"),
    ]
    for name in candidates:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


F_TITLE = font(40, bold=True)
F_SUB = font(22)
F_H2 = font(26, bold=True)
F_BOX = font(19, bold=True)
F_SMALL = font(15)
F_TINY = font(13)


def rbox(x0, y0, x1, y1, fill=BOX_FILL, outline=PANEL_EDGE, width=2, radius=14):
    d.rounded_rectangle([x0, y0, x1, y1], radius=radius, fill=fill,
                        outline=outline, width=width)


def ctext(cx, cy, text, f=F_BOX, fill=WHITE):
    l, t, r, b = d.textbbox((0, 0), text, font=f)
    d.text((cx - (r - l) / 2, cy - (b - t) / 2), text, font=f, fill=fill)


def arrow_down(x, y0, y1, color=CYAN, width=4, label=None):
    d.line([x, y0, x, y1 - 12], fill=color, width=width)
    d.polygon([(x - 10, y1 - 14), (x + 10, y1 - 14), (x, y1)], fill=color)
    if label:
        l, t, r, b = d.textbbox((0, 0), label, font=F_SMALL)
        d.text((x + 16, (y0 + y1) / 2 - (b - t) / 2), label, font=F_SMALL, fill=MUTED)


def arrow_right(x0, x1, y, color=CYAN, width=3):
    d.line([x0, y, x1 - 10, y], fill=color, width=width)
    d.polygon([(x1 - 12, y - 7), (x1 - 12, y + 7), (x1, y)], fill=color)


# ---------------------------------------------------------------- title
ctext(W / 2, 50, "UNIFIED DUAL-LAYER AI FIREWALL & BEHAVIORAL ZERO-TRUST PLATFORM",
      F_TITLE, CYAN)
ctext(W / 2, 100, "System Architecture  ·  v1.0  ·  2026", F_SUB, MUTED)
d.line([(200, 135), (W - 200, 135)], fill=(0, 240, 255, 60), width=1)

# ---------------------------------------------------------------- CLIENT band
cy0, cy1 = 170, 390
rbox(120, cy0, W - 120, cy1, outline=(0, 240, 255), width=2, radius=18)
d.text((150, cy0 + 14), "CLIENT — REACT + VITE  ·  :5174", font=F_H2, fill=CYAN)
ctext(W - 260, cy0 + 28, "IBM Plex · 3D Glass UI", F_SMALL, MUTED)

cboxes = [
    ("LOGIN", "behavioral gate\n+ face auth (off)"),
    ("BEHAVIOR RISK", "gauge · metrics\nexplainability"),
    ("AI CHAT", "Layer-1 firewall\ntest console"),
    ("THREAT FEED", "live SSE stream\ndecisions"),
    ("RISK TABLE", "per-user profiles\nbaselines"),
]
bw, gap = 380, 30
total = len(cboxes) * bw + (len(cboxes) - 1) * gap
x = (W - total) / 2
for title, sub in cboxes:
    rbox(x, cy0 + 60, x + bw, cy1 - 20, outline=(0, 240, 255, 150), width=2)
    ctext(x + bw / 2, cy0 + 95, title, F_BOX, WHITE)
    for i, line in enumerate(sub.split("\n")):
        ctext(x + bw / 2, cy0 + 130 + i * 22, line, F_SMALL, MUTED)
    x += bw + gap

# arrows client -> proxy
arrow_down(W / 2 - 350, cy1 + 6, 470, CYAN, 4, "HTTP /api/*")
arrow_down(W / 2 + 350, cy1 + 6, 470, GREEN, 4, "SSE /api/events")

# ---------------------------------------------------------------- PROXY band
py0, py1 = 480, 1290
rbox(120, py0, W - 120, py1, outline=BLUE, width=3, radius=18)
d.text((150, py0 + 14), "PROXY — NODE / EXPRESS AI FIREWALL  ·  :4001", font=F_H2, fill=CYAN)
d.text((150, py0 + 48), "inbound intercept → inspect → transform → outbound check",
       font=F_SMALL, fill=MUTED)

# ---- Layer 1 pipeline
l1y0, l1y1 = py0 + 80, py0 + 290
rbox(150, l1y0, W - 150, l1y1, fill=(8, 12, 26), outline=RED, width=2)
d.text((175, l1y0 + 10), "LAYER 1 — AI FIREWALL PIPELINE  (prompt → LLM → response)",
       font=F_H2, fill=RED)

steps = [
    ("HEURISTICS", "regex · 40+ sigs\nLLM01-07", RED),
    ("ML CLASSIFIER", "TF-IDF + LogReg\nthreat prob", AMBER),
    ("LLAMA GUARD", "OWASP LLM top-10\ndeBERTa (opt)", AMBER),
    ("REBUFF", "4-layer defense\nCanary + detect", CYAN),
    ("TRIFECTA AGENTS", "Reader→Validator\n→Actor + RBAC", CYAN),
    ("OUTBOUND CHECK", "exfil · PII · secrets\nredaction", GREEN),
]
sbw, sgap = 330, 44
sx = 150 + (W - 300 - (len(steps) * sbw + (len(steps) - 1) * sgap)) / 2
sy = l1y0 + 55
for i, (t, s, col) in enumerate(steps):
    rbox(sx, sy, sx + sbw, l1y1 - 18, outline=col, width=2)
    ctext(sx + sbw / 2, sy + 32, t, F_BOX, col)
    for j, line in enumerate(s.split("\n")):
        ctext(sx + sbw / 2, sy + 68 + j * 21, line, F_TINY, MUTED)
    if i < len(steps) - 1:
        arrow_right(sx + sbw + 4, sx + sbw + sgap - 4, sy + (l1y1 - 18 - sy) / 2, col, 3)
    sx += sbw + sgap

# ---- Layer 2 row
l2y0, l2y1 = py0 + 310, py0 + 560
rbox(150, l2y0, W - 150, l2y1, fill=(8, 12, 26), outline=GREEN, width=2)
d.text((175, l2y0 + 10), "LAYER 2 — BEHAVIORAL ZERO-TRUST  (context-centric, not biometric)",
       font=F_H2, fill=GREEN)

l2 = [
    ("LOGIN + RISK GATE", "credentials → engine\nHIGH risk = deny", GREEN),
    ("BEHAVIOR ROUTES", "/behavior/analyze\nrisk · profile · events", GREEN),
    ("SESSION / STEP-UP", "WebAuthn MFA\nescalation ladder", CYAN),
    ("EVENT BUS + SSE", "audit chain · SIEM\nlive feed", CYAN),
    ("COMPLIANCE", "GDPR consent\nimmutable audit", AMBER),
]
lbw, lgap = 400, 30
lx = 150 + (W - 300 - (len(l2) * lbw + (len(l2) - 1) * lgap)) / 2
ly = l2y0 + 55
for t, s, col in l2:
    rbox(lx, ly, lx + lbw, l2y1 - 18, outline=col, width=2)
    ctext(lx + lbw / 2, ly + 32, t, F_BOX, col)
    for j, line in enumerate(s.split("\n")):
        ctext(lx + lbw / 2, ly + 68 + j * 21, line, F_TINY, MUTED)
    lx += lbw + lgap

# ---- shared services row
ssy0, ssy1 = py0 + 580, py1 - 18
rbox(150, ssy0, W - 150, ssy1, fill=(8, 12, 26), outline=(0, 240, 255, 120), width=2)
d.text((175, ssy0 + 10), "SHARED SERVICES", font=F_H2, fill=CYAN)
svc = ["LLM CLIENT (GLM · DNS-bypass · 429 retry)", "IP FORENSICS / SIEM",
       "ADVERSARIAL ML SHIELD", "O11Y: Prometheus + Grafana"]
sw = (W - 300 - 3 * 30) / 4
sxx = 150 + 15
for s in svc:
    rbox(sxx, ssy0 + 50, sxx + sw - 30, ssy1 - 14, outline=(0, 240, 255, 100), width=2)
    lines = s.split(" · ") if " · " in s and len(s) > 34 else [s]
    if len(lines) == 1:
        ctext(sxx + (sw - 30) / 2, ssy0 + 50 + (ssy1 - 14 - ssy0 - 50) / 2, s, F_SMALL, WHITE)
    else:
        for j, ln in enumerate(lines):
            ctext(sxx + (sw - 30) / 2, ssy0 + 75 + j * 24, ln, F_SMALL, MUTED)
    sxx += sw

# arrows proxy -> engine + externals
arrow_down(W / 2 - 420, py1 + 6, 1370, GREEN, 4, "REST /behavior · /classify")
arrow_down(W / 2 + 420, py1 + 6, 1370, AMBER, 4, "HTTPS chat/completions")

# ---------------------------------------------------------------- ENGINE band
ey0, ey1 = 1380, 1740
rbox(120, ey0, W / 2 + 320, ey1, outline=GREEN, width=3, radius=18)
d.text((150, ey0 + 14), "ENGINE — PYTHON / FASTAPI  ·  :8011", font=F_H2, fill=GREEN)

# L1 classifier mini
rbox(150, ey0 + 55, 480, ey0 + 150, outline=AMBER, width=2)
ctext(315, ey0 + 85, "L1 CLASSIFIER", F_BOX, AMBER)
ctext(315, ey0 + 120, "TF-IDF · LogReg · SVM\nprompt-injection model", F_TINY, MUTED)

# L2 behavioral pipeline
rbox(500, ey0 + 55, W / 2 + 290, ey1 - 20, fill=(6, 14, 20), outline=GREEN, width=2)
d.text((525, ey0 + 62), "L2 BEHAVIORAL RISK PIPELINE — 7 components", font=F_BOX, fill=GREEN)

flow = [
    ("TELEMETRY", "7 categories\nid·dev·loc·time\nsession·res·act", CYAN),
    ("FEATURES", "25 numeric\nStandardScaler\n+ engineered", CYAN),
    ("BASELINE", "per user+role\nEWMA update\nnormal profile", GREEN),
    ("ONE-CLASS SVM", "anomaly score\ndistance from\nnormal boundary", RED),
    ("LLM ENRICH", "context features\nbulk export\nexfil signals", AMBER),
    ("RANDOM FOREST", "risk score 0-100\nLOW/MED/HIGH", RED),
    ("RESPONSE", "ALLOW/STEP-UP\nRESTRICT/DENY\n+ decision obj", GREEN),
]
fw, fgap = 196, 26
fx = 525 + 10
fy = ey0 + 110
for i, (t, s, col) in enumerate(flow):
    rbox(fx, fy, fx + fw, ey1 - 42, outline=col, width=2)
    ctext(fx + fw / 2, fy + 24, t, F_TINY, col)
    for j, line in enumerate(s.split("\n")):
        ctext(fx + fw / 2, fy + 55 + j * 19, line, F_TINY, MUTED)
    if i < len(flow) - 1:
        arrow_right(fx + fw + 2, fx + fw + fgap - 2, fy + (ey1 - 42 - fy) / 2, col, 2)
    fx += fw + fgap

# model artifacts note
ctext(W / 4 + 60, ey1 - 18, "artifacts: behavioral_svm.joblib · behavioral_rf.joblib · behavioral_dnn.pt (1.8M, committed)",
      F_TINY, MUTED)

# ---------------------------------------------------------------- EXTERNAL band
xy0, xy1 = 1380, 1740
rbox(W / 2 + 360, xy0, W - 120, xy1, outline=AMBER, width=3, radius=18)
d.text((W / 2 + 390, xy0 + 14), "EXTERNAL SERVICES", font=F_H2, fill=AMBER)

ext = [
    ("GLM-4.5-FLASH", "Zhipu OpenAI-compat API\nDNS-bypass · rate-limit aware", AMBER),
    ("MONGODB", "Atlas / Community\nAES-256-GCM field encryption", GREEN),
    ("DEPLOY TARGETS", "Docker Compose · Helm\nRender · Vercel", CYAN),
]
ey = xy0 + 60
for t, s, col in ext:
    rbox(W / 2 + 385, ey, W - 145, ey + 90, outline=col, width=2)
    ctext((W / 2 + 385 + W - 145) / 2, ey + 28, t, F_BOX, col)
    for j, line in enumerate(s.split("\n")):
        ctext((W / 2 + 385 + W - 145) / 2, ey + 58 + j * 19, line, F_TINY, MUTED)
    ey += 105

# ---------------------------------------------------------------- footer legend
fy0 = 1770
rbox(120, fy0, W - 120, H - 40, fill=(8, 12, 26), outline=(0, 240, 255, 80), width=1)
d.text((150, fy0 + 12), "LEGEND", font=F_BOX, fill=CYAN)
legend = [
    ("L1 AI FIREWALL", RED), ("L2 ZERO-TRUST", GREEN),
    ("INFRA / SHARED", CYAN), ("EXTERNAL", AMBER),
]
lx = 320
for t, col in legend:
    d.rounded_rectangle([lx, fy0 + 16, lx + 26, fy0 + 34], radius=4, outline=col, width=2)
    d.text((lx + 36, fy0 + 15), t, font=F_SMALL, fill=WHITE)
    lx += 320
d.text((150, fy0 + 50),
       "Flow: user prompt → heuristics → ML → guards → agents → LLM → outbound scan → response.  "
       "Every request also feeds Layer-2 telemetry → risk score → adaptive decision.",
       font=F_SMALL, fill=MUTED)
d.text((150, fy0 + 78),
       "Ports: client 5174 · proxy 4001 · engine 8011.  Login: admin/admin123 · analyst/sec123 · demo/demo.",
       font=F_SMALL, fill=MUTED)

img.save("docs/architecture.jpg", "JPEG", quality=92)
print("saved docs/architecture.jpg", img.size)
