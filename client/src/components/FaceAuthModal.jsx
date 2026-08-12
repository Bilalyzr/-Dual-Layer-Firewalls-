/**
 * FaceAuthModal — multi-angle face enrollment + verification (PRD §25).
 *
 * Enrollment captures 3 angles for robust recognition:
 *   Step 1: FRONT view (look straight ahead)
 *   Step 2: LEFT view (turn head left ~30°)
 *   Step 3: RIGHT view (turn head right ~30°)
 *
 * Each angle produces a 128-d embedding. The final template = average of 3.
 * Verification captures one front view and compares against the stored template.
 *
 * Features:
 *   - Live face-detection box overlay (green when face detected)
 *   - Big capture button always visible
 *   - Progress indicator (1/3, 2/3, 3/3)
 *   - Camera mirror effect for natural interaction
 */
import { useState, useEffect, useRef, useCallback } from "react";
import * as faceapi from "face-api.js";

const MODEL_URL = "/models";
let modelsLoaded = false;
let modelsLoading = null;

async function loadModels() {
  if (modelsLoaded) return;
  // De-duplicate concurrent calls (React StrictMode / HMR can double-invoke).
  if (modelsLoading) return modelsLoading;

  modelsLoading = (async () => {
    // face-api.js v0.22 bundles @tensorflow/tfjs. Its backend must be
    // initialized BEFORE models load, otherwise loadFromUri() throws an
    // opaque error in some browsers (the #1 face-api + Vite gotcha).
    try {
      await faceapi.tf.setBackend("webgl");
      await faceapi.tf.ready();
    } catch {
      // WebGL unavailable (headless, no GPU) — fall back to CPU.
      try {
        await faceapi.tf.setBackend("cpu");
        await faceapi.tf.ready();
      } catch { /* proceed anyway; loadFromUri will throw a clearer error */ }
    }

    await faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL);
    await faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL);
    await faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL);
    modelsLoaded = true;
  })();
  return modelsLoading;
}

async function detectFace(video) {
  return await faceapi
    .detectSingleFace(video, new faceapi.TinyFaceDetectorOptions({ inputSize: 320, scoreThreshold: 0.4 }))
    .withFaceLandmarks()
    .withFaceDescriptor();
}

const ENROLL_STEPS = [
  { label: "FRONT VIEW", instruction: "Look straight at the camera", icon: "😀" },
  { label: "LEFT VIEW", instruction: "Turn your head slightly LEFT (about 30°)", icon: "👈" },
  { label: "RIGHT VIEW", instruction: "Turn your head slightly RIGHT (about 30°)", icon: "👉" },
];

export default function FaceAuthModal({ mode, userId, onVerified, onCancel, onSkip }) {
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const streamRef = useRef(null);
  const detectLoopRef = useRef(null);
  // Ref mirror of status so the detection loop can read the latest value
  // without being a useEffect dependency (avoids camera teardown loops).
  const statusRef = useRef("loading");
  const [status, setStatus] = useState("loading");
  const [message, setMessage] = useState("Loading face recognition models...");
  const [step, setStep] = useState(0);
  const [captured, setCaptured] = useState([]); // collected descriptors
  const [cameraReady, setCameraReady] = useState(false); // true the moment a live stream attaches
  const [faceDetected, setFaceDetected] = useState(false);
  const [retryKey, setRetryKey] = useState(0);

  const updateStatus = useCallback((s) => {
    statusRef.current = s;
    setStatus(s);
  }, []);

  const stopCamera = useCallback(() => {
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    }
    if (videoRef.current) {
      try { videoRef.current.srcObject = null; } catch { /* noop */ }
    }
    if (detectLoopRef.current) {
      clearInterval(detectLoopRef.current);
      detectLoopRef.current = null;
    }
    setCameraReady(false);
  }, []);

  // Start camera + models ONCE on mount. `status` is intentionally NOT a
  // dependency: including it tears the camera down every time the status
  // flips (e.g. loading→ready), which races getUserMedia and hangs on
  // "Starting camera...". The loop reads status via statusRef instead.
  useEffect(() => {
    let active = true;
    (async () => {
      try {
        updateStatus("loading");
        setMessage("Loading AI face models...");
        await loadModels();
        if (!active) return;

        setMessage("Starting camera...");
        setCameraReady(false);
        // Race getUserMedia against a timeout so it can never hang forever
        // (common when a previous stream wasn't released or the OS prompt
        // is dismissed without answering).
        const getUserMediaWithTimeout = () => {
          const timeout = new Promise((_, reject) =>
            setTimeout(() => reject(new Error("Camera request timed out")), 8000)
          );
          return Promise.race([
            navigator.mediaDevices.getUserMedia({ video: { width: 480, height: 360 } }),
            timeout,
          ]);
        };
        const stream = await getUserMediaWithTimeout();
        if (!active) { stream.getTracks().forEach((t) => t.stop()); return; }
        streamRef.current = stream;

        // Flip cameraReady the INSTANT the stream is granted — before play() —
        // so the capture buttons can never be blocked by a hung play() promise.
        setCameraReady(true);
        updateStatus("ready");
        setMessage(mode === "enroll" ? ENROLL_STEPS[0].instruction : "Look at the camera and click VERIFY");

        if (videoRef.current) {
          videoRef.current.srcObject = stream;
          // Fire-and-forget: the <video autoPlay> attribute handles playback.
          // Never await play() — a pending play() promise would block rendering.
          videoRef.current.play().catch(() => { /* autoplay restriction — non-fatal */ });
        }

        // Start live face detection loop (updates the green box + faceDetected state).
        // Reads status from the ref so it never re-triggers the camera effect.
        detectLoopRef.current = setInterval(async () => {
          if (!videoRef.current) return;
          const s = statusRef.current;
          if (s === "detecting" || s === "success") return;
          try {
            const detection = await faceapi.detectSingleFace(
              videoRef.current,
              new faceapi.TinyFaceDetectorOptions({ inputSize: 224, scoreThreshold: 0.4 })
            );
            setFaceDetected(Boolean(detection));
            // Draw detection box on canvas
            if (canvasRef.current && detection) {
              const ctx = canvasRef.current.getContext("2d");
              ctx.clearRect(0, 0, 480, 360);
              const box = detection.box;
              ctx.strokeStyle = "#00ff9d";
              ctx.lineWidth = 2;
              ctx.strokeRect(box.x, box.y, box.width, box.height);
              // Corner accents
              const c = 15;
              ctx.beginPath();
              ctx.moveTo(box.x, box.y + c); ctx.lineTo(box.x, box.y); ctx.lineTo(box.x + c, box.y);
              ctx.moveTo(box.x + box.width - c, box.y); ctx.lineTo(box.x + box.width, box.y); ctx.lineTo(box.x + box.width, box.y + c);
              ctx.moveTo(box.x + box.width, box.y + box.height - c); ctx.lineTo(box.x + box.width, box.y + box.height); ctx.lineTo(box.x + box.width - c, box.y + box.height);
              ctx.moveTo(box.x + c, box.y + box.height); ctx.lineTo(box.x, box.y + box.height); ctx.lineTo(box.x, box.y + box.height - c);
              ctx.stroke();
            } else if (canvasRef.current) {
              canvasRef.current.getContext("2d").clearRect(0, 0, 480, 360);
            }
          } catch { /* silent — detection loop is best-effort */ }
        }, 200);
      } catch (err) {
        if (!active) return;
        // Distinguish model-load failures (face-api/TF backend) from camera
        // failures so the real root cause is shown, not a misleading message.
        const msg = String(err?.message || err);
        const stage = cameraReady ? "camera" : msg.includes("timed out") ? "camera" : "model";
        updateStatus("no_camera");
        if (stage === "model") {
          setMessage(`AI model load failed: ${msg}`);
          console.error("[FaceAuth] model load failed:", err);
        } else {
          setMessage(`Camera error: ${msg}. Use http://localhost:5174 and allow camera access.`);
          console.error("[FaceAuth] camera failed:", err);
        }
      }
    })();
    return () => { active = false; stopCamera(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, retryKey]);

  const handleCapture = async () => {
    updateStatus("detecting");
    setMessage(faceDetected ? "Capturing face data..." : "Scanning for face...");
    try {
      const result = await detectFace(videoRef.current);
      if (!result) {
        updateStatus("ready");
        setMessage("⚠ Could not capture. Make sure your face is clearly visible.");
        return;
      }
      const descriptor = Array.from(result.descriptor);

      if (mode === "enroll") {
        const newCaptured = [...captured, descriptor];
        setCaptured(newCaptured);

        if (newCaptured.length < 3) {
          // Move to next angle
          const nextStep = newCaptured.length;
          setStep(nextStep);
          updateStatus("ready");
          setMessage(`✓ ${ENROLL_STEPS[newCaptured.length - 1].label} captured! Now: ${ENROLL_STEPS[nextStep].instruction}`);
          return;
        }

        // All 3 angles captured — compute average and enroll
        updateStatus("detecting");
        setMessage("Processing face template...");
        const avg = newCaptured[0].map((_, i) =>
          (newCaptured[0][i] + newCaptured[1][i] + newCaptured[2][i]) / 3
        );

        const res = await fetch("/api/auth/face/enroll", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ userId, descriptor: avg }),
        });
        const data = await res.json();
        if (data.success) {
          updateStatus("success");
          setMessage("✓ Face enrolled with 3 angles! Face authentication is now active.");
          stopCamera();
          setTimeout(() => onVerified?.(), 2500);
        } else {
          updateStatus("failed");
          setMessage(data.error || "Enrollment failed");
          setTimeout(() => { updateStatus("ready"); setStep(0); setCaptured([]); setMessage(ENROLL_STEPS[0].instruction); }, 2500);
        }
      } else {
        // Verify mode — single capture
        const res = await fetch("/api/auth/face/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ userId, descriptor }),
        });
        const data = await res.json();
        if (data.success && data.match) {
          updateStatus("success");
          setMessage(`✓ Face verified! (confidence: ${(100 - data.distance * 50).toFixed(1)}%)`);
          stopCamera();
          setTimeout(() => onVerified?.(true), 2000);
        } else {
          updateStatus("failed");
          setMessage(data.match === false ? "✗ Face does not match" : (data.error || "Verification failed"));
          setTimeout(() => { updateStatus("ready"); setMessage("Try again — look at the camera"); }, 2500);
        }
      }
    } catch (err) {
      updateStatus("failed");
      setMessage(`Error: ${err.message}`);
      setTimeout(() => { updateStatus("ready"); setMessage("Try again"); }, 2000);
    }
  };

  const progressBar = mode === "enroll" ? `${captured.length}/3` : "1/1";
  const currentStep = mode === "enroll" ? ENROLL_STEPS[step] : null;

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 9999,
      background: "rgba(0,0,0,0.85)", backdropFilter: "blur(4px)",
      display: "flex", alignItems: "center", justifyContent: "center",
    }}>
      <div className="panel" style={{ width: 440, maxWidth: "92vw", textAlign: "center" }}>
        {/* Header */}
        <div className="panel-head">
          <h2>{mode === "enroll" ? "👤 Face Enrollment" : "🔐 Face Verification"}</h2>
          <button onClick={() => { stopCamera(); onCancel?.(); }}
            style={{ background: "none", border: "none", color: "var(--muted)", cursor: "pointer", fontSize: 18 }}>✕</button>
        </div>

        {/* Progress indicator */}
        {mode === "enroll" && status !== "success" && status !== "loading" && (
          <div style={{ display: "flex", gap: 4, justifyContent: "center", marginBottom: 10 }}>
            {ENROLL_STEPS.map((s, i) => (
              <div key={i} style={{
                padding: "3px 10px", borderRadius: 4, fontSize: 10, fontFamily: "var(--mono)",
                background: i < captured.length ? "rgba(0,255,157,0.15)" : i === step ? "rgba(0,240,255,0.15)" : "rgba(255,255,255,0.05)",
                color: i < captured.length ? "var(--ok)" : i === step ? "var(--cyan)" : "var(--muted)",
                border: `1px solid ${i < captured.length ? "rgba(0,255,157,0.3)" : i === step ? "rgba(0,240,255,0.3)" : "transparent"}`,
              }}>
                {i < captured.length ? "✓" : i + 1}. {s.label}
              </div>
            ))}
          </div>
        )}

        {/* Camera feed with face detection overlay */}
        <div style={{
          position: "relative", width: 480, height: 360, maxWidth: "100%", margin: "0 auto 12px",
          borderRadius: 12, overflow: "hidden", background: "#000",
          border: `3px solid ${status === "success" ? "var(--ok)" : status === "failed" ? "var(--bad)" : faceDetected ? "var(--ok)" : "var(--panel-edge)"}`,
          boxShadow: faceDetected ? "0 0 20px rgba(0,255,157,0.2)" : "none",
          transition: "border-color 0.3s, box-shadow 0.3s",
        }}>
          <video ref={videoRef} width={480} height={360} autoPlay playsInline muted
            style={{ transform: "scaleX(-1)", objectFit: "cover", width: "100%", height: "100%" }} />
          <canvas ref={canvasRef} width={480} height={360}
            style={{ position: "absolute", top: 0, left: 0, width: "100%", height: "100%", transform: "scaleX(-1)" }} />

          {/* Status overlays */}
          {status === "loading" && (
            <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--cyan)" }}>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 32 }}>⏳</div>
                <div className="small" style={{ marginTop: 6 }}>{message}</div>
              </div>
            </div>
          )}
          {status === "success" && (
            <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(0,255,157,0.15)" }}>
              <div style={{ fontSize: 64 }}>✓</div>
            </div>
          )}
          {status === "detecting" && (
            <div style={{ position: "absolute", bottom: 10, left: 0, right: 0, textAlign: "center" }}>
              <span className="pill pill-ok" style={{ animation: "pulse 1s infinite" }}>📸 Capturing...</span>
            </div>
          )}

          {/* Face detection indicator */}
          {cameraReady && (
            <div style={{ position: "absolute", top: 8, right: 8 }}>
              <span className="pill" style={{
                fontSize: 9, padding: "2px 8px",
                color: faceDetected ? "var(--ok)" : "var(--warn)",
                borderColor: faceDetected ? "rgba(0,255,157,0.4)" : "rgba(255,204,51,0.4)",
                background: faceDetected ? "rgba(0,255,157,0.1)" : "rgba(255,204,51,0.1)",
              }}>
                {faceDetected ? "● FACE DETECTED" : "○ NO FACE"}
              </span>
            </div>
          )}

          {/* OVERLAY capture button — pinned to the bottom of the video.
              Rendered from `cameraReady` (set the instant the stream attaches),
              so it is physically impossible for the button to be missing while
              the feed is visible. Independent of the `status` machine. */}
          {cameraReady && status !== "detecting" && status !== "success" && (
            <button
              onClick={handleCapture}
              style={{
                position: "absolute", bottom: 12, left: "50%", transform: "translateX(-50%)",
                padding: "12px 36px", fontSize: 16, fontWeight: 800, borderRadius: 30,
                cursor: "pointer", whiteSpace: "nowrap",
                background: faceDetected
                  ? "linear-gradient(135deg, #00f0ff, #0066ff)"
                  : "rgba(0, 240, 255, 0.22)",
                color: faceDetected ? "#001018" : "#00f0ff",
                border: faceDetected ? "2px solid #00f0ff" : "2px solid rgba(0,240,255,0.7)",
                boxShadow: faceDetected
                  ? "0 0 28px rgba(0,240,255,0.6), 0 4px 16px rgba(0,0,0,0.4)"
                  : "0 0 14px rgba(0,240,255,0.3), 0 4px 12px rgba(0,0,0,0.4)",
                backdropFilter: "blur(6px)", letterSpacing: 1.5, textTransform: "uppercase",
              }}
            >
              📸 CAPTURE
            </button>
          )}
        </div>

        {/* Instructions */}
        <div className="small" style={{
          color: status === "failed" ? "var(--bad)" : status === "success" ? "var(--ok)" : faceDetected ? "var(--ok)" : "var(--warn)",
          minHeight: 24, marginBottom: 10,
        }}>
          {status === "ready" && currentStep && (
            <span style={{ fontSize: 14 }}>{currentStep.icon} </span>
          )}
          {message}
        </div>

        {/* Big capture button — renders from `cameraReady` (not status) so it
            can never vanish due to a stuck status transition. */}
        {cameraReady && status !== "detecting" && status !== "success" && (
          <button
            onClick={handleCapture}
            style={{
              width: "100%", padding: "16px", fontSize: 16, fontWeight: 800,
              borderRadius: 10, cursor: "pointer",
              background: faceDetected
                ? "linear-gradient(135deg, var(--cyan), var(--blue))"
                : "linear-gradient(135deg, rgba(0,240,255,0.25), rgba(0,102,255,0.25))",
              color: faceDetected ? "var(--bg-0)" : "var(--cyan)",
              border: faceDetected ? "none" : "2px solid var(--cyan)",
              boxShadow: faceDetected ? "0 0 24px rgba(0,240,255,0.45)" : "0 0 12px rgba(0,240,255,0.2)",
              letterSpacing: 1.5, textTransform: "uppercase",
              transition: "all 0.2s",
            }}
          >
            📸 CAPTURE {mode === "enroll" ? ENROLL_STEPS[captured.length]?.label || "FACE" : "FACE"}
          </button>
        )}

        {status === "detecting" && (
          <button disabled style={{ width: "100%", padding: "14px", fontSize: 15, borderRadius: 8, opacity: 0.5, border: "none", background: "var(--panel-2)", color: "var(--muted)" }}>
            ⏳ Processing...
          </button>
        )}

        {status === "no_camera" && (
          <div style={{ padding: 8 }}>
            <div className="muted small" style={{ marginBottom: 10 }}>
              Camera requires localhost or HTTPS.
              <br />Open <code>http://localhost:5174</code> on this machine,
              <br />or click retry if another app was using the camera.
            </div>
            <button
              onClick={() => { stopCamera(); setRetryKey((k) => k + 1); }}
              style={{ width: "100%", padding: "10px", fontSize: 13, fontWeight: 700,
                borderRadius: 8, cursor: "pointer", border: "1px solid var(--cyan)",
                background: "rgba(0,240,255,0.1)", color: "var(--cyan)" }}
            >
              ↻ RETRY CAMERA
            </button>
          </div>
        )}

        {/* Skip option — enroll mode only, any non-success state.
            Lets the user defer enrollment (e.g. camera unavailable on LAN IP)
            and continue. Falls back to onCancel when no onSkip is supplied. */}
        {mode === "enroll" && status !== "success" && (
          <button
            onClick={() => { stopCamera(); (onSkip || onCancel)?.(); }}
            style={{
              width: "100%", marginTop: 12, padding: "10px",
              fontSize: 11, fontWeight: 600, borderRadius: 8,
              cursor: "pointer", letterSpacing: 0.5,
              background: "transparent", border: "1px solid var(--panel-edge)",
              color: "var(--muted)", transition: "all 0.2s",
            }}
            onMouseEnter={(e) => { e.currentTarget.style.color = "var(--cyan)"; e.currentTarget.style.borderColor = "var(--cyan)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = "var(--muted)"; e.currentTarget.style.borderColor = "var(--panel-edge)"; }}
          >
            Skip face enrollment for now →
          </button>
        )}
      </div>
    </div>
  );
}
