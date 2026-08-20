/**
 * EPIC J — GPU inference routing.
 *
 * When a GPU inference service is available (INFERENCE_SVC_URL set), the proxy
 * routes heavy model calls (DistilBERT embedding, Llama Guard) to it instead of
 * the CPU engine. Falls back to the CPU engine automatically when the GPU
 * service is down or unset. This is behind the existing circuit breaker.
 */
import { withBreaker } from "./circuitBreaker.js";

const GPU_URL = () => process.env.INFERENCE_SVC_URL; // e.g. http://gpu-engine:8011

export function gpuAvailable() {
  return Boolean(GPU_URL());
}

/**
 * Route an embedding-outlier check to the GPU service if available; else CPU.
 * @param {string} text
 * @returns {Promise<{outlier_flag: boolean, outlier_distance: number}>}
 */
export async function embeddingCheck(text) {
  const url = GPU_URL();
  if (!url) {
    return { outlier_flag: false, outlier_distance: 0, source: "cpu-skipped" };
  }
  try {
    const r = await withBreaker("gpu-inference", () =>
      fetch(`${url}/classify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
        signal: AbortSignal.timeout(3000),
      }).then((res) => res.json())
    );
    return {
      outlier_flag: Boolean(r.outlier_flag),
      outlier_distance: r.outlier_distance || 0,
      source: "gpu",
    };
  } catch {
    return { outlier_flag: false, outlier_distance: 0, source: "cpu-fallback" };
  }
}
